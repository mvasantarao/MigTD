// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::{
    snp::{
        collateral_set::SnpCertificateEntryV1,
        evidence_header::{SnpEvidenceHeaderV1, SnpRecordTypeV1},
        policy_identity::PolicyIdentityV1,
        report_data_context::{SnpEvidencePurposeV1, SnpMigrationAlgorithmV1},
    },
    types::{SnpEvidenceVerificationRequest, VerifiedSnpEvidence},
};
use ring::signature::KeyPair;
use std::cell::Cell;

#[path = "ordered_collateral_tests.rs"]
mod ordered_tests;

#[path = "local_handoff_tests.rs"]
mod local_handoff_tests;

#[path = "crypto_vectors.rs"]
mod crypto_vectors;

#[path = "peer_channel/tests.rs"]
mod peer_channel_tests;

struct TestClock(Cell<u64>);

impl MaPolicyTimeV1 for TestClock {
    fn unix_seconds(&self) -> Result<u64, MaPolicyErrorV1> {
        Ok(self.0.get())
    }
}

fn rules() -> FixedReleaseAdmissionRulesV1 {
    FixedReleaseAdmissionRulesV1 {
        minimum_current_tcb: VeniceTcbV1 {
            fmc: 1,
            tee: 1,
            snp: 1,
        },
        minimum_current_etcb: VeniceEtcbV1::from_report_bytes(
            &[1; 14].into_iter().chain([0; 18]).collect::<Vec<_>>(),
        )
        .unwrap(),
        minimum_current_mit_vector: 1,
    }
}

// Model schema/signature adapter, NOT the unprovided Microsoft policy schema.
struct TestPolicy;

impl LmPolicyVerifierV1 for TestPolicy {
    fn authenticate_and_canonicalize(
        &self,
        signed_policy: &[u8],
        chain: &[Vec<u8>],
        trust: MaPolicyTrustV1,
        _: u64,
    ) -> Result<AuthenticatedLmPolicyV1, MaPolicyErrorV1> {
        if trust != MaPolicyTrustV1::Fixture {
            return Err(MaPolicyErrorV1::PolicyUnavailable);
        }
        if signed_policy != b"test-signed-policy" || chain != [b"test-policy-chain".to_vec()] {
            return Err(MaPolicyErrorV1::InvalidPolicy);
        }
        Ok(AuthenticatedLmPolicyV1 {
            canonical_semantic_bytes: br#"{"test_only":true}"#.to_vec(),
            rules: rules(),
            release_rules: MaPolicyReleaseRulesV1::FixedReleaseV1,
            trust,
            issued_at: 10,
            expires_at: 200,
        })
    }
}

// Models certificate-path/purpose appraisal. Allowlist signatures below use real P-384.
struct TestSigner {
    key: ring::signature::EcdsaKeyPair,
    reject: Cell<bool>,
    output_trust: Cell<MaPolicyTrustV1>,
}

impl TestSigner {
    fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let algorithm = &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(algorithm, &rng).unwrap();
        Self {
            key: ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, pkcs8.as_ref(), &rng)
                .unwrap(),
            reject: Cell::new(false),
            output_trust: Cell::new(MaPolicyTrustV1::Fixture),
        }
    }

    fn claims(&self) -> AuthorizationSignerV1 {
        // DER SubjectPublicKeyInfo for id-ecPublicKey / secp384r1.
        let mut spki = vec![
            0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
        ];
        spki.extend_from_slice(self.key.public_key().as_ref());
        AuthorizationSignerV1 {
            root_spki_der: spki,
            leaf_subject_der: vec![
                0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, b'T',
                b'e', b's', b't',
            ],
            public_key_sec1: self.key.public_key().as_ref().to_vec(),
            trust: self.output_trust.get(),
        }
    }

    fn sign(&self, allowlist: &mut FixedReleaseAllowlistV1) {
        let encoded = allowlist.encode_exact().unwrap();
        allowlist.signature.copy_from_slice(
            self.key
                .sign(&ring::rand::SystemRandom::new(), &encoded[..224])
                .unwrap()
                .as_ref(),
        );
    }
}

impl MaPolicySignerVerifierV1 for TestSigner {
    fn verify_signer(
        &self,
        chain: &[Vec<u8>],
        trust: MaPolicyTrustV1,
        _: u64,
    ) -> Result<AuthorizationSignerV1, MaPolicyErrorV1> {
        if self.reject.get()
            || trust != MaPolicyTrustV1::Fixture
            || chain != [b"test-authorization-chain".to_vec()]
        {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        Ok(self.claims())
    }
}

#[derive(Default)]
struct TestStore {
    record: Option<[u8; 320]>,
    revision: u64,
    fail_load: bool,
    fail_commit: bool,
    concurrent_replacement: bool,
    commits: usize,
}

impl DurableAllowlistStoreV1 for TestStore {
    fn load_authenticated(
        &mut self,
        _: MaPolicyTrustV1,
        _: &[u8; 48],
    ) -> Result<AllowlistSnapshotV1, MaPolicyErrorV1> {
        if self.fail_load {
            return Err(MaPolicyErrorV1::StoreUnavailable);
        }
        let snapshot = AllowlistSnapshotV1 {
            revision: self.revision,
            accepted_record: self.record,
        };
        if self.concurrent_replacement {
            self.revision += 1;
        }
        Ok(snapshot)
    }

    fn commit(
        &mut self,
        _: MaPolicyTrustV1,
        _: &[u8; 48],
        revision: u64,
        record: &[u8; 320],
    ) -> Result<(), MaPolicyErrorV1> {
        if self.fail_commit {
            return Err(MaPolicyErrorV1::StoreUnavailable);
        }
        if self.revision != revision {
            return Err(MaPolicyErrorV1::StoreConflict);
        }
        self.record = Some(*record);
        self.revision += 1;
        self.commits += 1;
        Ok(())
    }
}

#[derive(Default)]
struct TestEvidenceVerifier {
    reject: bool,
    status: Option<TcbStatus>,
}

impl SnpEvidenceVerifier for TestEvidenceVerifier {
    fn verify_evidence(
        &self,
        request: &SnpEvidenceVerificationRequest<'_>,
    ) -> Result<VerifiedSnpEvidence, SnpVerificationError> {
        if self.reject {
            return Err(SnpVerificationError::CryptographicVerification);
        }
        Ok(VerifiedSnpEvidence {
            binding: request.evidence.binding(),
            trust: request.trust,
            tcb_status: self.status.clone().unwrap_or(TcbStatus::UpToDate),
            platform_tcb: None,
        })
    }
}

struct Setup {
    clock: TestClock,
    signer: TestSigner,
    policy: VerifiedLmPolicyV1,
    collateral: FixedReleaseCollateralV1,
    report_collateral: SnpCollateralSetV1,
    evidence: SnpMaEvidenceV1,
    context: ReportDataContextV1,
    selected: [u8; 48],
}

impl Setup {
    fn new() -> Self {
        let clock = TestClock(Cell::new(100));
        let signer = TestSigner::new();
        let policy = VerifiedLmPolicyV1::verify(
            &TestPolicy,
            &clock,
            b"test-signed-policy",
            &[b"test-policy-chain".to_vec()],
            MaPolicyTrustV1::Fixture,
        )
        .unwrap();
        let mut report = [0; 1184];
        report[..4].copy_from_slice(&6u32.to_le_bytes());
        report[0x04..0x08].copy_from_slice(&7u32.to_le_bytes());
        report[0x08..0x10].copy_from_slice(&0x1234u64.to_le_bytes());
        report[0x10..0x20].fill(0x11);
        report[0x20..0x30].fill(0x22);
        report[0x38..0x40].copy_from_slice(&[2, 2, 2, 0, 0, 0, 0, 0]);
        report[0x48] = 1;
        report[0x90..0xc0].fill(0x33);
        report[0xc0..0xe0].fill(0x44);
        report[0xe0..0x110].fill(0x55);
        report[0x110..0x140].fill(0x66);
        report[0x200..0x208].copy_from_slice(&3u64.to_le_bytes());
        report[0x220..0x22e].fill(2);
        let selected =
            MaPolicyIdentityInputV1::from_authenticated_report(&report, *policy.digest())
                .unwrap()
                .digest()
                .unwrap();
        let context = ReportDataContextV1 {
            evidence_purpose: SnpEvidencePurposeV1::InterNodeKeyContribution,
            role: SnpMaRoleV1::Source,
            request_id: 0x0102_0304_0506_0708,
            negotiated_migration_version: 1,
            algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            tenant_binding_id: [0x77; 32],
            th1: [0x88; 48],
            purpose_binding_digest: [0x99; 48],
            ma_policy_identity_digest: selected,
        };
        report[0x50..0x90].copy_from_slice(&context.expected_report_data().unwrap());
        let report_collateral = SnpCollateralSetV1 {
            evidence_profile: SnpEvidenceProfileV1::Fixture,
            tcb_profile: SnpTcbProfileV1::Venice,
            leaf_certificate: SnpCertificateEntryV1 {
                role: SnpCertificateRoleV1::Vcek,
                certificate_der: vec![1, 2, 3],
            },
            ask_certificate: SnpCertificateEntryV1 {
                role: SnpCertificateRoleV1::Ask,
                certificate_der: vec![4, 5, 6],
            },
        };
        let evidence = SnpMaEvidenceV1 {
            header: SnpEvidenceHeaderV1 {
                record_type: SnpRecordTypeV1::MaEvidence,
                record_length: SnpMaEvidenceV1::ENCODED_SIZE as u32,
                request_id: context.request_id,
                role: context.role,
                evidence_purpose: context.evidence_purpose,
                evidence_profile: SnpEvidenceProfileV1::Fixture,
                tcb_profile: SnpTcbProfileV1::Venice,
            },
            report_data_context: context.clone(),
            policy_identity: PolicyIdentityV1 {
                policy_digest: *policy.digest(),
            },
            collateral_digest: sha384(&report_collateral.encode_exact().unwrap()),
            ma_report: report,
        };
        let claims = signer.claims();
        let root_id = sha384(&claims.root_spki_der);
        let signer_id = hash_parts(&[
            SIGNER_DOMAIN,
            &root_id,
            &(claims.leaf_subject_der.len() as u32).to_le_bytes(),
            &claims.leaf_subject_der,
        ]);
        let mut release_id = [0; 32];
        release_id[..4].copy_from_slice(b"test");
        let mut allowlist = FixedReleaseAllowlistV1 {
            sequence: 10,
            issued_at: 20,
            expires_at: 180,
            identity_digest: selected,
            release_id,
            signer_id,
            authorization_root_id: root_id,
            signature: [0; 96],
        };
        signer.sign(&mut allowlist);
        Self {
            clock,
            signer,
            policy,
            evidence,
            context,
            selected,
            report_collateral,
            collateral: FixedReleaseCollateralV1 {
                identity: MaPolicyIdentity { allowlist },
                identity_issuer_chain: vec![b"test-authorization-chain".to_vec()],
            },
        }
    }

    fn request(&self) -> MaPolicyVerificationRequestV1<'_> {
        MaPolicyVerificationRequestV1 {
            evidence: &self.evidence,
            report_collateral: &self.report_collateral,
            expected_context: &self.context,
            selected_identity: &self.selected,
            expected_vmpl: 0,
            report_trust: SnpVerifierTrust::PinnedMilanArkTest,
            authorization_trust: MaPolicyTrustV1::Fixture,
        }
    }

    fn verify(&self, store: &mut TestStore) -> Result<VerifiedMaPolicyCollateral, MaPolicyErrorV1> {
        VerifiedMaPolicyCollateral::verify_fixed(
            &self.request(),
            &self.policy,
            &self.collateral,
            &mut MaPolicyVerificationServicesV1 {
                evidence_verifier: &TestEvidenceVerifier::default(),
                signer_verifier: &self.signer,
                clock: &self.clock,
                store,
            },
        )
    }

    fn rebind_context(&mut self, context: ReportDataContextV1) {
        self.context = context.clone();
        self.evidence.header.role = context.role;
        self.evidence.header.evidence_purpose = context.evidence_purpose;
        self.evidence.header.request_id = context.request_id;
        self.evidence.report_data_context = context;
        self.evidence.ma_report[0x50..0x90]
            .copy_from_slice(&self.context.expected_report_data().unwrap());
    }
}

fn error<T: std::fmt::Debug>(result: Result<T, MaPolicyErrorV1>) -> MaPolicyErrorV1 {
    result.unwrap_err()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn disabled_author_key_reserved_key_info_and_wrong_signing_key_fail() {
    for key_info in [0u32, 3 | (1 << 2), 1 | (7 << 2), 1 | (1 << 5)] {
        let mut setup = Setup::new();
        setup.evidence.ma_report[0x48..0x4c].copy_from_slice(&key_info.to_le_bytes());
        assert_eq!(
            error(setup.verify(&mut TestStore::default())),
            MaPolicyErrorV1::Evidence(SnpVerificationError::InvalidEvidence),
        );
    }
}

#[test]
fn all_signature_bytes_and_unchanged_identity_signed_metadata_are_authenticated() {
    let mut setup = Setup::new();
    for offset in 0..96 {
        setup.collateral.identity.allowlist.signature[offset] ^= 1;
        assert_eq!(
            error(setup.verify(&mut TestStore::default())),
            MaPolicyErrorV1::InvalidSignature
        );
        setup.collateral.identity.allowlist.signature[offset] ^= 1;
    }
    setup.collateral.identity.allowlist.sequence += 1;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::InvalidSignature
    );
}

#[test]
fn unavailable_clock_and_signer_do_not_reach_store_commit() {
    let setup = Setup::new();
    let mut store = TestStore::default();
    let unavailable = UnavailableMaPolicyServicesV1;
    for (clock, signer, expected) in [
        (
            &unavailable as &dyn MaPolicyTimeV1,
            &setup.signer as &dyn MaPolicySignerVerifierV1,
            MaPolicyErrorV1::TimeUnavailable,
        ),
        (
            &setup.clock as &dyn MaPolicyTimeV1,
            &unavailable as &dyn MaPolicySignerVerifierV1,
            MaPolicyErrorV1::SignerUnavailable,
        ),
    ] {
        assert_eq!(
            error(VerifiedMaPolicyCollateral::verify_fixed(
                &setup.request(),
                &setup.policy,
                &setup.collateral,
                &mut MaPolicyVerificationServicesV1 {
                    evidence_verifier: &TestEvidenceVerifier::default(),
                    signer_verifier: signer,
                    clock,
                    store: &mut store,
                },
            )),
            expected,
        );
        assert_eq!(store.commits, 0);
    }
}

#[test]
fn policy_and_issuer_bounds_use_exact_limits() {
    struct BoundedPolicy;
    impl LmPolicyVerifierV1 for BoundedPolicy {
        fn authenticate_and_canonicalize(
            &self,
            signed_policy: &[u8],
            _: &[Vec<u8>],
            trust: MaPolicyTrustV1,
            _: u64,
        ) -> Result<AuthenticatedLmPolicyV1, MaPolicyErrorV1> {
            Ok(AuthenticatedLmPolicyV1 {
                canonical_semantic_bytes: signed_policy.to_vec(),
                rules: rules(),
                release_rules: MaPolicyReleaseRulesV1::FixedReleaseV1,
                trust,
                issued_at: 10,
                expires_at: 200,
            })
        }
    }
    let clock = TestClock(Cell::new(100));
    for (length, succeeds) in [(0, false), (1, true), (65536, true), (65537, false)] {
        assert_eq!(
            VerifiedLmPolicyV1::verify(
                &BoundedPolicy,
                &clock,
                &vec![b'x'; length],
                &[vec![1]],
                MaPolicyTrustV1::Fixture,
            )
            .is_ok(),
            succeeds,
        );
    }
    for (count, size, succeeds) in [
        (0, 1, false),
        (1, 0, false),
        (8, 65536, true),
        (9, 1, false),
        (1, 65537, false),
    ] {
        assert_eq!(
            validate_chain_bounds(&vec![vec![1; size]; count]).is_ok(),
            succeeds
        );
    }
}

#[test]
fn identity_layout_round_trip_and_domain_are_exact() {
    let setup = Setup::new();
    let identity = MaPolicyIdentityInputV1::from_authenticated_report(
        &setup.evidence.ma_report,
        *setup.policy.digest(),
    )
    .unwrap();
    let bytes = identity.encode_exact().unwrap();
    assert_eq!(bytes.len(), 280);
    assert_eq!(&bytes[..12], &[1, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[0x0c..0x3c], &[0x33; 48]);
    assert_eq!(&bytes[0x3c..0x40], &7u32.to_le_bytes());
    assert_eq!(&bytes[0x40..0x50], &[0x11; 16]);
    assert_eq!(&bytes[0x50..0x60], &[0x22; 16]);
    assert_eq!(&bytes[0x60..0x90], &[0x55; 48]);
    assert_eq!(&bytes[0x90..0xc0], &[0x66; 48]);
    assert_eq!(&bytes[0xc0..0xe0], &[0x44; 32]);
    assert_eq!(&bytes[0xe0..0xe8], &0x1234u64.to_le_bytes());
    assert_eq!(&bytes[0xe8..], setup.policy.digest());
    assert_eq!(
        MaPolicyIdentityInputV1::decode_exact(&bytes).unwrap(),
        identity
    );
    let mut independently_framed = b"SNP-MA-POLICY-IDENTITY-v1".to_vec();
    independently_framed.extend_from_slice(&bytes);
    assert_eq!(identity.digest().unwrap(), sha384(&independently_framed));
    assert_eq!(
        hex(&identity.digest().unwrap()),
        "aa7af4eb158c42dcc19a76f00ae7d9e7830a9eb52ed68053f8b78016b9d7c34fd827ce13993431af76e8249cc73f2f19"
    );
}

#[test]
fn identity_and_allowlist_reject_truncation_trailing_and_header_changes() {
    let setup = Setup::new();
    let bytes = MaPolicyIdentityInputV1::from_authenticated_report(
        &setup.evidence.ma_report,
        *setup.policy.digest(),
    )
    .unwrap()
    .encode_exact()
    .unwrap();
    for length in 0..280 {
        assert!(MaPolicyIdentityInputV1::decode_exact(&bytes[..length]).is_err());
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(MaPolicyIdentityInputV1::decode_exact(&extended).is_err());
    for offset in 0..12 {
        let mut altered = bytes;
        altered[offset] ^= 0x80;
        assert!(MaPolicyIdentityInputV1::decode_exact(&altered).is_err());
    }
    let bytes = setup.collateral.identity.allowlist.encode_exact().unwrap();
    for length in 0..320 {
        assert!(FixedReleaseAllowlistV1::decode_exact(&bytes[..length]).is_err());
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(FixedReleaseAllowlistV1::decode_exact(&extended).is_err());
    for offset in (0..8).chain(0x20..0x28).chain(0xd8..0xe0) {
        let mut altered = bytes;
        altered[offset] ^= 0x80;
        assert!(
            FixedReleaseAllowlistV1::decode_exact(&altered).is_err(),
            "{offset}"
        );
    }
}

#[test]
fn allowlist_layout_and_real_signature_are_exact() {
    let setup = Setup::new();
    let allowlist = &setup.collateral.identity.allowlist;
    let bytes = allowlist.encode_exact().unwrap();
    assert_eq!(bytes.len(), 320);
    assert_eq!(&bytes[..8], &[1, 0, 1, 0, 0x40, 1, 0, 0]);
    assert_eq!(&bytes[8..16], &10u64.to_le_bytes());
    assert_eq!(&bytes[0x20..0x28], &[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[0x28..0x58], &setup.selected);
    assert_eq!(&bytes[0xd8..0xe0], &[1, 0, 1, 0, 1, 0, 0, 0]);
    assert_eq!(&bytes[0xe0..], &allowlist.signature);
    assert_eq!(
        FixedReleaseAllowlistV1::decode_exact(&bytes).unwrap(),
        *allowlist
    );
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P384_SHA384_FIXED,
        setup.signer.key.public_key(),
    )
    .verify(&bytes[..224], &bytes[224..])
    .unwrap();
}

#[test]
fn release_labels_are_bounded_printable_and_canonically_padded() {
    let mut setup = Setup::new();
    for label in [[0; 32], [0xff; 32], [0x1f; 32], [0x7f; 32]] {
        setup.collateral.identity.allowlist.release_id = label;
        assert!(setup.collateral.identity.allowlist.encode_exact().is_err());
    }
    let mut label = [0; 32];
    label[..3].copy_from_slice(&[b'a', 0, b'b']);
    setup.collateral.identity.allowlist.release_id = label;
    assert!(setup.collateral.identity.allowlist.encode_exact().is_err());
    setup.collateral.identity.allowlist.release_id = [b'x'; 32];
    assert!(setup.collateral.identity.allowlist.encode_exact().is_ok());
}

#[test]
fn policy_authentication_and_hashing_are_not_a_raw_bytes_constructor() {
    let setup = Setup::new();
    let bytes = br#"{"test_only":true}"#;
    let mut preimage = b"SNP-LM-POLICY-v1".to_vec();
    preimage.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    preimage.extend_from_slice(bytes);
    assert_eq!(*setup.policy.digest(), sha384(&preimage));
    assert_eq!(
        hex(setup.policy.digest()),
        "aba0e1a36419c54ce5b6715a0e3c58da616c5f7fd181e67568ee1c7699a606a27a548c1e241ace854649093057d243fa"
    );
    for policy in [b"unknown-field".as_slice(), b"invalid-signature", b""] {
        assert!(VerifiedLmPolicyV1::verify(
            &TestPolicy,
            &setup.clock,
            policy,
            &[b"test-policy-chain".to_vec()],
            MaPolicyTrustV1::Fixture,
        )
        .is_err());
    }
    assert_eq!(
        error(VerifiedLmPolicyV1::verify(
            &UnavailableMaPolicyServicesV1,
            &setup.clock,
            b"unavailable",
            &[vec![1]],
            MaPolicyTrustV1::Fixture,
        )),
        MaPolicyErrorV1::PolicyUnavailable
    );
    assert_eq!(
        error(VerifiedLmPolicyV1::verify(
            &TestPolicy,
            &UnavailableMaPolicyServicesV1,
            b"test-signed-policy",
            &[vec![1]],
            MaPolicyTrustV1::Fixture,
        )),
        MaPolicyErrorV1::TimeUnavailable
    );
}

#[test]
fn approval_is_minted_only_after_atomic_store_acknowledgement() {
    let setup = Setup::new();
    let mut store = TestStore::default();
    let verified = setup.verify(&mut store).unwrap();
    assert_eq!(verified.identity_digest(), &setup.selected);
    assert_eq!(verified.context(), &setup.context);
    assert_eq!(verified.report_id(), &[0; 32]);
    assert_eq!(verified.report_digest(), &sha384(&setup.evidence.ma_report));
    assert_eq!(
        verified.report_collateral_digest(),
        &setup.evidence.collateral_digest
    );
    assert_eq!(store.commits, 1);
    assert_eq!(
        store.record.unwrap(),
        setup.collateral.identity.allowlist.encode_exact().unwrap()
    );
    store.fail_commit = true;
    assert_eq!(
        error(setup.verify(&mut store)),
        MaPolicyErrorV1::StoreUnavailable
    );
    assert_eq!(store.commits, 1);
}

#[test]
fn every_identity_input_byte_is_checked_against_selected_identity() {
    for range in [0x04..0x10, 0x10..0x30, 0x90..0x140] {
        for offset in range {
            let mut setup = Setup::new();
            setup.evidence.ma_report[offset] ^= 1;
            let mut store = TestStore::default();
            assert_eq!(
                error(setup.verify(&mut store)),
                MaPolicyErrorV1::IdentityMismatch
            );
            assert_eq!(store.commits, 0);
        }
    }
    let mut setup = Setup::new();
    setup.selected[0] ^= 1;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::IdentityMismatch
    );
}

#[test]
fn signature_signer_chain_root_and_purpose_substitutions_fail() {
    let mut setup = Setup::new();
    setup.collateral.identity.allowlist.signature[0] ^= 1;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::InvalidSignature
    );
    setup.signer.sign(&mut setup.collateral.identity.allowlist);
    setup.collateral.identity.allowlist.signer_id[0] ^= 1;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::InvalidSigner
    );
    setup.collateral.identity.allowlist.signer_id[0] ^= 1;
    setup.collateral.identity.allowlist.authorization_root_id[0] ^= 1;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::InvalidSigner
    );
    setup.collateral.identity.allowlist.authorization_root_id[0] ^= 1;
    setup.signer.reject.set(true);
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::InvalidSigner
    );
    setup.signer.reject.set(false);
    setup.collateral.identity_issuer_chain[0][0] ^= 1;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::InvalidSigner
    );
}

#[test]
fn allowlist_validity_boundaries_and_cached_policy_expiration_are_rechecked() {
    let setup = Setup::new();
    for (now, success) in [
        (19, false),
        (20, true),
        (179, true),
        (180, false),
        (200, false),
    ] {
        setup.clock.0.set(now);
        assert_eq!(
            setup.verify(&mut TestStore::default()).is_ok(),
            success,
            "{now}"
        );
    }
    let mut setup = Setup::new();
    setup.collateral.identity.allowlist.expires_at = 300;
    setup.signer.sign(&mut setup.collateral.identity.allowlist);
    setup.clock.0.set(200);
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::OutsideValidity
    );
}

#[test]
fn rollback_and_same_sequence_replacement_are_rejected_after_reload() {
    let mut setup = Setup::new();
    let mut store = TestStore::default();
    setup.verify(&mut store).unwrap();
    setup.verify(&mut store).unwrap();
    assert_eq!(store.commits, 2);
    store = TestStore {
        record: store.record,
        revision: store.revision,
        ..Default::default()
    };
    setup.collateral.identity.allowlist.sequence = 9;
    setup.signer.sign(&mut setup.collateral.identity.allowlist);
    assert_eq!(
        error(setup.verify(&mut store)),
        MaPolicyErrorV1::SequenceRollback
    );
    setup.collateral.identity.allowlist.sequence = 10;
    setup.collateral.identity.allowlist.release_id[0] = b'n';
    setup.signer.sign(&mut setup.collateral.identity.allowlist);
    assert_eq!(
        error(setup.verify(&mut store)),
        MaPolicyErrorV1::SequenceContentConflict
    );
    setup.collateral.identity.allowlist.sequence = 11;
    setup.signer.sign(&mut setup.collateral.identity.allowlist);
    setup.verify(&mut store).unwrap();
    assert_eq!(store.commits, 1);
}

#[test]
fn store_missing_corrupt_conflicting_and_unavailable_states_fail_closed() {
    let setup = Setup::new();
    let mut store = TestStore {
        fail_load: true,
        ..Default::default()
    };
    assert_eq!(
        error(setup.verify(&mut store)),
        MaPolicyErrorV1::StoreUnavailable
    );
    assert_eq!(store.commits, 0);
    let mut store = TestStore {
        record: Some([0; 320]),
        ..Default::default()
    };
    assert_eq!(
        error(setup.verify(&mut store)),
        MaPolicyErrorV1::InvalidStoredState
    );
    let mut store = TestStore {
        concurrent_replacement: true,
        ..Default::default()
    };
    assert_eq!(
        error(setup.verify(&mut store)),
        MaPolicyErrorV1::StoreConflict
    );
    let mut unavailable = UnavailableMaPolicyServicesV1;
    assert_eq!(
        error(VerifiedMaPolicyCollateral::verify_fixed(
            &setup.request(),
            &setup.policy,
            &setup.collateral,
            &mut MaPolicyVerificationServicesV1 {
                evidence_verifier: &TestEvidenceVerifier::default(),
                signer_verifier: &setup.signer,
                clock: &setup.clock,
                store: &mut unavailable,
            },
        )),
        MaPolicyErrorV1::StoreUnavailable
    );
}

#[test]
fn fixture_and_production_are_not_interchangeable() {
    let setup = Setup::new();
    let mut request = setup.request();
    request.authorization_trust = MaPolicyTrustV1::Production;
    assert_eq!(
        error(VerifiedMaPolicyCollateral::verify_fixed(
            &request,
            &setup.policy,
            &setup.collateral,
            &mut MaPolicyVerificationServicesV1 {
                evidence_verifier: &TestEvidenceVerifier::default(),
                signer_verifier: &setup.signer,
                clock: &setup.clock,
                store: &mut TestStore::default(),
            },
        )),
        MaPolicyErrorV1::ProductionProfileUnavailable
    );
    setup.signer.output_trust.set(MaPolicyTrustV1::Production);
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::TrustMismatch
    );
}

#[test]
fn exact_context_and_policy_envelope_binding_are_required() {
    for field in 0..8 {
        let mut setup = Setup::new();
        match field {
            0 => setup.context.request_id ^= 1,
            1 => setup.context.tenant_binding_id[0] ^= 1,
            2 => setup.context.th1[0] ^= 1,
            3 => setup.context.role = SnpMaRoleV1::Destination,
            4 => setup.context.purpose_binding_digest[0] ^= 1,
            5 => setup.context.ma_policy_identity_digest[0] ^= 1,
            6 => setup.context.negotiated_migration_version ^= 1,
            _ => setup.evidence.policy_identity.policy_digest[0] ^= 1,
        }
        assert_eq!(
            error(setup.verify(&mut TestStore::default())),
            MaPolicyErrorV1::ContextMismatch
        );
    }
    let mut setup = Setup::new();
    setup.evidence.ma_report[0x8f] = 1;
    assert!(matches!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::Evidence(SnpVerificationError::ReportDataBinding)
    ));
}

#[test]
fn certificate_contents_roles_order_and_profiles_are_bound() {
    let mut setup = Setup::new();
    setup.report_collateral.leaf_certificate.certificate_der[0] ^= 1;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::CollateralMismatch
    );
    setup.report_collateral.leaf_certificate.certificate_der[0] ^= 1;
    core::mem::swap(
        &mut setup.report_collateral.leaf_certificate,
        &mut setup.report_collateral.ask_certificate,
    );
    assert!(setup.verify(&mut TestStore::default()).is_err());
    let mut setup = Setup::new();
    setup.report_collateral.evidence_profile = SnpEvidenceProfileV1::Production;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::TrustMismatch
    );
    let mut setup = Setup::new();
    setup.report_collateral.tcb_profile = SnpTcbProfileV1::Turin;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::ContextMismatch
    );
}

#[test]
fn all_tcb_etcb_components_and_mitigation_bits_are_checked() {
    for offset in [0x38, 0x39, 0x3a].into_iter().chain(0x220..0x22e) {
        let mut setup = Setup::new();
        setup.evidence.ma_report[offset] = 0;
        assert_eq!(
            error(setup.verify(&mut TestStore::default())),
            MaPolicyErrorV1::PlatformDowngrade
        );
    }
    for offset in (0x3b..0x40).chain(0x22e..0x240) {
        let mut setup = Setup::new();
        setup.evidence.ma_report[offset] = 1;
        assert!(matches!(
            error(setup.verify(&mut TestStore::default())),
            MaPolicyErrorV1::Codec(_)
        ));
    }
    let mut setup = Setup::new();
    setup.evidence.ma_report[0x200] = 2;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::MitigationMissing
    );
}

#[test]
fn reported_committed_and_launch_values_cannot_replace_current_floors() {
    let mut setup = Setup::new();
    setup.evidence.ma_report[0x180..0x188].fill(0xff);
    setup.evidence.ma_report[0x1e0..0x200].fill(0xff);
    setup.evidence.ma_report[0x240..0x280].fill(0xff);
    setup.evidence.ma_report[0x38] = 0;
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::PlatformDowngrade
    );
}

#[test]
fn platform_and_session_specific_fields_do_not_change_release_fingerprint() {
    let setup = Setup::new();
    for range in [0x38..0x40, 0x50..0x90, 0x140..0x180, 0x180..0x280] {
        let mut report = setup.evidence.ma_report;
        report[range].fill(0xaa);
        assert_eq!(
            MaPolicyIdentityInputV1::from_authenticated_report(&report, *setup.policy.digest(),)
                .unwrap()
                .digest()
                .unwrap(),
            setup.selected
        );
    }
}

fn pair(
    setup: &Setup,
    dst_context: ReportDataContextV1,
    destination_tcb: u8,
    destination_etcb: u8,
    destination_mit: u8,
) -> (VerifiedMaPolicyCollateral, VerifiedMaPolicyCollateral) {
    let mut store = TestStore::default();
    let source = setup.verify(&mut store).unwrap();
    let mut evidence = setup.evidence.clone();
    evidence.header.role = dst_context.role;
    evidence.header.evidence_purpose = dst_context.evidence_purpose;
    evidence.header.request_id = dst_context.request_id;
    evidence.report_data_context = dst_context.clone();
    evidence.ma_report[0x50..0x90].copy_from_slice(&dst_context.expected_report_data().unwrap());
    evidence.ma_report[0x38] = destination_tcb;
    evidence.ma_report[0x220] = destination_etcb;
    evidence.ma_report[0x200] = destination_mit;
    let mut request = setup.request();
    request.evidence = &evidence;
    request.expected_context = &dst_context;
    let destination = VerifiedMaPolicyCollateral::verify_fixed(
        &request,
        &setup.policy,
        &setup.collateral,
        &mut MaPolicyVerificationServicesV1 {
            evidence_verifier: &TestEvidenceVerifier::default(),
            signer_verifier: &setup.signer,
            clock: &setup.clock,
            store: &mut store,
        },
    )
    .unwrap();
    (source, destination)
}

#[test]
fn pair_admission_checks_each_forwarding_dimension_not_lexicographic_rank() {
    let setup = Setup::new();
    let mut dst = setup.context.clone();
    dst.role = SnpMaRoleV1::Destination;
    dst.purpose_binding_digest[0] ^= 1;
    for (tcb, etcb, mit, expected) in [
        (2, 2, 3, Ok(())),
        (3, 3, 7, Ok(())),
        (1, 3, 3, Err(MaPolicyErrorV1::PlatformDowngrade)),
        (3, 1, 3, Err(MaPolicyErrorV1::PlatformDowngrade)),
        (3, 3, 1, Err(MaPolicyErrorV1::MitigationMissing)),
    ] {
        let (source, destination) = pair(&setup, dst.clone(), tcb, etcb, mit);
        assert_eq!(admit_fixed_release_pair_v1(&source, &destination), expected);
    }
}

#[test]
fn mismatched_pair_sessions_roles_and_tenants_fail() {
    let setup = Setup::new();
    for field in 0..5 {
        let mut dst = setup.context.clone();
        dst.role = SnpMaRoleV1::Destination;
        match field {
            0 => dst.request_id ^= 1,
            1 => dst.tenant_binding_id[0] ^= 1,
            2 => dst.th1[0] ^= 1,
            3 => dst.role = SnpMaRoleV1::Source,
            _ => dst.negotiated_migration_version ^= 1,
        }
        let (source, destination) = pair(&setup, dst, 2, 2, 3);
        assert_eq!(
            admit_fixed_release_pair_v1(&source, &destination),
            Err(MaPolicyErrorV1::ContextMismatch)
        );
    }
}

#[test]
fn planned_handoff_uses_same_release_without_invented_initial_authorization() {
    let mut setup = Setup::new();
    let mut outgoing = setup.context.clone();
    outgoing.role = SnpMaRoleV1::Outgoing;
    outgoing.evidence_purpose = SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization;
    outgoing.algorithm = SnpMigrationAlgorithmV1::LocalHandoffSecretV1;
    outgoing.tenant_binding_id = [0; 32];
    setup.rebind_context(outgoing.clone());
    let mut incoming = outgoing;
    incoming.role = SnpMaRoleV1::Incoming;
    let (source, destination) = pair(&setup, incoming, 2, 2, 3);
    admit_fixed_release_pair_v1(&source, &destination).unwrap();
}

#[test]
fn cryptographic_evidence_failure_or_bad_tcb_status_cannot_mint_approval() {
    let setup = Setup::new();
    for verifier in [
        TestEvidenceVerifier {
            reject: true,
            status: None,
        },
        TestEvidenceVerifier {
            reject: false,
            status: Some(TcbStatus::Revoked),
        },
    ] {
        let mut store = TestStore::default();
        assert!(VerifiedMaPolicyCollateral::verify_fixed(
            &setup.request(),
            &setup.policy,
            &setup.collateral,
            &mut MaPolicyVerificationServicesV1 {
                evidence_verifier: &verifier,
                signer_verifier: &setup.signer,
                clock: &setup.clock,
                store: &mut store,
            },
        )
        .is_err());
        assert_eq!(store.commits, 0);
    }
}
