// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Test-only P0.10 references. No live provider, production PKI or claims adapter.

use super::*;
use crate::{
    snp::{
        confirmation::{
            SnpConfirmationDirectionV1, SnpConfirmationSequenceV1, SnpConfirmationStateV1,
            SnpConfirmationStatusV1, SnpConfirmationV1, SnpConfirmationVerificationErrorV1,
            SnpConfirmationVerifierV1, SnpSessionReferenceV1, UnavailableSnpConfirmationVerifierV1,
            UnavailableSnpPersistedInstallationVerifierV1,
        },
        contribution_exchange::{
            ContributionCommitmentErrorV1, ContributionCommitmentVerifierV1,
            UnavailableContributionCommitmentVerifierV1,
        },
        migration_data::{MigrationDataV1, TenantHistoryInputV1},
        purpose_binding::{
            CanonicalFirmwareResultSetV1, CanonicalTenantSetV1, FirmwareRebindResultV1,
            LocalHandoffBindingV1, PostInstallBindingV1, SnpOperationStageV1,
            VerifiedTenantReportIdV1,
        },
        tenant_authorization::{
            canonical_tenant_evidence_digest_v1, TenantAuthorizationContextV1,
            VerifiedContributionMaV1,
        },
        wire::StrictWriter,
    },
    tenant_identity::{
        HostPushedTenantReportV1, PrepareMigrationRequestV1, TenantReportDeliveryV1,
    },
    types::{
        HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, SnpOperationContext,
        SnpVerificationCollateral,
    },
};
use crypto::x509::{Certificate, Decode, Encode, SequenceOf, Time};
use ring::{hkdf, hmac, signature};

fn certificate_from_der(bytes: &[u8]) -> Result<Certificate<'_>, crypto::x509::DerError> {
    Certificate::from_der(bytes)
}

fn extension(cert: &Certificate<'_>, oid: &str) -> Option<Vec<u8>> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .get()
        .iter()
        .find(|ext| ext.extn_id.to_string() == oid)
        .and_then(|ext| ext.extn_value.map(|value| value.as_bytes().to_vec()))
}

const REQUEST: u64 = 0x0102_0304_0506_0708;
const CORPUS: &str = include_str!("test_data/p010_vectors.txt");

fn vector(name: &str) -> Vec<u8> {
    let encoded = CORPUS
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == name).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing independent vector {name}"));
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).expect("fixture hex")
        })
        .collect()
}

fn array<const N: usize>(name: &str) -> [u8; N] {
    vector(name).try_into().unwrap()
}

fn compare(name: &str, actual: &[u8]) {
    assert_eq!(actual, vector(name), "{name}");
}

fn certificate_key(cert: &Certificate<'_>) -> Result<Vec<u8>, MaPolicyErrorV1> {
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| MaPolicyErrorV1::InvalidSigner)?;
    let prefix = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
    ];
    if spki.len() != prefix.len() + 97 || !spki.starts_with(&prefix) {
        return Err(MaPolicyErrorV1::InvalidSigner);
    }
    Ok(spki[prefix.len()..].to_vec())
}

fn certificate_edge(
    issuer: &Certificate<'_>,
    subject: &Certificate<'_>,
) -> Result<(), MaPolicyErrorV1> {
    if issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|_| MaPolicyErrorV1::InvalidSigner)?
        != subject
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(|_| MaPolicyErrorV1::InvalidSigner)?
    {
        return Err(MaPolicyErrorV1::InvalidSigner);
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, certificate_key(issuer)?)
        .verify(
            &subject
                .tbs_certificate
                .to_der()
                .map_err(|_| MaPolicyErrorV1::InvalidSigner)?,
            subject
                .signature_value
                .as_bytes()
                .ok_or(MaPolicyErrorV1::InvalidSigner)?,
        )
        .map_err(|_| MaPolicyErrorV1::InvalidSigner)
}

// This deliberately small fixture path is NOT a production RFC 5280 provider.
fn fixture_chain(
    root_bytes: &[u8],
    chain: &[Vec<u8>],
    now: u64,
    purpose: bool,
) -> Result<AuthorizationSignerV1, MaPolicyErrorV1> {
    if root_bytes != vector("root_der") || chain.len() != 2 {
        return Err(MaPolicyErrorV1::InvalidSigner);
    }
    fn parse(bytes: &[u8]) -> Result<Certificate<'_>, MaPolicyErrorV1> {
        let cert = certificate_from_der(bytes).map_err(|_| MaPolicyErrorV1::InvalidSigner)?;
        if cert.to_der().map_err(|_| MaPolicyErrorV1::InvalidSigner)? != bytes {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        let outer_header = 2 + if bytes[1] & 0x80 == 0 {
            0
        } else {
            usize::from(bytes[1] & 0x7f)
        };
        let algorithm_offset = outer_header
            + cert
                .tbs_certificate
                .to_der()
                .map_err(|_| MaPolicyErrorV1::InvalidSigner)?
                .len();
        if bytes.get(algorithm_offset..algorithm_offset + 12)
            != Some(
                [
                    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
                ]
                .as_slice(),
            )
        {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        let signature_offset = algorithm_offset + 12;
        let bitstring_length = u8::try_from(
            cert.signature_value
                .as_bytes()
                .ok_or(MaPolicyErrorV1::InvalidSigner)?
                .len()
                + 1,
        )
        .map_err(|_| MaPolicyErrorV1::InvalidSigner)?;
        if bytes.get(signature_offset..signature_offset + 3)
            != Some([3, bitstring_length, 0].as_slice())
        {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        Ok(cert)
    }
    let root = parse(root_bytes)?;
    let ask = parse(&chain[1])?;
    let leaf = parse(&chain[0])?;
    for cert in [&root, &ask, &leaf] {
        let seconds = |time: &Time| match time {
            Time::Utc(value) => value.to_unix_duration().as_secs(),
            Time::Generalized(value) => value.to_unix_duration().as_secs(),
        };
        let validity_der = cert
            .tbs_certificate
            .validity
            .to_der()
            .map_err(|_| MaPolicyErrorV1::InvalidSigner)?;
        let validity = SequenceOf::<Time, 2>::from_der(&validity_der)
            .map_err(|_| MaPolicyErrorV1::InvalidSigner)?;
        if validity.len() != 2
            || now < seconds(validity.get(0).ok_or(MaPolicyErrorV1::InvalidSigner)?)
            || now > seconds(validity.get(1).ok_or(MaPolicyErrorV1::InvalidSigner)?)
        {
            return Err(MaPolicyErrorV1::OutsideValidity);
        }
    }
    for (cert, path_length) in [(&root, 1), (&ask, 0)] {
        if extension(cert, "2.5.29.19") != Some(vec![0x30, 6, 1, 1, 0xff, 2, 1, path_length])
            || !extension(cert, "2.5.29.15").is_some_and(|usage| {
                usage.len() == 4 && usage[0..2] == [3, 2] && usage[2] <= 2 && usage[3] & 4 != 0
            })
        {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
    }
    if extension(&leaf, "2.5.29.19") != Some(vec![0x30, 0])
        || extension(&leaf, "2.5.29.15") != Some(vec![3, 2, 7, 0x80])
    {
        return Err(MaPolicyErrorV1::InvalidSigner);
    }
    certificate_edge(&root, &root)?;
    certificate_edge(&root, &ask)?;
    certificate_edge(&ask, &leaf)?;
    if purpose && extension(&leaf, "2.5.29.37") != Some(vector("signer_purpose_der")) {
        return Err(MaPolicyErrorV1::InvalidSigner);
    }
    Ok(AuthorizationSignerV1 {
        root_spki_der: root
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| MaPolicyErrorV1::InvalidSigner)?,
        leaf_subject_der: leaf
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|_| MaPolicyErrorV1::InvalidSigner)?,
        public_key_sec1: certificate_key(&leaf)?,
        trust: MaPolicyTrustV1::Fixture,
    })
}

struct FixtureSigner;

impl MaPolicySignerVerifierV1 for FixtureSigner {
    fn verify_signer(
        &self,
        chain: &[Vec<u8>],
        trust: MaPolicyTrustV1,
        now: u64,
    ) -> Result<AuthorizationSignerV1, MaPolicyErrorV1> {
        if trust != MaPolicyTrustV1::Fixture {
            return Err(MaPolicyErrorV1::TrustMismatch);
        }
        fixture_chain(&vector("root_der"), chain, now, true)
    }
}

fn verify_report_signature(report: &[u8; 1184], key: &[u8]) -> bool {
    if report[0x2d0..0x2e8] != [0; 24] || report[0x318..] != [0; 392] {
        return false;
    }
    let mut sig = [0; 96];
    for i in 0..48 {
        sig[i] = report[0x2cf - i];
        sig[48 + i] = report[0x317 - i];
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, key)
        .verify(&report[..0x2a0], &sig)
        .is_ok()
}

struct FixtureEvidence;

impl SnpEvidenceVerifier for FixtureEvidence {
    fn verify_evidence(
        &self,
        request: &SnpEvidenceVerificationRequest<'_>,
    ) -> Result<VerifiedSnpEvidence, SnpVerificationError> {
        // Legacy enum is only the test bridge carrier; this is not SnpQvl/Milan appraisal.
        if request.trust != SnpVerifierTrust::PinnedMilanArkTest {
            return Err(SnpVerificationError::UnsupportedTrust);
        }
        let signer = fixture_chain(
            &vector("root_der"),
            &[
                request.collateral.leaf_der().to_vec(),
                request.collateral.ask_der().to_vec(),
            ],
            100,
            false,
        )
        .map_err(|_| SnpVerificationError::InvalidCollateral)?;
        if !verify_report_signature(request.evidence.report(), &signer.public_key_sec1) {
            return Err(SnpVerificationError::CryptographicVerification);
        }
        Ok(VerifiedSnpEvidence {
            binding: request.evidence.binding(),
            trust: request.trust,
            tcb_status: TcbStatus::UpToDate,
            platform_tcb: None,
        })
    }
}

fn context(role: SnpMaRoleV1) -> ReportDataContextV1 {
    let name = if role == SnpMaRoleV1::Source {
        "source_context"
    } else {
        "destination_context"
    };
    ReportDataContextV1::decode_exact(&vector(name)).unwrap()
}

fn commitment(context: &ReportDataContextV1, secret: &[u8; 32]) -> [u8; 48] {
    assert_eq!(
        context.evidence_purpose,
        SnpEvidencePurposeV1::InterNodeKeyContribution
    );
    assert!(matches!(
        context.role,
        SnpMaRoleV1::Source | SnpMaRoleV1::Destination
    ));
    let mut zero = context.clone();
    zero.purpose_binding_digest = [0; 48];
    hash_parts(&[
        b"SNP-LM-CONTRIBUTION-v1",
        &zero.encode_exact().unwrap(),
        secret,
    ])
}

fn history() -> MigrationDataV1 {
    let base = array::<1184>("tenant_report");
    MigrationDataV1::from_tenant(
        &TenantHistoryInputV1 {
            report_version: 6,
            profile: SnpTcbProfileV1::Venice,
            launch_tcb: base[0x1f0..0x1f8].try_into().unwrap(),
            launch_etcb: base[0x240..0x260].try_into().unwrap(),
            launch_mitigation_vector: u64::from_le_bytes(base[0x1f8..0x200].try_into().unwrap()),
            report_id_ma: [0x11; 32],
            migration_data_valid: false,
            migration_data: None,
        },
        &[0x11; 32],
    )
    .unwrap()
}

fn raw_authorization() -> TenantAuthorizationContextV1 {
    let collateral = SnpVerificationCollateral::new(vector("vcek_der"), vector("ask_der"));
    let operation = SnpOperationContext::new(
        HostRequestId::new(REQUEST),
        MigrationId::new(2),
        MigrationRole::Source,
        ManagedGuestHandle::new(3),
    );
    let tenant = PrepareMigrationRequestV1::new(
        operation,
        TenantReportDeliveryV1::Inline(
            HostPushedTenantReportV1::from_bytes(&vector("tenant_report")).unwrap(),
        ),
    )
    .verify_tenant_report(
        &FixtureEvidence,
        &collateral,
        SnpVerifierTrust::PinnedMilanArkTest,
        None,
    )
    .unwrap();
    let proof = |role: SnpMaRoleV1, name: &str| {
        VerifiedContributionMaV1::verify(
            &context(role),
            &FixtureEvidence,
            &MaEvidence::new(array(name), MaEvidenceBinding::RequestedReportData),
            &collateral,
            0,
            SnpVerifierTrust::PinnedMilanArkTest,
        )
        .unwrap()
    };
    TenantAuthorizationContextV1::new(
        tenant,
        proof(SnpMaRoleV1::Source, "source_report"),
        proof(SnpMaRoleV1::Destination, "destination_report"),
    )
    .unwrap()
}

fn verify_supplement(
    base: &[u8; 1184],
    supplement: &[u8],
    sig: &[u8],
    key: &[u8],
) -> Result<(), &'static str> {
    if supplement.len() != 220
        || supplement[..4] != [1, 0, 1, 0]
        || base[0x48] & 0x20 != 0
        || supplement[149..156] != [0; 7]
    {
        return Err("supplement codec");
    }
    let message = [b"SNP-EMU-SUPPLEMENT-v1".as_slice(), supplement].concat();
    signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, key)
        .verify(&message, sig)
        .map_err(|_| "supplement signature")?;
    if supplement[4..52] != sha384(base)
        || supplement[52..84] != base[0x220..0x240]
        || supplement[84..116] != base[0x240..0x260]
        || supplement[116..148] != base[0x260..0x280]
        || supplement[148] > 1
        || (supplement[148] == 0 && supplement[156..] != [0; 64])
    {
        return Err("supplement binding");
    }
    Ok(())
}

fn complete_ma_digest(name: &str, emulator: bool) -> [u8; 48] {
    let evidence = SnpMaEvidenceV1::decode_exact(&vector(&format!("{name}_ma_evidence"))).unwrap();
    let encoded = evidence.encode_exact().unwrap();
    if emulator {
        let supplement = vector(&format!("{name}_supplement"));
        let sig = vector(&format!("{name}_supplement_signature"));
        verify_supplement(&evidence.ma_report, &supplement, &sig, &vector("vcek_sec1")).unwrap();
        hash_parts(&[
            b"SNP-LM-MA-EVIDENCE-v1",
            &2u16.to_le_bytes(),
            &1540u32.to_le_bytes(),
            &encoded,
            &220u32.to_le_bytes(),
            &supplement,
            &96u32.to_le_bytes(),
            &sig,
        ])
    } else {
        hash_parts(&[
            b"SNP-LM-MA-EVIDENCE-v1",
            &1u16.to_le_bytes(),
            &1540u32.to_le_bytes(),
            &encoded,
            &[0; 8],
        ])
    }
}

fn emulator_authorization_bytes() -> [u8; 421] {
    let mut encoded = raw_authorization().encode_exact().unwrap();
    let base = array("tenant_report");
    let supplement = array("tenant_supplement");
    let sig = array("tenant_supplement_signature");
    verify_supplement(&base, &supplement, &sig, &vector("vcek_sec1")).unwrap();
    // Reference encoding only: no supplemented delivery receipt is minted.
    let offset = TenantAuthorizationContextV1::DOMAIN.len() + 48;
    encoded[offset..offset + 48].copy_from_slice(&canonical_tenant_evidence_digest_v1(
        &base,
        Some((&supplement, &sig)),
    ));
    encoded
}

fn session_bytes(ordered: bool) -> [u8; 799] {
    let mut encoded = [0; 799];
    let mut writer = StrictWriter::new(&mut encoded);
    writer.write_bytes(b"SNP-LM-SESSION-v1").unwrap();
    writer.write_u16(1).unwrap();
    writer.write_bytes(&emulator_authorization_bytes()).unwrap();
    for name in ["source", "destination"] {
        writer.write_bytes(&complete_ma_digest(name, true)).unwrap();
    }
    let collateral = SnpCollateralSetV1::decode_exact(&vector("collateral")).unwrap();
    writer
        .write_bytes(&sha384(&collateral.encode_exact().unwrap()))
        .unwrap();
    writer
        .write_bytes(&history().encode_exact().unwrap())
        .unwrap();
    writer.write_u16(1).unwrap();
    writer.write_u16(1).unwrap();
    writer.write_u8(3).unwrap();
    writer.write_u16(if ordered { 2 } else { 1 }).unwrap();
    let record = if ordered {
        ordered::MaReleaseEndorsementV1::decode_exact(&vector("ordered_snapshot"))
            .unwrap()
            .encode_exact()
            .unwrap()
    } else {
        FixedReleaseAllowlistV1::decode_exact(&vector("allowlist"))
            .unwrap()
            .encode_exact()
            .unwrap()
            .to_vec()
    };
    let digest = hash_parts(&[
        b"SNP-LM-APPROVAL-v1",
        &(if ordered { 2u16 } else { 1 }).to_le_bytes(),
        &record,
    ]);
    writer.write_bytes(&digest).unwrap();
    writer.write_bytes(&digest).unwrap();
    let initial = if ordered {
        let initial =
            ordered::InitialMaAuthorizationV1::decode_exact(&vector("initial_record")).unwrap();
        hash_parts(&[b"SNP-LM-INITIAL-v1", &initial.encode_exact().unwrap()])
    } else {
        [0; 48]
    };
    writer.write_bytes(&initial).unwrap();
    assert_eq!(writer.written(), 799);
    encoded
}

struct OutputSize(usize);

impl hkdf::KeyType for OutputSize {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_output(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA384, salt).extract(ikm);
    let mut output = vec![0; length];
    prk.expand(&[info], OutputSize(length))
        .unwrap()
        .fill(&mut output)
        .unwrap();
    output
}

fn confirmation_tag(record: &SnpConfirmationV1, key: &[u8]) -> [u8; 48] {
    let mut zero = record.clone();
    zero.tag = [0; 48];
    let input = [
        b"SNP-LM-CONFIRM-v1".as_slice(),
        &zero.encode_exact().unwrap(),
    ]
    .concat();
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA384, key), &input)
        .as_ref()
        .try_into()
        .unwrap()
}

struct FixtureConfirmation {
    expected: SnpSessionReferenceV1,
    source_key: [u8; 48],
    destination_key: [u8; 48],
}

impl SnpConfirmationVerifierV1 for FixtureConfirmation {
    fn verify(&self, record: &SnpConfirmationV1) -> Result<(), SnpConfirmationVerificationErrorV1> {
        if record.session != self.expected || record.status != SnpConfirmationStatusV1::Confirmed {
            return Err(SnpConfirmationVerificationErrorV1::TagMismatch);
        }
        let key = match (record.role, record.direction) {
            (SnpMaRoleV1::Source, SnpConfirmationDirectionV1::SourceToDestination) => {
                self.source_key
            }
            (SnpMaRoleV1::Destination, SnpConfirmationDirectionV1::DestinationToSource) => {
                self.destination_key
            }
            _ => return Err(SnpConfirmationVerificationErrorV1::TagMismatch),
        };
        let mut zero = record.clone();
        zero.tag = [0; 48];
        let input = [
            b"SNP-LM-CONFIRM-v1".as_slice(),
            &zero
                .encode_exact()
                .map_err(|_| SnpConfirmationVerificationErrorV1::TagMismatch)?,
        ]
        .concat();
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA384, &key),
            &input,
            &record.tag,
        )
        .map_err(|_| SnpConfirmationVerificationErrorV1::TagMismatch)
    }
}

#[test]
fn independent_identity_allowlist_and_real_fixture_chain() {
    let identity = MaPolicyIdentityInputV1::decode_exact(&vector("identity")).unwrap();
    compare("identity", &identity.encode_exact().unwrap());
    compare("identity_digest", &identity.digest().unwrap());
    let allowlist = FixedReleaseAllowlistV1::decode_exact(&vector("allowlist")).unwrap();
    compare("allowlist", &allowlist.encode_exact().unwrap());
    let signer = FixtureSigner
        .verify_signer(
            &[vector("signer_der"), vector("ask_der")],
            MaPolicyTrustV1::Fixture,
            100,
        )
        .unwrap();
    compare("root_id", &sha384(&signer.root_spki_der));
    compare(
        "signer_id",
        &hash_parts(&[
            SIGNER_DOMAIN,
            &sha384(&signer.root_spki_der),
            &(signer.leaf_subject_der.len() as u32).to_le_bytes(),
            &signer.leaf_subject_der,
        ]),
    );
    signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, signer.public_key_sec1)
        .verify(&vector("allowlist")[..224], &allowlist.signature)
        .unwrap();
    for offset in 0..280 {
        let mut changed = vector("identity");
        changed[offset] ^= 1;
        if let Ok(identity) = MaPolicyIdentityInputV1::decode_exact(&changed) {
            assert_ne!(identity.digest().unwrap(), allowlist.identity_digest);
        }
    }
}

#[test]
fn fixture_chain_rejects_wrong_root_purpose_order_time_and_signature() {
    let chain = [vector("signer_der"), vector("ask_der")];
    assert!(fixture_chain(&vector("unrelated_root_der"), &chain, 100, true).is_err());
    assert!(fixture_chain(
        &vector("root_der"),
        &[vector("wrong_purpose_der"), chain[1].clone()],
        100,
        true
    )
    .is_err());
    assert!(fixture_chain(
        &vector("root_der"),
        &[chain[1].clone(), chain[0].clone()],
        100,
        true
    )
    .is_err());
    for time in [9, 201] {
        assert!(fixture_chain(&vector("root_der"), &chain, time, true).is_err());
    }
    for index in 0..chain[0].len() {
        let mut changed = chain.clone();
        changed[0][index] ^= 1;
        assert!(
            fixture_chain(&vector("root_der"), &changed, 100, true).is_err(),
            "certificate byte {index}"
        );
    }
    assert!(FixtureSigner
        .verify_signer(&chain, MaPolicyTrustV1::Production, 100)
        .is_err());
}

fn fixed_verify(
    evidence: &SnpMaEvidenceV1,
    allowlist: &FixedReleaseAllowlistV1,
    now: u64,
) -> Result<VerifiedMaPolicyCollateral, MaPolicyErrorV1> {
    let clock = TestClock(Cell::new(now));
    let policy = VerifiedLmPolicyV1::verify(
        &TestPolicy,
        &clock,
        b"test-signed-policy",
        &[b"test-policy-chain".to_vec()],
        MaPolicyTrustV1::Fixture,
    )?;
    let selected = array("identity_digest");
    let collateral = SnpCollateralSetV1::decode_exact(&vector("collateral")).unwrap();
    VerifiedMaPolicyCollateral::verify_fixed(
        &MaPolicyVerificationRequestV1 {
            evidence,
            report_collateral: &collateral,
            expected_context: &context(SnpMaRoleV1::Source),
            selected_identity: &selected,
            expected_vmpl: 0,
            report_trust: SnpVerifierTrust::PinnedMilanArkTest,
            authorization_trust: MaPolicyTrustV1::Fixture,
        },
        &policy,
        &FixedReleaseCollateralV1 {
            identity: MaPolicyIdentity {
                allowlist: allowlist.clone(),
            },
            identity_issuer_chain: vec![vector("signer_der"), vector("ask_der")],
        },
        &mut MaPolicyVerificationServicesV1 {
            evidence_verifier: &FixtureEvidence,
            signer_verifier: &FixtureSigner,
            clock: &clock,
            store: &mut TestStore::default(),
        },
    )
}

#[test]
fn signed_fixed_admission_and_all_identity_inputs_validity_status() {
    let original = SnpMaEvidenceV1::decode_exact(&vector("source_ma_evidence")).unwrap();
    let allowlist = FixedReleaseAllowlistV1::decode_exact(&vector("allowlist")).unwrap();
    for now in [20, 100, 179] {
        fixed_verify(&original, &allowlist, now).unwrap();
    }
    for now in [19, 180] {
        assert!(fixed_verify(&original, &allowlist, now).is_err());
    }
    for name in [
        "measurement",
        "guest_svn",
        "family",
        "image",
        "id_key",
        "author_key",
        "host_data",
        "guest_policy",
    ] {
        let mut changed = original.clone();
        changed.ma_report = array(&format!("changed_{name}_report"));
        assert!(verify_report_signature(
            &changed.ma_report,
            &vector("vcek_sec1")
        ));
        assert!(fixed_verify(&changed, &allowlist, 100).is_err(), "{name}");
    }
    let mut policy_changed = original.clone();
    policy_changed.policy_identity.policy_digest[0] ^= 1;
    assert!(fixed_verify(&policy_changed, &allowlist, 100).is_err());
    for offset in 0..320 {
        let mut changed = vector("allowlist");
        changed[offset] ^= 1;
        if let Ok(record) = FixedReleaseAllowlistV1::decode_exact(&changed) {
            assert!(
                fixed_verify(&original, &record, 100).is_err(),
                "allowlist byte {offset}"
            );
        }
    }
}

#[test]
fn independent_contributions_report_data_and_complete_evidence() {
    for (role, name) in [
        (SnpMaRoleV1::Source, "source"),
        (SnpMaRoleV1::Destination, "destination"),
    ] {
        let ctx = context(role);
        let secret = array(&format!("{name}_secret"));
        compare(&format!("{name}_commitment"), &commitment(&ctx, &secret));
        compare(&format!("{name}_context"), &ctx.encode_exact().unwrap());
        compare(
            &format!("{name}_report_data"),
            &ctx.expected_report_data().unwrap(),
        );
        for emulator in [false, true] {
            compare(
                &format!(
                    "{name}_{}_evidence_digest",
                    if emulator { "emulator" } else { "raw" }
                ),
                &complete_ma_digest(name, emulator),
            );
        }
        for index in 0..32 {
            let mut changed = secret;
            changed[index] ^= 1;
            assert_ne!(commitment(&ctx, &changed), ctx.purpose_binding_digest);
        }
        let mut encoded = ctx.encode_exact().unwrap();
        // Zeroed commitment slot is excluded by design; other context fields are bound.
        for index in (0..124).chain(172..220) {
            encoded[index] ^= 1;
            if let Ok(changed) = ReportDataContextV1::decode_exact(&encoded) {
                if changed.evidence_purpose == SnpEvidencePurposeV1::InterNodeKeyContribution {
                    assert_ne!(
                        commitment(&changed, &secret),
                        ctx.purpose_binding_digest,
                        "context byte {index}"
                    );
                }
            }
            encoded[index] ^= 1;
        }
    }
}

#[test]
fn independent_authorization_raw_and_emulator_reference_encodings() {
    let raw = raw_authorization();
    compare("raw_authorization_context", &raw.encode_exact().unwrap());
    compare("raw_authorization_digest", &raw.digest().unwrap());
    compare(
        "emulator_authorization_context",
        &emulator_authorization_bytes(),
    );
    compare(
        "emulator_authorization_digest",
        &sha384(&emulator_authorization_bytes()),
    );
    let report = array("tenant_report");
    compare(
        "tenant_raw_evidence_digest",
        &canonical_tenant_evidence_digest_v1(&report, None),
    );
    compare(
        "tenant_emulator_evidence_digest",
        &canonical_tenant_evidence_digest_v1(
            &report,
            Some((
                &array("tenant_supplement"),
                &array("tenant_supplement_signature"),
            )),
        ),
    );
}

#[test]
fn independent_session_hkdf_prk_msk_direction_keys_and_tags() {
    for ordered in [false, true] {
        let name = if ordered {
            "ordered_emulator"
        } else {
            "fixed_emulator"
        };
        let preimage = session_bytes(ordered);
        compare(&format!("{name}_session_context"), &preimage);
        let digest = sha384(&preimage);
        compare(&format!("{name}_session_digest"), &digest);
        let salt = hash_parts(&[b"SNP-LM-HKDF-SALT-v1", &digest]);
        compare(&format!("{name}_salt"), &salt);
        let ikm = [vector("source_secret"), vector("destination_secret")].concat();
        compare(&format!("{name}_ikm"), &ikm);
        compare(
            &format!("{name}_prk"),
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA384, &salt), &ikm).as_ref(),
        );
        for (key_name, label, length) in [
            ("msk", b"SNP-LM-MSK-v1".as_slice(), 32),
            (
                "destination_key",
                b"SNP-LM-CONFIRM-DST-KEY-v1".as_slice(),
                48,
            ),
            ("source_key", b"SNP-LM-CONFIRM-SRC-KEY-v1".as_slice(), 48),
        ] {
            compare(
                &format!("{name}_{key_name}"),
                &hkdf_output(&salt, &ikm, &[label, &digest].concat(), length),
            );
        }
        for direction in ["destination", "source"] {
            let zero = SnpConfirmationV1::decode_exact(&vector(&format!(
                "{name}_{direction}_confirmation_zero"
            )))
            .unwrap();
            compare(
                &format!("{name}_{direction}_confirmation_zero"),
                &zero.encode_exact().unwrap(),
            );
            let tag = confirmation_tag(&zero, &vector(&format!("{name}_{direction}_key")));
            compare(&format!("{name}_{direction}_tag"), &tag);
            let record = SnpConfirmationV1 { tag, ..zero };
            compare(
                &format!("{name}_{direction}_confirmation"),
                &record.encode_exact().unwrap(),
            );
        }
    }
}

#[test]
fn every_session_byte_and_contribution_order_changes_key_and_confirmation() {
    let session = session_bytes(false);
    let ikm = [vector("source_secret"), vector("destination_secret")].concat();
    let original = vector("fixed_emulator_msk");
    let original_tag = vector("fixed_emulator_destination_tag");
    let confirmation =
        SnpConfirmationV1::decode_exact(&vector("fixed_emulator_destination_confirmation_zero"))
            .unwrap();
    for index in 0..799 {
        let mut changed = session;
        changed[index] ^= 1;
        let digest = sha384(&changed);
        let salt = hash_parts(&[b"SNP-LM-HKDF-SALT-v1", &digest]);
        assert_ne!(
            hkdf_output(
                &salt,
                &ikm,
                &[b"SNP-LM-MSK-v1".as_slice(), &digest].concat(),
                32
            ),
            original,
            "session byte {index}"
        );
        let key = hkdf_output(
            &salt,
            &ikm,
            &[b"SNP-LM-CONFIRM-DST-KEY-v1".as_slice(), &digest].concat(),
            48,
        );
        let mut changed_confirmation = confirmation.clone();
        changed_confirmation.session.session_context_digest = digest;
        assert_ne!(
            confirmation_tag(&changed_confirmation, &key).as_slice(),
            original_tag,
            "session byte {index} confirmation"
        );
    }
    let digest = array::<48>("fixed_emulator_session_digest");
    let salt = vector("fixed_emulator_salt");
    let info = [b"SNP-LM-MSK-v1".as_slice(), &digest].concat();
    assert_ne!(
        hkdf_output(
            &salt,
            &[vector("destination_secret"), vector("source_secret")].concat(),
            &info,
            32
        ),
        original
    );
    assert_ne!(hkdf_output(&salt, &ikm, b"SNP-LM-MSK-v1", 32), original);
    assert_ne!(
        vector("fixed_emulator_source_key"),
        vector("fixed_emulator_destination_key")
    );
}

#[test]
fn real_hmac_sequence_rejects_mutations_wrong_direction_duplicate_and_missing_persistence() {
    let verifier = FixtureConfirmation {
        expected: SnpSessionReferenceV1 {
            request_id: REQUEST,
            session_context_digest: array("fixed_emulator_session_digest"),
        },
        source_key: array("fixed_emulator_source_key"),
        destination_key: array("fixed_emulator_destination_key"),
    };
    let dst = vector("fixed_emulator_destination_confirmation");
    let src = vector("fixed_emulator_source_confirmation");
    for (bytes, direction) in [
        (&dst, SnpConfirmationDirectionV1::DestinationToSource),
        (&src, SnpConfirmationDirectionV1::SourceToDestination),
    ] {
        verifier
            .verify(&SnpConfirmationV1::decode_exact(bytes).unwrap())
            .unwrap();
        for index in 0..128 {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            if let Ok(record) = SnpConfirmationV1::decode_exact(&changed) {
                assert!(
                    verifier.verify(&record).is_err(),
                    "confirmation byte {index}"
                );
            }
        }
        let mut sequence = SnpConfirmationSequenceV1::new(verifier.expected.clone());
        if direction == SnpConfirmationDirectionV1::SourceToDestination {
            assert!(sequence
                .accept_confirmation(direction, bytes, &verifier)
                .is_err());
        }
    }
    let mut sequence = SnpConfirmationSequenceV1::new(verifier.expected.clone());
    sequence
        .accept_confirmation(
            SnpConfirmationDirectionV1::DestinationToSource,
            &dst,
            &verifier,
        )
        .unwrap();
    sequence
        .accept_confirmation(
            SnpConfirmationDirectionV1::SourceToDestination,
            &src,
            &verifier,
        )
        .unwrap();
    assert_eq!(
        sequence.state(),
        SnpConfirmationStateV1::AwaitingPersistedState
    );
    assert!(sequence
        .verify_persisted_state(&UnavailableSnpPersistedInstallationVerifierV1)
        .is_err());
    assert_eq!(sequence.state(), SnpConfirmationStateV1::Aborted);
    let mut duplicate = SnpConfirmationSequenceV1::new(verifier.expected.clone());
    duplicate
        .accept_confirmation(
            SnpConfirmationDirectionV1::DestinationToSource,
            &dst,
            &verifier,
        )
        .unwrap();
    assert!(duplicate
        .accept_confirmation(
            SnpConfirmationDirectionV1::DestinationToSource,
            &dst,
            &verifier
        )
        .is_err());
    assert_eq!(duplicate.state(), SnpConfirmationStateV1::Aborted);
    let wrong_key = FixtureConfirmation {
        source_key: verifier.destination_key,
        destination_key: verifier.source_key,
        expected: verifier.expected.clone(),
    };
    assert!(wrong_key
        .verify(&SnpConfirmationV1::decode_exact(&dst).unwrap())
        .is_err());
    assert!(UnavailableSnpConfirmationVerifierV1
        .verify(&SnpConfirmationV1::decode_exact(&dst).unwrap(),)
        .is_err());
    assert!(UnavailableContributionCommitmentVerifierV1
        .verify(&context(SnpMaRoleV1::Source), &array("source_secret"),)
        .is_err());
    assert_eq!(
        ContributionCommitmentErrorV1::ConstructionUnavailable,
        UnavailableContributionCommitmentVerifierV1
            .verify(&context(SnpMaRoleV1::Source), &array("source_secret"),)
            .unwrap_err()
    );
}

#[test]
fn supplement_signatures_full_report_binding_and_all_bytes_are_checked() {
    for name in ["source", "destination", "tenant"] {
        let base = array::<1184>(&format!("{name}_report"));
        let supplement = vector(&format!("{name}_supplement"));
        let sig = vector(&format!("{name}_supplement_signature"));
        let key = vector("vcek_sec1");
        assert!(verify_report_signature(&base, &key));
        verify_supplement(&base, &supplement, &sig, &key).unwrap();
        for index in 0..220 {
            let mut changed = supplement.clone();
            changed[index] ^= 1;
            assert!(verify_supplement(&base, &changed, &sig, &key).is_err());
        }
        for index in 0..1184 {
            let mut changed = base;
            changed[index] ^= 1;
            assert!(verify_supplement(&changed, &supplement, &sig, &key).is_err());
        }
        for index in 0..96 {
            let mut changed = sig.clone();
            changed[index] ^= 1;
            assert!(verify_supplement(&base, &supplement, &changed, &key).is_err());
        }
        assert!(verify_supplement(&base, &supplement, &sig, &vector("signer_sec1")).is_err());
    }
}

#[test]
fn independent_ordered_signatures_keys_and_initial_history_binding() {
    let snapshot =
        ordered::MaReleaseEndorsementV1::decode_exact(&vector("ordered_snapshot")).unwrap();
    let initial =
        ordered::InitialMaAuthorizationV1::decode_exact(&vector("initial_record")).unwrap();
    compare("ordered_snapshot", &snapshot.encode_exact().unwrap());
    compare("initial_record", &initial.encode_exact().unwrap());
    compare(
        "ordered_key_id",
        &ordered::collateral_key_id_v1(&array("release_sec1")),
    );
    compare(
        "initial_key_id",
        &ordered::collateral_key_id_v1(&array("initial_sec1")),
    );
    for (key, message, sig) in [
        (
            vector("release_sec1"),
            snapshot.signature_message().unwrap(),
            snapshot.signature,
        ),
        (
            vector("initial_sec1"),
            initial.signature_message().unwrap(),
            initial.signature,
        ),
    ] {
        signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &key)
            .verify(&message, &sig)
            .unwrap();
        for index in 0..message.len() {
            let mut changed = message.clone();
            changed[index] ^= 1;
            assert!(
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &key)
                    .verify(&changed, &sig)
                    .is_err()
            );
        }
    }
    history()
        .validate_authorization_initial_ma(&initial.initial_ma_report_id)
        .unwrap();
    for index in 0..32 {
        let mut changed = initial.initial_ma_report_id;
        changed[index] ^= 1;
        assert!(history()
            .validate_authorization_initial_ma(&changed)
            .is_err());
    }
}

#[test]
fn valid_signed_supplements_still_reject_inconsistent_etcb_and_history() {
    let base = array("tenant_report");
    let key = vector("vcek_sec1");
    verify_supplement(
        &base,
        &vector("tenant_initialized_supplement"),
        &vector("tenant_initialized_supplement_signature"),
        &key,
    )
    .unwrap();
    for name in [
        "current_etcb",
        "launch_etcb",
        "committed_etcb",
        "uninitialized_history",
        "invalid_history_flag",
    ] {
        let supplement = vector(&format!("invalid_{name}_supplement"));
        let signature = vector(&format!("invalid_{name}_signature"));
        let message = [b"SNP-EMU-SUPPLEMENT-v1".as_slice(), &supplement].concat();
        signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &key)
            .verify(&message, &signature)
            .unwrap();
        assert_eq!(
            verify_supplement(&base, &supplement, &signature, &key),
            Err("supplement binding"),
            "{name}"
        );
    }
}

fn recipe_provenance(
    trust: u16,
    interpretation: u16,
    conflicting_layout: bool,
) -> Result<(), &'static str> {
    match (trust, interpretation) {
        (1, 1) => Ok(()),
        (2, 2) if conflicting_layout => Err("ConflictingAbiLayout"),
        (2, 2) => Err("UnsupportedVersion6Layout"),
        _ => Err("ProfileTrustMismatch"),
    }
}

#[test]
fn fixture_provenance_and_unqualified_hardware_reference_fail_closed() {
    // Contract oracle only: the common production adapter is not implemented here.
    assert_eq!(recipe_provenance(1, 1, false), Ok(()));
    assert_eq!(recipe_provenance(1, 2, false), Err("ProfileTrustMismatch"));
    assert_eq!(recipe_provenance(2, 1, false), Err("ProfileTrustMismatch"));
    assert_eq!(
        recipe_provenance(2, 2, false),
        Err("UnsupportedVersion6Layout")
    );
    assert_eq!(recipe_provenance(2, 2, true), Err("ConflictingAbiLayout"));
    for unknown in [0, 3, u16::MAX] {
        assert!(recipe_provenance(unknown, 1, false).is_err());
        assert!(recipe_provenance(1, unknown, false).is_err());
    }
}

#[test]
fn independent_complete_purpose_role_algorithm_registry() {
    let mut legal = Vec::new();
    for purpose in [
        SnpEvidencePurposeV1::InterNodeKeyContribution,
        SnpEvidencePurposeV1::InterNodeTenantAuthorization,
        SnpEvidencePurposeV1::InterNodePostInstallConfirmation,
        SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
        SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization,
    ] {
        for role in [
            SnpMaRoleV1::Source,
            SnpMaRoleV1::Destination,
            SnpMaRoleV1::Outgoing,
            SnpMaRoleV1::Incoming,
        ] {
            for algorithm in [
                SnpMigrationAlgorithmV1::None,
                SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
                SnpMigrationAlgorithmV1::LocalHandoffSecretV1,
            ] {
                let mut ctx = context(SnpMaRoleV1::Source);
                ctx.evidence_purpose = purpose;
                ctx.role = role;
                ctx.algorithm = algorithm;
                if purpose as u8 >= 4 {
                    ctx.tenant_binding_id = [0; 32];
                }
                if purpose == SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization {
                    ctx.th1 = [0; 48];
                }
                if ctx.validate().is_ok() {
                    legal.extend_from_slice(&[purpose as u8, role as u8, algorithm as u8]);
                }
            }
        }
    }
    assert_eq!(legal.len(), 8 * 3);
    compare("legal_purpose_role_algorithm", &legal);
}

#[test]
fn independent_first_next_history_and_purpose_preimages_report_data() {
    let first = history().encode_exact().unwrap();
    compare("history_first", &first);
    let input = TenantHistoryInputV1 {
        report_version: 6,
        profile: SnpTcbProfileV1::Venice,
        launch_tcb: [8, 9, 10, 0, 0, 0, 0, 0],
        launch_etcb: std::array::from_fn(|i| {
            if i >= 14 {
                0
            } else if i % 2 == 0 {
                10 + i as u8
            } else {
                40 + i as u8
            }
        }),
        launch_mitigation_vector: 0xCCCC_F0F0_FFFF_0F0F,
        report_id_ma: [0x11; 32],
        migration_data_valid: true,
        migration_data: Some(&first),
    };
    let next = MigrationDataV1::from_tenant(&input, &[0x11; 32]).unwrap();
    compare("history_next", &next.encode_exact().unwrap());
    assert!(MigrationDataV1::from_tenant(
        &TenantHistoryInputV1 {
            migration_data: None,
            ..input
        },
        &[0x11; 32]
    )
    .is_err());
    history()
        .validate_installation_pair(&first, &first)
        .unwrap();
    for index in 0..64 {
        let mut changed = first;
        changed[index] ^= 1;
        assert!(history()
            .validate_installation_pair(&first, &changed)
            .is_err());
    }
    let post = PostInstallBindingV1::after_successful_persistence(
        REQUEST, [0x77; 32], [0x22; 32], &first, 0, true,
    )
    .unwrap();
    compare("post_install_preimage", &post.encode_exact().unwrap());
    let post_ctx = ReportDataContextV1::decode_exact(&vector("post_install_context")).unwrap();
    post.verify_context(&post_ctx).unwrap();
    compare(
        "post_install_report_data",
        &post_ctx.expected_report_data().unwrap(),
    );
    let ids = [VerifiedTenantReportIdV1::from_verified_report_id(
        [0x77; 32],
    )];
    let tenants = CanonicalTenantSetV1::new(1, &ids).unwrap();
    let results = [FirmwareRebindResultV1::decode_exact(&vector("firmware_result")).unwrap()];
    let result_set =
        CanonicalFirmwareResultSetV1::new(1, &results, &tenants, [0x11; 32], [0x22; 32]).unwrap();
    for (purpose, prefix) in [
        (
            SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
            "planned",
        ),
        (
            SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization,
            "recovery",
        ),
    ] {
        for stage in ["prepare", "result"] {
            let name = format!("{prefix}_{stage}");
            let binding =
                LocalHandoffBindingV1::decode_exact(purpose, &vector(&format!("{name}_preimage")))
                    .unwrap();
            compare(
                &format!("{name}_preimage"),
                &binding.encode_exact().unwrap(),
            );
            let result = if binding.stage == SnpOperationStageV1::FirmwareResultConfirmation {
                Some(&result_set)
            } else {
                None
            };
            let ctx =
                ReportDataContextV1::decode_exact(&vector(&format!("{name}_context"))).unwrap();
            binding.verify_context(&ctx, &tenants, result).unwrap();
            if purpose == SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization {
                let outgoing =
                    ReportDataContextV1::decode_exact(&vector(&format!("{name}_outgoing_context")))
                        .unwrap();
                binding.verify_context(&outgoing, &tenants, result).unwrap();
                compare(
                    &format!("{name}_outgoing_report_data"),
                    &outgoing.expected_report_data().unwrap(),
                );
            }
            compare(
                &format!("{name}_report_data"),
                &ctx.expected_report_data().unwrap(),
            );
        }
    }
}
