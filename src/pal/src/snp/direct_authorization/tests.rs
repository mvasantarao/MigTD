use super::*;
use crate::{
    snp::{
        direct_exchange::{FirmwareCompletionRecordV2, InstallSessionControlV2, KeyAcceptanceV2},
        direct_key::{MigrationKeyV2, MigrationSessionContextV2, SessionClaimsV2},
        tenant_authorization::tests::{
            collateral, contribution_context, ma_report, tenant, tenant_bytes, TestVerifier,
        },
    },
    types::{MaEvidenceBinding, MigrationRole},
};

fn vector(name: &str) -> Vec<u8> {
    let hex = include_str!("../test_data/direct_random_v2.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .expect("V2 vector");
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn verified_context(verifier: &TestVerifier) -> TenantAuthorizationContextV2 {
    let tenant = tenant(verifier, MigrationRole::Source, &tenant_bytes());
    let proof = |role| {
        let context = session_context_v2(contribution_context(role), &tenant).unwrap();
        VerifiedSessionMaV2::verify(
            &context,
            &tenant,
            verifier,
            &ma_report(&context),
            &collateral(),
            0,
        )
        .unwrap()
    };
    let source = proof(SnpMaRoleV1::Source);
    let destination = proof(SnpMaRoleV1::Destination);
    TenantAuthorizationContextV2::new(tenant, source, destination).unwrap()
}
fn role_proof(
    context: &TenantAuthorizationContextV2,
    verifier: &TestVerifier,
    role: SnpMaRoleV1,
) -> VerifiedTenantAuthorizationRoleV2 {
    let expected = context.report_data_context(role).unwrap();
    context
        .verify_role_proof(role, verifier, &ma_report(&expected), &collateral(), 0)
        .unwrap()
}
fn authorize(
    context: &TenantAuthorizationContextV2,
    verifier: &TestVerifier,
) -> VerifiedTenantAuthorizationV1 {
    context
        .accept_both_roles(
            role_proof(context, verifier, SnpMaRoleV1::Source),
            role_proof(context, verifier, SnpMaRoleV1::Destination),
        )
        .unwrap()
}
fn claims() -> SessionClaimsV2 {
    let mut migration_data = [0; 64];
    migration_data[0] = 1;
    migration_data[1] = 3;
    SessionClaimsV2 {
        source_complete_evidence_digest: [10; 48],
        destination_complete_evidence_digest: [11; 48],
        tenant_collateral_digest: [12; 48],
        migration_data,
        trust: SnpVerifierTrust::PinnedMilanArkTest,
        interpretation: 1,
        approval_profile: 1,
        source_approval_digest: [13; 48],
        destination_approval_digest: [14; 48],
        initial_authorization_digest: [0; 48],
    }
}

#[test]
fn v2_context_authorization_session_and_every_record_match_independent_python() {
    let verifier = TestVerifier::default();
    let context = verified_context(&verifier);
    let source = context.session_context(SnpMaRoleV1::Source).unwrap();
    assert_eq!(
        source.encode_exact().unwrap().as_slice(),
        vector("source_context")
    );
    assert_eq!(
        source.expected_report_data().unwrap().as_slice(),
        vector("source_report_data")
    );
    assert_eq!(
        source.purpose_binding_digest.as_slice(),
        vector("session_binding")
    );
    assert_eq!(
        context.encode_exact().unwrap().as_slice(),
        vector("authorization")
    );
    assert_eq!(
        context.digest().unwrap().as_slice(),
        vector("authorization_digest")
    );
    let authorization = authorize(&context, &verifier);
    let session = MigrationSessionContextV2::new(&context, &authorization, &claims()).unwrap();
    assert_eq!(
        MigrationSessionContextV2::canonical_preimage(&context, &claims())
            .unwrap()
            .as_slice(),
        vector("session_preimage")
    );
    assert_eq!(
        session.reference().session_context_digest.as_slice(),
        vector("session_digest")
    );
    let key = MigrationKeyV2::generate(&session, &mut crate::snp::direct_exchange::tests::Random)
        .unwrap();
    assert_eq!(
        key.encode_delivery().unwrap().as_slice(),
        vector("key_delivery")
    );
    let acceptance = KeyAcceptanceV2::decode_exact(&vector("acceptance")).unwrap();
    assert_eq!(&acceptance.session, session.reference());
    for (name, source) in [
        ("destination_completion", false),
        ("source_completion", true),
    ] {
        let record = crate::snp::direct_exchange::tests::completion(&session, source);
        assert_eq!(record.encode_exact().unwrap().as_slice(), vector(name));
        assert_eq!(
            FirmwareCompletionRecordV2::decode_exact(&vector(name)).unwrap(),
            record
        );
    }
    for name in ["poll", "acknowledgement"] {
        let record = InstallSessionControlV2::decode_exact(&vector(name)).unwrap();
        assert_eq!(record.encode_exact().unwrap().as_slice(), vector(name));
    }
}

#[test]
fn legacy_purpose_and_arbitrary_binding_never_mint_session_proof() {
    let verifier = TestVerifier::default();
    let tenant = tenant(&verifier, MigrationRole::Source, &tenant_bytes());
    let old = contribution_context(SnpMaRoleV1::Source);
    assert!(VerifiedSessionMaV2::verify(
        &old,
        &tenant,
        &verifier,
        &ma_report(&old),
        &collateral(),
        0
    )
    .is_err());
    let mut context = session_context_v2(old, &tenant).unwrap();
    context.purpose_binding_digest[0] ^= 1;
    assert!(VerifiedSessionMaV2::verify(
        &context,
        &tenant,
        &verifier,
        &ma_report(&context),
        &collateral(),
        0
    )
    .is_err());
}

#[test]
fn failed_wrong_trust_and_wrong_binding_verifiers_never_mint_session_proof() {
    for failure in 0..3 {
        let verifier = TestVerifier::default();
        let tenant = tenant(&verifier, MigrationRole::Source, &tenant_bytes());
        let context =
            session_context_v2(contribution_context(SnpMaRoleV1::Source), &tenant).unwrap();
        match failure {
            0 => verifier.fail.set(true),
            1 => verifier.trust.set(Some(SnpVerifierTrust::AzureProduction)),
            _ => verifier
                .binding
                .set(Some(MaEvidenceBinding::CapturedFixture)),
        }
        assert!(VerifiedSessionMaV2::verify(
            &context,
            &tenant,
            &verifier,
            &ma_report(&context),
            &collateral(),
            0
        )
        .is_err());
    }
}

#[test]
fn both_distinct_current_roles_are_required_and_wrong_ma_identity_is_rejected() {
    let verifier = TestVerifier::default();
    let context = verified_context(&verifier);
    assert!(context
        .accept_both_roles(
            role_proof(&context, &verifier, SnpMaRoleV1::Source),
            role_proof(&context, &verifier, SnpMaRoleV1::Source)
        )
        .is_err());
    let expected = context.report_data_context(SnpMaRoleV1::Source).unwrap();
    let mut report = *ma_report(&expected).report();
    report[0x140] ^= 1;
    assert!(matches!(
        context.verify_role_proof(
            SnpMaRoleV1::Source,
            &verifier,
            &MaEvidence::new(report, MaEvidenceBinding::RequestedReportData),
            &collateral(),
            0
        ),
        Err(DirectAuthorizationErrorV2::MaIdentityMismatch)
    ));
}

#[test]
fn purpose_seven_proofs_cannot_be_substituted_across_authorizations() {
    let verifier = TestVerifier::default();
    let context = verified_context(&verifier);
    let mut other = verified_context(&verifier);
    other.destination.context.ma_policy_identity_digest[0] ^= 1;
    assert!(context
        .accept_both_roles(
            role_proof(&other, &verifier, SnpMaRoleV1::Source),
            role_proof(&other, &verifier, SnpMaRoleV1::Destination)
        )
        .is_err());
}

#[test]
fn source_association_and_actual_shared_th1_remain_required() {
    let verifier = TestVerifier::default();
    for change in 0..2 {
        let mut context = verified_context(&verifier);
        if change == 0 {
            context.source.report_id[0] ^= 1;
        } else {
            context.destination.context.th1[0] ^= 1;
        }
        assert!(TenantAuthorizationContextV2::new(
            context.tenant,
            context.source,
            context.destination
        )
        .is_err());
    }
}

#[test]
fn nonsecret_session_keeps_all_evidence_history_and_approval_inputs_without_a_kdf() {
    let verifier = TestVerifier::default();
    let context = verified_context(&verifier);
    let baseline = MigrationSessionContextV2::canonical_preimage(&context, &claims()).unwrap();
    for change in 0..10 {
        let mut claims = claims();
        match change {
            0 => claims.source_complete_evidence_digest[0] ^= 1,
            1 => claims.destination_complete_evidence_digest[0] ^= 1,
            2 => claims.tenant_collateral_digest[0] ^= 1,
            3 => claims.migration_data[2] ^= 1,
            4 => claims.trust = SnpVerifierTrust::AzureProduction,
            5 => claims.interpretation = 2,
            6 => {
                claims.approval_profile = 2;
                claims.initial_authorization_digest = [19; 48];
            }
            7 => claims.source_approval_digest[0] ^= 1,
            8 => claims.destination_approval_digest[0] ^= 1,
            _ => {
                claims.approval_profile = 2;
                claims.initial_authorization_digest = [20; 48];
            }
        }
        let changed = MigrationSessionContextV2::canonical_preimage(&context, &claims).unwrap();
        assert_ne!(sha384(&changed), sha384(&baseline), "{change}");
    }
}

#[test]
fn old_replay_bindings_conflict_and_invalid_profiles_fail_explicitly() {
    use crate::tenant_replay::{
        DurableTenantReplayStoreV1, TenantReplayErrorV1, TenantReplayJournalV1,
        TenantReplaySnapshotV1,
    };
    struct Store(TenantReplaySnapshotV1);
    impl DurableTenantReplayStoreV1 for Store {
        fn load_authenticated(
            &mut self,
            _: usize,
        ) -> Result<TenantReplaySnapshotV1, TenantReplayErrorV1> {
            Ok(self.0.clone())
        }
        fn commit(
            &mut self,
            expected: u64,
            replacement: &TenantReplaySnapshotV1,
        ) -> Result<(), TenantReplayErrorV1> {
            if self.0.revision != expected {
                return Err(TenantReplayErrorV1::ConcurrentUpdate);
            }
            self.0 = replacement.clone();
            Ok(())
        }
    }
    let verifier = TestVerifier::default();
    let context = verified_context(&verifier);
    let old = VerifiedTenantReplayBindingV1::from_verified_context(
        &context.tenant,
        [1; 48],
        context.source.report_id,
        context.destination.report_id,
    );
    let mut journal = TenantReplayJournalV1::new(
        Store(TenantReplaySnapshotV1 {
            revision: 0,
            records: vec![],
        }),
        4,
    )
    .unwrap();
    journal.reserve(&old).unwrap();
    assert_eq!(
        journal.reserve(&context.replay_binding().unwrap()),
        Err(TenantReplayErrorV1::ConflictingReuse)
    );
    let authorization = authorize(&context, &verifier);
    for invalid in 0..4 {
        let mut bad = claims();
        match invalid {
            0 => bad.interpretation = 0,
            1 => bad.approval_profile = 0,
            2 => bad.initial_authorization_digest = [1; 48],
            _ => {
                bad.approval_profile = 2;
                bad.initial_authorization_digest = [0; 48];
            }
        }
        assert!(MigrationSessionContextV2::new(&context, &authorization, &bad).is_err());
    }
    assert_ne!(old, context.replay_binding().unwrap());
}
