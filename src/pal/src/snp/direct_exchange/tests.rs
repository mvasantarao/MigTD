use super::*;
use crate::snp::{
    direct_key::{DirectKeyErrorV2, MigrationRandomSourceV2},
    report_data_context::{ReportDataContextV1, SnpEvidencePurposeV1, SnpMigrationAlgorithmV1},
};

pub(crate) fn context(role: MigrationRole, request: u64) -> MigrationSessionContextV2 {
    let source = ReportDataContextV1 {
        evidence_purpose: SnpEvidencePurposeV1::InterNodeSessionV2,
        role: SnpMaRoleV1::Source,
        request_id: request,
        negotiated_migration_version: 1,
        algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
        tenant_binding_id: [4; 32],
        th1: [0x88; 48],
        purpose_binding_digest: [5; 48],
        ma_policy_identity_digest: [6; 48],
    };
    let destination = ReportDataContextV1 {
        role: SnpMaRoleV1::Destination,
        ..source.clone()
    };
    let mut history = [0; 64];
    history[0] = 1;
    history[1] = 3;
    MigrationSessionContextV2::for_test(
        SnpSessionReferenceV2 {
            request_id: request,
            session_context_digest: [33; 48],
        },
        source,
        destination,
        history,
        role,
    )
}

pub(crate) struct Random;
impl MigrationRandomSourceV2 for Random {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), DirectKeyErrorV2> {
        output.fill(0x42);
        Ok(())
    }
}

pub(crate) fn completion(
    context: &MigrationSessionContextV2,
    source: bool,
) -> FirmwareCompletionRecordV2 {
    FirmwareCompletionRecordV2 {
        session: context.reference().clone(),
        role: if source {
            SnpMaRoleV1::Source
        } else {
            SnpMaRoleV1::Destination
        },
        outcome: FirmwareCompletionOutcomeV2::Completed,
        effect: FirmwareCompletionEffectV2::Applied,
        raw_firmware_status: Some(0),
    }
}

// Schedule oracle only: production receipts come exclusively from peer I/O.
pub(crate) fn payload(context: &MigrationSessionContextV2, opcode: u8) -> Zeroizing<Vec<u8>> {
    let bytes = match opcode {
        0x30 => {
            let source = MigrationSessionContextV2::for_test(
                context.reference().clone(),
                context.source_context().clone(),
                context.destination_context().clone(),
                *context.migration_data(),
                MigrationRole::Source,
            );
            MigrationKeyV2::generate(&source, &mut Random)
                .unwrap()
                .encode_delivery()
                .unwrap()
                .to_vec()
        }
        0x31 => KeyAcceptanceV2 {
            session: context.reference().clone(),
        }
        .encode_exact()
        .unwrap()
        .to_vec(),
        0x32 | 0x35 => InstallSessionControlV2 {
            session: context.reference().clone(),
            kind: if opcode == 0x32 {
                InstallSessionControlKindV2::PollDestinationCompletion
            } else {
                InstallSessionControlKindV2::AcknowledgeSourceCompletion
            },
        }
        .encode_exact()
        .unwrap()
        .to_vec(),
        0x33 | 0x34 => completion(context, opcode == 0x34)
            .encode_exact()
            .unwrap()
            .to_vec(),
        _ => panic!("not a V2 installation opcode"),
    };
    Zeroizing::new(bytes)
}
pub(crate) fn token(context: &MigrationSessionContextV2, opcode: u8) -> ProtectedInstallRecordV2 {
    ProtectedInstallRecordV2::from_peer(opcode, &payload(context, opcode), context).unwrap()
}

#[test]
fn direct_random32_is_exact_redacted_and_source_only() {
    let context = context(MigrationRole::Source, 17);
    let key = MigrationKeyV2::generate(&context, &mut Random).unwrap();
    assert_eq!(key.for_installation(&context).unwrap(), &[0x42; 32]);
    assert_eq!(format!("{key:?}"), "MigrationKeyV2(<redacted>)");
    assert_eq!(
        key.encode_delivery().unwrap(),
        key.encode_delivery().unwrap()
    );
    let wrong = super::tests::context(MigrationRole::Source, 18);
    assert!(matches!(
        key.for_installation(&wrong),
        Err(DirectKeyErrorV2::ContextMismatch)
    ));
    let destination = super::tests::context(MigrationRole::Destination, 17);
    assert!(matches!(
        MigrationKeyV2::generate(&destination, &mut Random),
        Err(DirectKeyErrorV2::WrongRole)
    ));
    assert!(matches!(
        MigrationKeyV2::generate(
            &context,
            &mut crate::snp::direct_key::UnavailableMigrationRandomSourceV2
        ),
        Err(DirectKeyErrorV2::RandomnessUnavailable)
    ));
}

#[test]
fn partial_rng_failure_cannot_return_a_key_owner_or_success_record() {
    struct PartialFailure;
    impl MigrationRandomSourceV2 for PartialFailure {
        fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), DirectKeyErrorV2> {
            output[..16].fill(0x77);
            Err(DirectKeyErrorV2::RandomnessUnavailable)
        }
    }
    let context = context(MigrationRole::Source, 17);
    assert!(matches!(
        MigrationKeyV2::generate(&context, &mut PartialFailure),
        Err(DirectKeyErrorV2::RandomnessUnavailable)
    ));
}

#[test]
fn key_delivery_wipes_input_on_every_success_and_failure() {
    let context = context(MigrationRole::Source, 17);
    let bytes = payload(&context, 0x30);
    for end in 0..bytes.len() {
        let mut bad = bytes[..end].to_vec();
        assert!(MigrationKeyV2::decode_delivery(&mut bad).is_err());
        assert!(bad.iter().all(|b| *b == 0));
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(MigrationKeyV2::decode_delivery(&mut extra).is_err());
    assert!(extra.iter().all(|b| *b == 0));
    let mut good = bytes.to_vec();
    let decoded = MigrationKeyV2::decode_delivery(&mut good).unwrap();
    assert!(good.iter().all(|b| *b == 0));
    assert_eq!(decoded.for_installation(&context).unwrap(), &[0x42; 32]);
}

#[test]
fn protected_acceptance_is_not_firmware_success_and_source_waits_for_destination() {
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let context = context(role, 17);
        let mut sequence = InstallExchangeSequenceV2::new(&context);
        assert!(sequence.accepted_session().is_err());
        let key = sequence.observe(token(&context, 0x30)).unwrap().unwrap();
        assert_eq!(key.for_installation(&context).unwrap(), &[0x42; 32]);
        assert!(sequence.accepted_session().is_err());
        sequence.observe(token(&context, 0x31)).unwrap();
        let receipt = sequence.accepted_session().unwrap();
        assert_eq!(
            receipt.permits_installation(MigrationRole::Destination),
            role == MigrationRole::Destination
        );
        assert!(!receipt.permits_installation(MigrationRole::Source));
        sequence.observe(token(&context, 0x32)).unwrap();
        sequence.observe(token(&context, 0x33)).unwrap();
        assert_eq!(
            sequence
                .accepted_session()
                .unwrap()
                .permits_installation(MigrationRole::Source),
            role == MigrationRole::Source
        );
        sequence.observe(token(&context, 0x34)).unwrap();
        sequence.observe(token(&context, 0x35)).unwrap();
        assert_eq!(sequence.finish().unwrap().session(), context.reference());
    }
}

#[test]
fn unsolicited_reordered_duplicate_and_cross_session_records_poison_sequence() {
    let context = context(MigrationRole::Source, 17);
    for opcode in 0x31..=0x35 {
        let mut sequence = InstallExchangeSequenceV2::new(&context);
        assert!(sequence.observe(token(&context, opcode)).is_err());
        assert!(sequence.observe(token(&context, 0x30)).is_err());
        assert!(sequence.finish().is_err());
    }
    let mut sequence = InstallExchangeSequenceV2::new(&context);
    sequence.observe(token(&context, 0x30)).unwrap();
    assert!(sequence.observe(token(&context, 0x30)).is_err());
    let other = super::tests::context(MigrationRole::Source, 18);
    let mut sequence = InstallExchangeSequenceV2::new(&context);
    assert!(sequence.observe(token(&other, 0x30)).is_err());
    assert!(sequence.accepted_session().is_err());
}

#[test]
fn every_prefix_before_final_ack_is_incomplete() {
    let context = context(MigrationRole::Source, 17);
    for end in 0x30..=0x35 {
        let mut sequence = InstallExchangeSequenceV2::new(&context);
        for opcode in 0x30..end {
            sequence.observe(token(&context, opcode)).unwrap();
        }
        assert!(sequence.finish().is_err());
    }
}

#[test]
fn partial_unknown_and_failed_installations_never_authorize_source_or_success() {
    let context = context(MigrationRole::Source, 17);
    for (outcome, effect, status) in [
        (
            FirmwareCompletionOutcomeV2::Unavailable,
            FirmwareCompletionEffectV2::NotApplied,
            None,
        ),
        (
            FirmwareCompletionOutcomeV2::NotApplied,
            FirmwareCompletionEffectV2::NotApplied,
            Some(7),
        ),
        (
            FirmwareCompletionOutcomeV2::Indeterminate,
            FirmwareCompletionEffectV2::Partial,
            Some(0),
        ),
        (
            FirmwareCompletionOutcomeV2::Indeterminate,
            FirmwareCompletionEffectV2::Unknown,
            None,
        ),
    ] {
        let mut sequence = InstallExchangeSequenceV2::new(&context);
        for opcode in 0x30..=0x32 {
            sequence.observe(token(&context, opcode)).unwrap();
        }
        let mut value = completion(&context, false);
        value.outcome = outcome;
        value.effect = effect;
        value.raw_firmware_status = status;
        let record =
            ProtectedInstallRecordV2::from_peer(0x33, &value.encode_exact().unwrap(), &context)
                .unwrap();
        assert!(matches!(
            sequence.observe(record),
            Err(HostControlErrorV1::PeerInstallationV2 { .. })
        ));
        assert!(sequence.accepted_session().is_err());
        assert!(sequence.finish().is_err());
    }
}

#[test]
fn exact_codecs_reject_truncation_trailing_reserved_wrong_role_and_legacy_versions() {
    let context = context(MigrationRole::Source, 17);
    for opcode in 0x30..=0x35 {
        let bytes = payload(&context, opcode);
        for end in 0..bytes.len() {
            assert!(ProtectedInstallRecordV2::from_peer(opcode, &bytes[..end], &context).is_err());
        }
        let mut bad = bytes.to_vec();
        bad.push(0);
        assert!(ProtectedInstallRecordV2::from_peer(opcode, &bad, &context).is_err());
        for offset in [0, 8, 10, 12, 16, 24] {
            let mut bad = bytes.to_vec();
            bad[offset] ^= 1;
            assert!(
                ProtectedInstallRecordV2::from_peer(opcode, &bad, &context).is_err(),
                "{opcode:x}:{offset}"
            );
        }
    }
    for opcode in [0x31, 0x32, 0x35] {
        for offset in 72..80 {
            let mut bad = payload(&context, opcode);
            bad[offset] ^= 0x80;
            assert!(ProtectedInstallRecordV2::from_peer(opcode, &bad, &context).is_err());
        }
    }
}

#[test]
fn history_context_and_direction_substitutions_are_rejected() {
    let context = context(MigrationRole::Source, 17);
    let mut bytes = payload(&context, 0x30);
    bytes[106] ^= 1;
    assert!(ProtectedInstallRecordV2::from_peer(0x30, &bytes, &context).is_err());
    assert!(ProtectedInstallRecordV2::from_peer(0x34, &payload(&context, 0x33), &context).is_err());
    let mut sequence = InstallExchangeSequenceV2::new(&context);
    let other_role = super::tests::context(MigrationRole::Destination, 17);
    assert!(sequence.observe(token(&other_role, 0x30)).is_err());
}
