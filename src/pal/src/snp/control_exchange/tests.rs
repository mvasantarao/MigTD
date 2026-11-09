use super::*;
use crate::snp::confirmation::{
    SnpConfirmationVerificationErrorV1, UnavailableSnpConfirmationVerifierV1,
};

fn reference() -> SnpSessionReferenceV1 {
    SnpSessionReferenceV1 {
        request_id: 17,
        session_context_digest: [33; 48],
    }
}
fn confirmation(source: bool) -> SnpConfirmationV1 {
    SnpConfirmationV1 {
        session: reference(),
        role: if source {
            SnpMaRoleV1::Source
        } else {
            SnpMaRoleV1::Destination
        },
        direction: if source {
            SnpConfirmationDirectionV1::SourceToDestination
        } else {
            SnpConfirmationDirectionV1::DestinationToSource
        },
        status: SnpConfirmationStatusV1::Confirmed,
        tag: [7; 48],
    }
}
fn control(ack: bool) -> InstallSessionControlV1 {
    InstallSessionControlV1 {
        session: reference(),
        kind: if ack {
            InstallSessionControlKindV1::AcknowledgeSourceCompletion
        } else {
            InstallSessionControlKindV1::PollDestinationConfirmation
        },
    }
}
fn completion(source: bool) -> FirmwareCompletionRecordV1 {
    FirmwareCompletionRecordV1 {
        session: reference(),
        role: if source {
            SnpMaRoleV1::Source
        } else {
            SnpMaRoleV1::Destination
        },
        outcome: FirmwareCompletionOutcomeV1::Completed,
        effect: FirmwareCompletionEffectV1::Applied,
        raw_firmware_status: Some(0),
    }
}

// Schedule oracle only; real cryptography and live session activation are gated.
struct Verifier;
impl SnpConfirmationVerifierV1 for Verifier {
    fn verify(&self, record: &SnpConfirmationV1) -> Result<(), SnpConfirmationVerificationErrorV1> {
        if record.tag == [7; 48] {
            Ok(())
        } else {
            Err(SnpConfirmationVerificationErrorV1::TagMismatch)
        }
    }
}

#[test]
fn completion_and_poll_match_independent_python_struct_vectors() {
    let bytes = completion(false).encode_exact().unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "534e502d4c4d2d460100080058000000110000000000000021212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212101010101000000000000000000000000");
    let bytes = control(false).encode_exact().unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "534e502d4c4d2d51010009005000000011000000000000002121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121210100000000000000");
}

#[test]
fn current_scope_schedule_requires_three_correlated_exchanges_and_both_installations() {
    let mut sequence = InstallExchangeSequenceV1::new(reference());
    assert!(sequence.confirmed_session().is_err());
    sequence
        .begin_request(&InstallExchangeRequestV1::Poll(control(false)), &Verifier)
        .unwrap();
    sequence
        .complete_response(
            &InstallExchangeResponseV1::DestinationConfirmation(confirmation(false)),
            &Verifier,
        )
        .unwrap();
    assert!(sequence.confirmed_session().is_err());
    sequence
        .begin_request(
            &InstallExchangeRequestV1::SourceConfirmation(confirmation(true)),
            &Verifier,
        )
        .unwrap();
    assert_eq!(
        sequence.confirmed_session().unwrap().session(),
        &reference()
    );
    sequence
        .complete_response(
            &InstallExchangeResponseV1::DestinationCompletion(completion(false)),
            &Verifier,
        )
        .unwrap();
    sequence
        .begin_request(
            &InstallExchangeRequestV1::SourceCompletion(completion(true)),
            &Verifier,
        )
        .unwrap();
    sequence
        .complete_response(
            &InstallExchangeResponseV1::Acknowledgement(control(true)),
            &Verifier,
        )
        .unwrap();
    assert_eq!(sequence.finish().unwrap().session(), &reference());
}

#[test]
fn unsolicited_wrong_session_and_duplicate_responses_abort_without_success() {
    let mut sequence = InstallExchangeSequenceV1::new(reference());
    assert!(sequence
        .complete_response(
            &InstallExchangeResponseV1::DestinationConfirmation(confirmation(false)),
            &Verifier
        )
        .is_err());
    assert!(sequence.finish().is_err());
    let mut sequence = InstallExchangeSequenceV1::new(reference());
    sequence
        .begin_request(&InstallExchangeRequestV1::Poll(control(false)), &Verifier)
        .unwrap();
    let mut wrong = confirmation(false);
    wrong.session.request_id += 1;
    assert!(sequence
        .complete_response(
            &InstallExchangeResponseV1::DestinationConfirmation(wrong),
            &Verifier
        )
        .is_err());
    assert!(sequence.confirmed_session().is_err());
    let mut sequence = InstallExchangeSequenceV1::new(reference());
    sequence
        .begin_request(&InstallExchangeRequestV1::Poll(control(false)), &Verifier)
        .unwrap();
    let response = InstallExchangeResponseV1::DestinationConfirmation(confirmation(false));
    sequence.complete_response(&response, &Verifier).unwrap();
    assert!(sequence.complete_response(&response, &Verifier).is_err());
    assert!(sequence.finish().is_err());
}

#[test]
fn unavailable_or_invalid_crypto_never_creates_confirmation_receipt() {
    for verifier in [
        &UnavailableSnpConfirmationVerifierV1 as &dyn SnpConfirmationVerifierV1,
        &Verifier,
    ] {
        let mut sequence = InstallExchangeSequenceV1::new(reference());
        sequence
            .begin_request(&InstallExchangeRequestV1::Poll(control(false)), verifier)
            .unwrap();
        let mut record = confirmation(false);
        record.tag = [0; 48];
        assert!(matches!(
            sequence.complete_response(
                &InstallExchangeResponseV1::DestinationConfirmation(record),
                verifier
            ),
            Err(HostControlErrorV1::Confirmation(_))
        ));
        assert!(sequence.confirmed_session().is_err());
    }
}

#[test]
fn completion_codec_preserves_absent_zero_nonzero_and_uncertain_effects() {
    let cases = [
        (
            FirmwareCompletionOutcomeV1::Completed,
            FirmwareCompletionEffectV1::Applied,
            Some(0),
        ),
        (
            FirmwareCompletionOutcomeV1::Unavailable,
            FirmwareCompletionEffectV1::NotApplied,
            None,
        ),
        (
            FirmwareCompletionOutcomeV1::NotApplied,
            FirmwareCompletionEffectV1::NotApplied,
            Some(7),
        ),
        (
            FirmwareCompletionOutcomeV1::Indeterminate,
            FirmwareCompletionEffectV1::Partial,
            Some(0),
        ),
        (
            FirmwareCompletionOutcomeV1::Indeterminate,
            FirmwareCompletionEffectV1::Unknown,
            None,
        ),
        (
            FirmwareCompletionOutcomeV1::Indeterminate,
            FirmwareCompletionEffectV1::Unknown,
            Some(7),
        ),
    ];
    for role in [SnpMaRoleV1::Source, SnpMaRoleV1::Destination] {
        for (outcome, effect, raw_firmware_status) in cases {
            let record = FirmwareCompletionRecordV1 {
                role,
                outcome,
                effect,
                raw_firmware_status,
                session: reference(),
            };
            let bytes = record.encode_exact().unwrap();
            assert_eq!(
                FirmwareCompletionRecordV1::decode_exact(&bytes).unwrap(),
                record
            );
            for end in 0..bytes.len() {
                assert!(FirmwareCompletionRecordV1::decode_exact(&bytes[..end]).is_err());
            }
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(FirmwareCompletionRecordV1::decode_exact(&trailing).is_err());
        }
    }
}

#[test]
fn completion_and_poll_codecs_reject_forged_success_reserved_and_wrong_record() {
    let record = completion(false);
    for index in [0, 8, 10, 72, 73, 74, 75, 80] {
        let mut bytes = record.encode_exact().unwrap();
        bytes[index] = 255;
        assert!(
            FirmwareCompletionRecordV1::decode_exact(&bytes).is_err(),
            "{index}"
        );
    }
    let mut record = record;
    record.raw_firmware_status = None;
    assert!(record.encode_exact().is_err());
    for ack in [false, true] {
        let value = control(ack);
        let bytes = value.encode_exact().unwrap();
        assert_eq!(
            InstallSessionControlV1::decode_exact(&bytes).unwrap(),
            value
        );
        assert!(FirmwareCompletionRecordV1::decode_exact(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(InstallSessionControlV1::decode_exact(&bytes[..end]).is_err());
        }
        let mut bad = bytes;
        bad[79] = 1;
        assert!(InstallSessionControlV1::decode_exact(&bad).is_err());
    }
}

#[test]
fn partial_or_indeterminate_destination_cannot_advance_to_source_installation() {
    for effect in [
        FirmwareCompletionEffectV1::Partial,
        FirmwareCompletionEffectV1::Unknown,
    ] {
        let mut sequence = InstallExchangeSequenceV1::new(reference());
        sequence
            .begin_request(&InstallExchangeRequestV1::Poll(control(false)), &Verifier)
            .unwrap();
        sequence
            .complete_response(
                &InstallExchangeResponseV1::DestinationConfirmation(confirmation(false)),
                &Verifier,
            )
            .unwrap();
        sequence
            .begin_request(
                &InstallExchangeRequestV1::SourceConfirmation(confirmation(true)),
                &Verifier,
            )
            .unwrap();
        let mut record = completion(false);
        record.outcome = FirmwareCompletionOutcomeV1::Indeterminate;
        record.effect = effect;
        assert_eq!(
            sequence.complete_response(
                &InstallExchangeResponseV1::DestinationCompletion(record),
                &Verifier
            ),
            Err(HostControlErrorV1::PeerInstallation {
                outcome: FirmwareCompletionOutcomeV1::Indeterminate,
                effect,
                raw_firmware_status: Some(0),
            })
        );
        assert!(sequence.finish().is_err());
    }
}
