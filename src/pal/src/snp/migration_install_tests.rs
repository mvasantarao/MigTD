use super::*;
use crate::{
    tenant_identity::VerifiedTenantReportDeliveryV1,
    tenant_replay::VerifiedTenantReplayBindingV1,
    types::{
        HostRequestId, ManagedGuestHandle, MigrationId, PeerRoutingReference, PolicyIdentity,
        ProtocolVersion, SnpVerifierTrust,
    },
};
use std::cell::RefCell;
use zeroize::Zeroizing;

// Trusted-interface doubles only: no signed claims, firmware or persistence.
struct Fixture {
    operation: SnpOperationContext,
    tenant: VerifiedTenantIdentity,
    authorization: VerifiedTenantAuthorizationV1,
    session: SnpSessionReferenceV2,
    key: Zeroizing<[u8; 32]>,
    history: [u8; 64],
}

impl Fixture {
    fn new(role: MigrationRole) -> Self {
        let operation = SnpOperationContext {
            peer: Some(PeerRoutingReference::new(4)),
            protocol_version: Some(ProtocolVersion::new(1, 2)),
            policy: Some(PolicyIdentity::new(5)),
            ..SnpOperationContext::new(
                HostRequestId::new(1),
                MigrationId::new(2),
                role,
                ManagedGuestHandle::new(3),
            )
        };
        let tenant = VerifiedTenantIdentity::from_verified_report_id([17; 32]);
        let delivery = VerifiedTenantReportDeliveryV1::from_verified_report(
            operation,
            tenant.clone(),
            [18; 48],
            SnpVerifierTrust::PinnedMilanArkTest,
            [19; 32],
            [20; 48],
        );
        let authorization = VerifiedTenantAuthorizationV1::from_verified_roles(
            VerifiedTenantReplayBindingV1::from_verified_context(
                &delivery, [21; 48], [19; 32], [22; 32],
            ),
        );
        let mut history = [0; 64];
        history[0] = 1;
        history[1] = 3;
        history[2..5].copy_from_slice(&[11, 12, 13]);
        for (index, byte) in history[10..].iter_mut().enumerate() {
            *byte = index as u8 + 30;
        }
        Self {
            operation,
            tenant,
            authorization,
            session: SnpSessionReferenceV2 {
                request_id: 1,
                session_context_digest: [23; 48],
            },
            key: Zeroizing::new([173; 32]),
            history,
        }
    }

    fn request(&self) -> MigrationInstallRequestV1<'_> {
        MigrationInstallRequestV1::new(
            &self.operation,
            &self.tenant,
            &self.authorization,
            &self.session,
            &self.key,
            &self.history,
            SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
        )
        .unwrap()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RecordedCall {
    correlation: MigrationInstallCorrelationV1,
    report_id_operand: [u8; 32],
    history: [u8; 64],
    algorithm: u16,
}

#[derive(Clone, Copy)]
enum InjectedOutcome {
    Success,
    Firmware(u32),
    Transport(MigrationInstallEffectV1),
    Partial(Option<u32>),
    Indeterminate(Option<u32>),
}

struct RecordingInstaller {
    calls: RefCell<Vec<RecordedCall>>,
    outcome: InjectedOutcome,
}

impl SnpMigrationKeyInstaller for RecordingInstaller {
    fn install_migration_info(
        &self,
        request: &MigrationInstallRequestV1<'_>,
    ) -> Result<MigrationInstallCompletionV1, MigrationInstallErrorV1> {
        assert_eq!(request.migration_key(), &[173; 32]);
        self.calls.borrow_mut().push(RecordedCall {
            correlation: request.correlation(),
            report_id_operand: request.firmware_report_id(),
            history: *request.migration_data(),
            algorithm: request.algorithm() as u16,
        });
        match self.outcome {
            InjectedOutcome::Success => {
                MigrationInstallCompletionV1::from_firmware_status(request, 0)
            }
            InjectedOutcome::Firmware(status) => {
                MigrationInstallCompletionV1::from_firmware_status(request, status)
            }
            InjectedOutcome::Transport(effect) => {
                Err(MigrationInstallErrorV1::transport(request, effect))
            }
            InjectedOutcome::Partial(status) => {
                Err(MigrationInstallErrorV1::partial(request, status))
            }
            InjectedOutcome::Indeterminate(status) => {
                Err(MigrationInstallErrorV1::indeterminate(request, status))
            }
        }
    }
}

#[test]
fn t412_completion_wire_uses_exact_local_correlation_not_persisted_state_receipts() {
    use crate::snp::control_exchange::*;
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let fixture = Fixture::new(role);
        let request = fixture.request();
        let success = MigrationInstallCompletionV1::from_firmware_status(&request, 0).unwrap();
        let record = FirmwareCompletionRecordV1::from_local(&request, Ok(&success)).unwrap();
        assert_eq!(record.outcome, FirmwareCompletionOutcomeV1::Completed);
        assert_eq!(record.effect, FirmwareCompletionEffectV1::Applied);
        assert_eq!(record.raw_firmware_status, Some(0));
        assert_eq!(
            FirmwareCompletionRecordV1::decode_exact(&record.encode_exact().unwrap()).unwrap(),
            record
        );
        let rejected = MigrationInstallCompletionV1::from_firmware_status(&request, 9).unwrap_err();
        let record = FirmwareCompletionRecordV1::from_local(&request, Err(&rejected)).unwrap();
        assert_eq!(record.outcome, FirmwareCompletionOutcomeV1::Indeterminate);
        assert_eq!(record.raw_firmware_status, Some(9));
        let mut wrong = Fixture::new(role);
        wrong.session.session_context_digest[0] ^= 1;
        assert!(FirmwareCompletionRecordV1::from_local(&wrong.request(), Ok(&success)).is_err());
    }
}

#[test]
fn both_roles_borrow_exact_key_history_and_existing_proofs() {
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let fixture = Fixture::new(role);
        let request = fixture.request();
        assert!(core::ptr::eq(request.migration_key(), &*fixture.key));
        assert!(core::ptr::eq(request.migration_data(), &fixture.history));
        assert!(core::ptr::eq(
            request.authorization(),
            &fixture.authorization
        ));
        assert_eq!(request.operation(), &fixture.operation);
        assert_eq!(request.tenant(), &fixture.tenant);
        assert_eq!(request.session(), &fixture.session);
        assert_eq!(request.algorithm() as u16, 3);
    }
}

#[test]
fn firmware_report_id_is_role_specific_without_losing_logical_identity() {
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let fixture = Fixture::new(role);
        let request = fixture.request();
        let expected = match role {
            MigrationRole::Source => [17; 32],
            MigrationRole::Destination => [0; 32],
        };
        assert_eq!(request.firmware_report_id(), expected);
        assert_eq!(request.correlation().tenant_report_id(), &[17; 32]);
    }
}

#[test]
fn every_operation_field_must_match_existing_authorization() {
    let fixture = Fixture::new(MigrationRole::Source);
    for operation in [
        SnpOperationContext {
            request_id: HostRequestId::new(99),
            ..fixture.operation
        },
        SnpOperationContext {
            migration_id: MigrationId::new(99),
            ..fixture.operation
        },
        SnpOperationContext {
            role: MigrationRole::Destination,
            ..fixture.operation
        },
        SnpOperationContext {
            managed_guest: ManagedGuestHandle::new(99),
            ..fixture.operation
        },
        SnpOperationContext {
            peer: None,
            ..fixture.operation
        },
        SnpOperationContext {
            protocol_version: None,
            ..fixture.operation
        },
        SnpOperationContext {
            policy: None,
            ..fixture.operation
        },
    ] {
        assert_eq!(
            MigrationInstallRequestV1::new(
                &operation,
                &fixture.tenant,
                &fixture.authorization,
                &fixture.session,
                &fixture.key,
                &fixture.history,
                SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            )
            .unwrap_err(),
            MigrationInstallInputErrorV1::OperationMismatch
        );
    }
}

#[test]
fn another_verified_tenant_is_not_this_authorized_tenant() {
    let fixture = Fixture::new(MigrationRole::Source);
    let other = VerifiedTenantIdentity::from_verified_report_id([99; 32]);
    assert_eq!(
        MigrationInstallRequestV1::new(
            &fixture.operation,
            &other,
            &fixture.authorization,
            &fixture.session,
            &fixture.key,
            &fixture.history,
            SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
        )
        .unwrap_err(),
        MigrationInstallInputErrorV1::TenantMismatch
    );
}

#[test]
fn mismatched_session_request_is_rejected() {
    let fixture = Fixture::new(MigrationRole::Source);
    let session = SnpSessionReferenceV2 {
        request_id: 99,
        ..fixture.session.clone()
    };
    assert_eq!(
        MigrationInstallRequestV1::new(
            &fixture.operation,
            &fixture.tenant,
            &fixture.authorization,
            &session,
            &fixture.key,
            &fixture.history,
            SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
        )
        .unwrap_err(),
        MigrationInstallInputErrorV1::SessionRequestMismatch
    );
}

#[test]
fn non_migration_algorithms_are_rejected() {
    let fixture = Fixture::new(MigrationRole::Source);
    for algorithm in [
        SnpMigrationAlgorithmV1::None,
        SnpMigrationAlgorithmV1::LocalHandoffSecretV1,
    ] {
        assert_eq!(
            MigrationInstallRequestV1::new(
                &fixture.operation,
                &fixture.tenant,
                &fixture.authorization,
                &fixture.session,
                &fixture.key,
                &fixture.history,
                algorithm,
            )
            .unwrap_err(),
            MigrationInstallInputErrorV1::UnsupportedAlgorithm
        );
    }
}

#[test]
fn history_version_profile_and_all_reserved_bytes_are_checked() {
    for index in [0, 1, 5, 6, 7, 8, 9] {
        let mut fixture = Fixture::new(MigrationRole::Source);
        fixture.history[index] ^= 0x80;
        assert!(matches!(
            MigrationInstallRequestV1::new(
                &fixture.operation,
                &fixture.tenant,
                &fixture.authorization,
                &fixture.session,
                &fixture.key,
                &fixture.history,
                SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            ),
            Err(MigrationInstallInputErrorV1::InvalidMigrationData(_))
        ));
    }
}

#[test]
fn recording_provider_receives_exact_history_and_correlated_local_completion() {
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let fixture = Fixture::new(role);
        let request = fixture.request();
        let provider = RecordingInstaller {
            calls: RefCell::new(Vec::new()),
            outcome: InjectedOutcome::Success,
        };
        let installer: &dyn SnpMigrationKeyInstaller = &provider;
        let completion = installer.install_migration_info(&request).unwrap();
        assert_eq!(completion.firmware_status(), 0);
        assert_eq!(completion.correlation(), &request.correlation());
        assert_eq!(
            provider.calls.borrow().as_slice(),
            &[RecordedCall {
                correlation: request.correlation(),
                report_id_operand: request.firmware_report_id(),
                history: fixture.history,
                algorithm: 3,
            }]
        );
        assert_eq!(&*fixture.key, &[173; 32]);
    }
}

#[test]
fn every_defined_history_byte_is_forwarded_without_recalculation() {
    for index in [2, 3, 4].into_iter().chain(10..64) {
        let mut fixture = Fixture::new(MigrationRole::Source);
        fixture.history[index] ^= 0x80;
        assert_eq!(fixture.request().migration_data(), &fixture.history);
    }
}

#[test]
fn nonzero_raw_status_never_becomes_success_or_an_invented_root_cause() {
    let fixture = Fixture::new(MigrationRole::Source);
    let request = fixture.request();
    for status in [1, 0xfeed_beef, u32::MAX] {
        let error =
            MigrationInstallCompletionV1::from_firmware_status(&request, status).unwrap_err();
        assert_eq!(
            error.failure(),
            MigrationInstallFailureV1::FirmwareRejected { status }
        );
        assert_eq!(error.firmware_status(), Some(status));
        assert_eq!(error.correlation(), &request.correlation());
        assert_eq!(error.effect(), MigrationInstallEffectV1::Unknown);
        assert!(error.requires_reconciliation());
    }
}

#[test]
fn unavailable_never_installs_for_either_role_or_explicit_retry() {
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let fixture = Fixture::new(role);
        let request = fixture.request();
        for _ in 0..2 {
            let error = UnavailableMigrationKeyInstallerV1
                .install_migration_info(&request)
                .unwrap_err();
            assert_eq!(error.failure(), MigrationInstallFailureV1::Unavailable);
            assert_eq!(error.firmware_status(), None);
            assert_eq!(error.effect(), MigrationInstallEffectV1::NotApplied);
            assert!(!error.requires_reconciliation());
            assert_eq!(error.correlation(), &request.correlation());
        }
    }
}

#[test]
fn transport_effects_are_explicit_and_never_implicitly_successful() {
    let fixture = Fixture::new(MigrationRole::Source);
    let request = fixture.request();
    for effect in [
        MigrationInstallEffectV1::NotApplied,
        MigrationInstallEffectV1::Partial,
        MigrationInstallEffectV1::Unknown,
    ] {
        let error = MigrationInstallErrorV1::transport(&request, effect);
        assert_eq!(
            error.failure(),
            MigrationInstallFailureV1::Transport { effect }
        );
        assert_eq!(error.effect(), effect);
        assert_eq!(error.firmware_status(), None);
        assert_eq!(
            error.requires_reconciliation(),
            effect != MigrationInstallEffectV1::NotApplied
        );
    }
}

#[test]
fn partial_and_indeterminate_retain_absent_zero_and_nonzero_observations() {
    let fixture = Fixture::new(MigrationRole::Source);
    let request = fixture.request();
    for status in [None, Some(0), Some(0xfeed_beef)] {
        let partial = MigrationInstallErrorV1::partial(&request, status);
        let unknown = MigrationInstallErrorV1::indeterminate(&request, status);
        assert_eq!(partial.effect(), MigrationInstallEffectV1::Partial);
        assert_eq!(unknown.effect(), MigrationInstallEffectV1::Unknown);
        for error in [partial, unknown] {
            assert_eq!(error.firmware_status(), status);
            assert_eq!(error.correlation(), &request.correlation());
            assert!(error.requires_reconciliation());
        }
    }
}

#[test]
fn failure_injection_keeps_all_outcomes_correlated_without_automatic_retry() {
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let fixture = Fixture::new(role);
        let request = fixture.request();
        for outcome in [
            InjectedOutcome::Firmware(0xfeed_beef),
            InjectedOutcome::Transport(MigrationInstallEffectV1::NotApplied),
            InjectedOutcome::Transport(MigrationInstallEffectV1::Unknown),
            InjectedOutcome::Partial(Some(0)),
            InjectedOutcome::Indeterminate(None),
        ] {
            let provider = RecordingInstaller {
                calls: RefCell::new(Vec::new()),
                outcome,
            };
            let error = provider.install_migration_info(&request).unwrap_err();
            assert_eq!(error.correlation(), &request.correlation());
            assert_eq!(provider.calls.borrow().len(), 1);
        }
    }
}

#[test]
fn correlation_preserves_operation_tenant_and_exact_session_digest() {
    let fixture = Fixture::new(MigrationRole::Source);
    let correlation = fixture.request().correlation();
    assert_eq!(correlation.operation(), &fixture.operation);
    assert_eq!(correlation.tenant_report_id(), fixture.tenant.as_bytes());
    assert_eq!(correlation.session(), &fixture.session);
    let mut other = Fixture::new(MigrationRole::Source);
    other.session.session_context_digest[47] ^= 1;
    assert_ne!(correlation, other.request().correlation());
    assert_ne!(
        correlation,
        Fixture::new(MigrationRole::Destination)
            .request()
            .correlation()
    );
}

#[test]
fn debug_redacts_secret_proofs_identity_history_and_session_material() {
    let fixture = Fixture::new(MigrationRole::Source);
    let before = format!("{:?}", fixture.request());
    let mut other = Fixture::new(MigrationRole::Source);
    other.key.fill(29);
    other.history[63] ^= 0xff;
    other.session.session_context_digest.fill(31);
    assert_eq!(before, format!("{:?}", other.request()));
    assert!(before.contains("[REDACTED]"));
    assert!(!before.contains(&format!("{:?}", &*fixture.key)));
}
