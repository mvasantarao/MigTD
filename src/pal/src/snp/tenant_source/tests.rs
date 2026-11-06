use super::*;
use crate::{
    snp::collateral_set::SnpCertificateEntryV1,
    tenant_identity::{HostPushedTenantReportV1, TenantReportReferenceV1},
    tenant_replay::{
        ReplayTerminalOutcomeV1, TenantReplaySnapshotV1, UnavailableTenantFirmwareStateV1,
        UnavailableTenantReplayStoreV1,
    },
    types::{HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole},
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

// These are trusted-interface doubles, not an attestation backend or signed
// fixtures. P0.10 owns crypto vectors; Task6/AAS1A-M own executable verification.
struct ContractVerifier {
    evidence: SnpEvidenceInput,
    claims: AuthenticatedSnpClaims,
    error: Cell<Option<SnpReportVerificationError>>,
    calls: Cell<usize>,
}

impl SnpReportVerifier for ContractVerifier {
    fn verify(
        &self,
        request: SnpReportVerificationRequest<'_>,
    ) -> Result<AuthenticatedSnpClaims, SnpReportVerificationError> {
        self.calls.set(self.calls.get() + 1);
        if let Some(error) = self.error.get() {
            return Err(error);
        }
        let (evidence, collateral, vmpl, data) = match request {
            SnpReportVerificationRequest::HostRequestedTenant {
                evidence,
                collateral,
            } => (evidence, collateral, u32::MAX, [0; 64]),
            SnpReportVerificationRequest::GuestRequestedTenant {
                evidence,
                collateral,
                expected_vmpl,
                expected_report_data,
            } => (evidence, collateral, expected_vmpl, expected_report_data),
            SnpReportVerificationRequest::GuestRequestedMa { .. } => {
                panic!("tenant evidence must not use MA verification")
            }
        };
        assert_eq!(collateral.expected_trust_domain, SnpTrustDomain::Fixture);
        if evidence != &self.evidence {
            return Err(SnpReportVerificationError::SignatureVerificationFailed);
        }
        if self.claims.vmpl != vmpl {
            return Err(SnpReportVerificationError::UnexpectedVmpl);
        }
        if self.claims.report_data != data {
            return Err(SnpReportVerificationError::ReportDataMismatch);
        }
        Ok(self.claims.clone())
    }
}

fn operation() -> SnpOperationContext {
    SnpOperationContext::new(
        HostRequestId::new(1),
        MigrationId::new(2),
        MigrationRole::Source,
        ManagedGuestHandle::new(3),
    )
}

fn collateral() -> SnpCollateralInput {
    SnpCollateralInput {
        expected_trust_domain: SnpTrustDomain::Fixture,
        leaf_certificate_der: vec![1],
        intermediate_certificate_der: vec![2],
        root_certificate_der: vec![3],
        revocation: SnpRevocationInput::FixtureNotApplicable,
        verification_time_unix_seconds: 10,
    }
}

fn package(binding: TenantEvidenceBinding) -> TenantEvidencePackage {
    let mut report = [0; 1184];
    report[..4].copy_from_slice(&6u32.to_le_bytes());
    let (vmpl, data) = match binding {
        TenantEvidenceBinding::HostRequestedZeroReportData => (u32::MAX, [0; 64]),
        TenantEvidenceBinding::GuestProvidedReportData {
            expected_vmpl,
            expected_report_data,
        } => (expected_vmpl, expected_report_data),
    };
    report[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes());
    report[0x50..0x90].copy_from_slice(&data);
    report[0x140..0x160].fill(0x44);
    report[0x160..0x180].fill(0x55);
    let mut supplement = [0; 220];
    supplement[..2].copy_from_slice(&1u16.to_le_bytes());
    supplement[2..4].copy_from_slice(&1u16.to_le_bytes());
    supplement[4..52].copy_from_slice(&sha384(&report));
    TenantEvidencePackage::new(
        SnpEvidenceInput::EmulatorV1(Box::new(SnpEmulatorEvidenceV1 {
            report,
            supplement,
            supplement_signature: [7; 96],
        })),
        SnpCollateralSetV1 {
            evidence_profile: SnpEvidenceProfileV1::Fixture,
            tcb_profile: SnpTcbProfileV1::Venice,
            leaf_certificate: SnpCertificateEntryV1 {
                role: SnpCertificateRoleV1::Vcek,
                certificate_der: vec![1],
            },
            ask_certificate: SnpCertificateEntryV1 {
                role: SnpCertificateRoleV1::Ask,
                certificate_der: vec![2],
            },
        },
    )
    .unwrap()
}

fn verifier(package: &TenantEvidencePackage) -> ContractVerifier {
    let evidence = match &package.evidence {
        SnpEvidenceInput::EmulatorV1(evidence) => evidence,
        _ => panic!("test requires emulator input"),
    };
    let report = &evidence.report;
    let tcb = AuthenticatedTcb::Venice {
        fmc: 0,
        tee: 0,
        snp: 0,
    };
    ContractVerifier {
        evidence: package.evidence.clone(),
        claims: AuthenticatedSnpClaims {
            provenance: SnpClaimProvenance {
                evidence_profile: SnpEvidenceProfile::SnpEmulatorV1,
                trust_domain: SnpTrustDomain::Fixture,
                report_sha384: sha384(report),
                supplement_sha384: Some(sha384(&evidence.supplement)),
            },
            report_version: 6,
            guest_svn: 0,
            policy: 0,
            family_id: [0; 16],
            image_id: [0; 16],
            vmpl: u32::from_le_bytes(report[0x30..0x34].try_into().unwrap()),
            report_data: report[0x50..0x90].try_into().unwrap(),
            measurement: [0; 48],
            host_data: [0; 32],
            id_key_digest: [0; 48],
            author_key_digest: [0; 48],
            author_key_en: false,
            report_id: [0x44; 32],
            report_id_ma: [0x55; 32],
            reported_tcb: tcb,
            current_tcb: tcb,
            committed_tcb: tcb,
            launch_tcb: tcb,
            current_etcb: AuthenticatedEtcb { raw: [0; 32] },
            committed_etcb: AuthenticatedEtcb { raw: [0; 32] },
            launch_etcb: AuthenticatedEtcb { raw: [0; 32] },
            current_mitigation_vector: 0,
            launch_mitigation_vector: 0,
            migration_data_valid: false,
            migration_data: [0; 64],
            signing_key_kind: SnpSigningKeyKind::Vcek,
            collateral_status: SnpCollateralStatus {
                trust_domain: SnpTrustDomain::Fixture,
                leaf_certificate_sha384: sha384(&[1]),
                certificate_chain_sha384: chain_digest(&collateral()),
                verification_time_unix_seconds: 10,
                revocation: SnpRevocationStatus::FixtureNotApplicable,
            },
        },
        error: Cell::new(None),
        calls: Cell::new(0),
    }
}

#[derive(Clone)]
struct Store {
    snapshot: Rc<RefCell<TenantReplaySnapshotV1>>,
    loads: Rc<Cell<usize>>,
    commits: Rc<Cell<usize>>,
}

impl Store {
    fn new() -> Self {
        Self {
            snapshot: Rc::new(RefCell::new(TenantReplaySnapshotV1 {
                revision: 0,
                records: vec![],
            })),
            loads: Rc::new(Cell::new(0)),
            commits: Rc::new(Cell::new(0)),
        }
    }
}

impl DurableTenantReplayStoreV1 for Store {
    fn load_authenticated(
        &mut self,
        _: usize,
    ) -> Result<TenantReplaySnapshotV1, TenantReplayErrorV1> {
        self.loads.set(self.loads.get() + 1);
        Ok(self.snapshot.borrow().clone())
    }

    fn commit(
        &mut self,
        expected_revision: u64,
        replacement: &TenantReplaySnapshotV1,
    ) -> Result<(), TenantReplayErrorV1> {
        if self.snapshot.borrow().revision != expected_revision {
            return Err(TenantReplayErrorV1::ConcurrentUpdate);
        }
        self.commits.set(self.commits.get() + 1);
        *self.snapshot.borrow_mut() = replacement.clone();
        Ok(())
    }
}

struct Firmware {
    calls: Rc<Cell<usize>>,
    error: Option<TenantReplayErrorV1>,
}

impl CurrentTenantFirmwareStateV1 for Firmware {
    fn validate_current(
        &mut self,
        _: &VerifiedTenantReplayBindingV1,
    ) -> Result<(), TenantReplayErrorV1> {
        self.calls.set(self.calls.get() + 1);
        match self.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn source(verifier: &dyn SnpReportVerifier) -> HostPushedTenantEvidenceSource<'_, Store, Firmware> {
    source_with_store(verifier, Store::new())
}

fn source_with_store(
    verifier: &dyn SnpReportVerifier,
    store: Store,
) -> HostPushedTenantEvidenceSource<'_, Store, Firmware> {
    HostPushedTenantEvidenceSource::new(
        operation(),
        verifier,
        collateral(),
        store,
        Firmware {
            calls: Rc::new(Cell::new(0)),
            error: None,
        },
        4,
    )
    .unwrap()
}

fn assert_rejected_before_effects(
    package: &TenantEvidencePackage,
    verifier: &ContractVerifier,
    error: SnpReportVerificationError,
) {
    let store = Store::new();
    let observed = store.clone();
    let mut source = source_with_store(verifier, store);
    assert_eq!(
        source.evidence(request(&prepare(package, false), package)),
        Err(error.into())
    );
    assert!(source.receipt.is_none());
    assert_eq!(observed.loads.get(), 0);
    assert_eq!(observed.commits.get(), 0);
    assert_eq!(source.firmware.calls.get(), 0);
    assert_eq!(verifier.calls.get(), 1);
}

fn prepare(package: &TenantEvidencePackage, reference: bool) -> PrepareMigrationRequestV1 {
    let delivery = if reference {
        TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new(sha384(
            package.evidence.report(),
        )))
    } else {
        TenantReportDeliveryV1::Inline(
            HostPushedTenantReportV1::from_bytes(package.evidence.report()).unwrap(),
        )
    };
    PrepareMigrationRequestV1::new(operation(), delivery)
}

fn request<'a>(
    prepare: &'a PrepareMigrationRequestV1,
    package: &'a TenantEvidencePackage,
) -> TenantEvidenceRequest<'a> {
    TenantEvidenceRequest {
        prepare,
        package,
        binding: TenantEvidenceBinding::HostRequestedZeroReportData,
        expected_identity: None,
    }
}

fn binding(receipt: &TenantEvidence) -> VerifiedTenantReplayBindingV1 {
    VerifiedTenantReplayBindingV1::from_verified_context(
        receipt.verified_delivery().unwrap(),
        [0x66; 48],
        [0x55; 32],
        [0x77; 32],
    )
}

fn t412_frame(
    package: &TenantEvidencePackage,
    reference: bool,
) -> crate::snp::host_control::HostControlFrameV1 {
    use crate::snp::host_control::*;
    HostControlFrameV1 {
        kind: HostControlKindV1::Prepare,
        response: false,
        operation: operation(),
        body: HostControlBodyV1::Prepare {
            request: prepare(package, reference),
            package: if reference {
                None
            } else {
                Some(Box::new(package.clone()))
            },
            package_digest: sha384(&package.encode_host_package_v1().unwrap()),
            ma_profiles: Box::new(HostMaProfilesV1 {
                source: package.clone(),
                destination: package.clone(),
            }),
        },
    }
}

// Conformance-only trusted context authority. No production storage is selected.
struct T412NewContext;
impl crate::snp::host_control::HostControlContextAuthorityV1 for T412NewContext {
    fn reserve_operation(
        &mut self,
        _: &SnpOperationContext,
    ) -> Result<
        crate::snp::host_control::HostControlClaimV1,
        crate::snp::host_control::HostControlErrorV1,
    > {
        Ok(crate::snp::host_control::HostControlClaimV1::ReservedNewOperation)
    }
    fn finish_before_proofs(
        &mut self,
        _: &SnpOperationContext,
        _: ReplayTerminalResultV1,
    ) -> Result<(), crate::snp::host_control::HostControlErrorV1> {
        Ok(())
    }
}

#[test]
fn t412_preproof_cancel_survives_restart_and_ambiguous_writes_do_not_acknowledge() {
    use crate::snp::host_control::*;
    type ContextState = Option<(SnpOperationContext, Option<ReplayTerminalResultV1>)>;
    #[derive(Clone)]
    struct Context {
        state: Rc<RefCell<ContextState>>,
        writes: Rc<Cell<usize>>,
        fail_after_write: bool,
    }
    impl HostControlContextAuthorityV1 for Context {
        fn reserve_operation(
            &mut self,
            operation: &SnpOperationContext,
        ) -> Result<HostControlClaimV1, HostControlErrorV1> {
            let mut state = self.state.borrow_mut();
            match *state {
                None => {
                    *state = Some((*operation, None));
                    Ok(HostControlClaimV1::ReservedNewOperation)
                }
                Some((stored, _)) if stored != *operation => {
                    Err(HostControlErrorV1::CorrelationMismatch)
                }
                Some((_, Some(result))) => Ok(HostControlClaimV1::Terminal(result)),
                Some((_, None)) => Ok(HostControlClaimV1::ExistingOperation),
            }
        }
        fn finish_before_proofs(
            &mut self,
            operation: &SnpOperationContext,
            result: ReplayTerminalResultV1,
        ) -> Result<(), HostControlErrorV1> {
            assert_eq!(self.state.borrow().as_ref().unwrap().0, *operation);
            assert_ne!(result.outcome, ReplayTerminalOutcomeV1::Succeeded);
            *self.state.borrow_mut() = Some((*operation, Some(result)));
            self.writes.set(self.writes.get() + 1);
            if self.fail_after_write {
                Err(HostControlErrorV1::ProviderUnavailable)
            } else {
                Ok(())
            }
        }
    }
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    for fail_after_write in [false, true] {
        let context = Context {
            state: Rc::new(RefCell::new(None)),
            writes: Rc::new(Cell::new(0)),
            fail_after_write,
        };
        let replay = Store::new();
        let mut owner = SnpHostOperationV1::new(
            operation(),
            source_with_store(&verifier, replay.clone()),
            context.clone(),
        )
        .unwrap();
        owner.prepare(&t412_frame(&package, false), None).unwrap();
        let cancel = HostControlFrameV1 {
            kind: HostControlKindV1::Cancel,
            response: false,
            operation: operation(),
            body: HostControlBodyV1::Empty,
        };
        let result = owner.control(&cancel);
        if fail_after_write {
            assert_eq!(result, Err(HostControlErrorV1::ProviderUnavailable));
            assert_eq!(owner.phase(), HostOperationPhaseV1::ReconciliationRequired);
            assert!(owner.control(&cancel).is_err());
        } else {
            assert!(result.is_ok());
            assert_eq!(owner.control(&cancel).unwrap(), result.unwrap());
        }
        assert_eq!(context.writes.get(), 1);
        assert_eq!(replay.commits.get(), 0);
        let mut restored = SnpHostOperationV1::new(
            operation(),
            source_with_store(&verifier, replay.clone()),
            context.clone(),
        )
        .unwrap();
        let query = HostControlFrameV1 {
            kind: HostControlKindV1::Query,
            ..cancel
        };
        assert!(matches!(
            restored.control(&query).unwrap().body,
            HostControlBodyV1::Status {
                phase: HostOperationPhaseV1::Terminal,
                terminal: Some(ReplayTerminalResultV1 {
                    outcome: ReplayTerminalOutcomeV1::Aborted,
                    ..
                })
            }
        ));
        assert_eq!(context.writes.get(), 1);
    }
}

#[test]
fn t412_preproof_restart_also_requires_authenticated_context_not_an_empty_journal() {
    use crate::snp::host_control::*;
    struct Existing;
    impl HostControlContextAuthorityV1 for Existing {
        fn reserve_operation(
            &mut self,
            _: &SnpOperationContext,
        ) -> Result<HostControlClaimV1, HostControlErrorV1> {
            Ok(HostControlClaimV1::ExistingOperation)
        }
        fn finish_before_proofs(
            &mut self,
            _: &SnpOperationContext,
            _: ReplayTerminalResultV1,
        ) -> Result<(), HostControlErrorV1> {
            Err(HostControlErrorV1::ReconciliationRequired)
        }
    }
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let mut restored = SnpHostOperationV1::new(operation(), source(&verifier), Existing).unwrap();
    assert_eq!(
        restored.phase(),
        HostOperationPhaseV1::ReconciliationRequired
    );
    assert!(restored
        .prepare(&t412_frame(&package, false), None)
        .is_err());
    assert!(matches!(
        SnpHostOperationV1::new(
            operation(),
            source(&verifier),
            UnavailableHostControlContextAuthorityV1
        ),
        Err(HostControlErrorV1::ProviderUnavailable)
    ));
}

#[test]
fn direct_installation_requires_acceptance_destination_completion_and_durable_terminal_commit() {
    for failure in 0..3 {
        use crate::snp::{
            direct_exchange::*, host_control::*, migration_install::*, report_data_context::*,
        };
        let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        let verifier = verifier(&package);
        let store = Store::new();
        let mut owner = SnpHostOperationV1::new(
            operation(),
            source_with_store(&verifier, store.clone()),
            T412NewContext,
        )
        .unwrap();
        owner.prepare(&t412_frame(&package, false), None).unwrap();
        let receipt = owner.received_evidence().unwrap().clone();
        owner
            .match_source_evidence(
                receipt
                    .verified_delivery()
                    .unwrap()
                    .canonical_evidence_digest(),
            )
            .unwrap();
        let binding = binding(&receipt);
        owner.reserve_after_ma_proofs(&binding).unwrap();
        let authorization = VerifiedTenantAuthorizationV1::from_verified_roles(binding);
        owner.authorize_after_role_proofs(&authorization).unwrap();
        let context = crate::snp::direct_exchange::tests::context(
            operation().role,
            operation().request_id.value(),
        );
        let session = context.reference().clone();
        let mut exchange = InstallExchangeSequenceV2::new(&context);
        let key = exchange
            .observe(crate::snp::direct_exchange::tests::token(&context, 0x30))
            .unwrap()
            .unwrap();
        exchange
            .observe(crate::snp::direct_exchange::tests::token(&context, 0x31))
            .unwrap();
        assert!(owner
            .begin_installation(&exchange.accepted_session().unwrap())
            .is_err());
        exchange
            .observe(crate::snp::direct_exchange::tests::token(&context, 0x32))
            .unwrap();
        exchange
            .observe(crate::snp::direct_exchange::tests::token(&context, 0x33))
            .unwrap();
        owner
            .begin_installation(&exchange.accepted_session().unwrap())
            .unwrap();
        assert!(owner
            .begin_installation(&exchange.accepted_session().unwrap())
            .is_err());
        let mut history = [0; 64];
        history[0] = 1;
        history[1] = 3;
        let operation = operation();
        let request = MigrationInstallRequestV1::new(
            &operation,
            receipt.identity(),
            &authorization,
            &session,
            key.for_installation(&context).unwrap(),
            &history,
            SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
        )
        .unwrap();
        let completion = MigrationInstallCompletionV1::from_firmware_status(&request, 0).unwrap();
        if failure != 0 {
            let error = if failure == 1 {
                MigrationInstallErrorV1::partial(&request, Some(0))
            } else {
                MigrationInstallErrorV1::indeterminate(&request, None)
            };
            assert_eq!(
                owner.observe_installation(Err(&error)),
                Err(HostControlErrorV1::ReconciliationRequired)
            );
            let abort = HostControlFrameV1 {
                kind: HostControlKindV1::Abort,
                response: false,
                operation,
                body: HostControlBodyV1::Empty,
            };
            assert_eq!(
                owner.control(&abort),
                Err(HostControlErrorV1::ReconciliationRequired)
            );
            assert!(owner
                .begin_installation(&exchange.accepted_session().unwrap())
                .is_err());
            assert_eq!(store.commits.get(), 2);
            continue;
        }
        owner.observe_installation(Ok(&completion)).unwrap();
        let result = ReplayTerminalResultV1 {
            outcome: ReplayTerminalOutcomeV1::Succeeded,
            result_digest: [74; 48],
        };
        assert!(owner.finish(result, None).is_err());
        let local = FirmwareCompletionRecordV2::from_local(&request, Ok(&completion)).unwrap();
        exchange
            .observe(
                ProtectedInstallRecordV2::from_peer(0x34, &local.encode_exact().unwrap(), &context)
                    .unwrap(),
            )
            .unwrap();
        exchange
            .observe(crate::snp::direct_exchange::tests::token(&context, 0x35))
            .unwrap();
        let peer = exchange.finish().unwrap();
        owner.finish(result, Some(&peer)).unwrap();
        owner.finish(result, Some(&peer)).unwrap();
        assert_eq!(owner.phase(), HostOperationPhaseV1::Terminal);
        assert_eq!(store.commits.get(), 3);
    }
}

#[test]
fn t412_controller_orders_evidence_proofs_authorization_and_durable_abort() {
    use crate::snp::host_control::*;
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let store = Store::new();
    let mut owner = SnpHostOperationV1::new(
        operation(),
        source_with_store(&verifier, store.clone()),
        T412NewContext,
    )
    .unwrap();
    assert_eq!(owner.phase(), HostOperationPhaseV1::AwaitingEvidence);
    owner.prepare(&t412_frame(&package, false), None).unwrap();
    let receipt = owner.received_evidence().unwrap().clone();
    let binding = binding(&receipt);
    assert!(owner.reserve_after_ma_proofs(&binding).is_err());
    let digest = *receipt
        .verified_delivery()
        .unwrap()
        .canonical_evidence_digest();
    assert!(owner.match_source_evidence(&[99; 48]).is_err());
    owner.match_source_evidence(&digest).unwrap();
    owner.reserve_after_ma_proofs(&binding).unwrap();
    assert_eq!(store.commits.get(), 1);
    owner
        .prepare(&t412_frame(&package, true), Some(&package))
        .unwrap();
    assert_eq!(store.commits.get(), 1);
    let authorization = VerifiedTenantAuthorizationV1::from_verified_roles(binding);
    owner.authorize_after_role_proofs(&authorization).unwrap();
    assert_eq!(store.commits.get(), 2);
    let cancel = HostControlFrameV1 {
        kind: HostControlKindV1::Cancel,
        response: false,
        operation: operation(),
        body: HostControlBodyV1::Empty,
    };
    let result = owner.control(&cancel).unwrap();
    assert_eq!(owner.phase(), HostOperationPhaseV1::Terminal);
    assert_eq!(store.commits.get(), 3);
    assert_eq!(owner.control(&cancel).unwrap(), result);
    assert_eq!(store.commits.get(), 3);
    let mut restored = SnpHostOperationV1::new(
        operation(),
        source_with_store(&verifier, store.clone()),
        T412NewContext,
    )
    .unwrap();
    let query = HostControlFrameV1 {
        kind: HostControlKindV1::Query,
        ..cancel
    };
    assert!(matches!(
        restored.control(&query).unwrap().body,
        HostControlBodyV1::Status {
            phase: HostOperationPhaseV1::Terminal,
            terminal: Some(_)
        }
    ));
    assert_eq!(store.commits.get(), 3);
}

#[test]
fn t412_restart_never_replaces_a_live_session_or_reconstructs_empty_state() {
    use crate::snp::host_control::*;
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let store = Store::new();
    let mut owner = SnpHostOperationV1::new(
        operation(),
        source_with_store(&verifier, store.clone()),
        T412NewContext,
    )
    .unwrap();
    owner.prepare(&t412_frame(&package, false), None).unwrap();
    let receipt = owner.received_evidence().unwrap().clone();
    owner
        .match_source_evidence(
            receipt
                .verified_delivery()
                .unwrap()
                .canonical_evidence_digest(),
        )
        .unwrap();
    owner.reserve_after_ma_proofs(&binding(&receipt)).unwrap();
    let mut restored = SnpHostOperationV1::new(
        operation(),
        source_with_store(&verifier, store.clone()),
        T412NewContext,
    )
    .unwrap();
    assert_eq!(
        restored.phase(),
        HostOperationPhaseV1::ReconciliationRequired
    );
    assert_eq!(
        restored.prepare(&t412_frame(&package, false), None),
        Err(HostControlErrorV1::ReconciliationRequired)
    );
    assert_eq!(store.commits.get(), 1);
    let unavailable = HostPushedTenantEvidenceSource::new(
        operation(),
        &verifier,
        collateral(),
        UnavailableTenantReplayStoreV1,
        UnavailableTenantFirmwareStateV1,
        4,
    )
    .unwrap();
    assert!(matches!(
        SnpHostOperationV1::new(operation(), unavailable, T412NewContext),
        Err(HostControlErrorV1::Evidence(
            TenantEvidenceError::ProductionReplayStateUnavailable
        ))
    ));
}

#[test]
fn t412_controller_rejects_changed_profile_package_operation_and_host_success() {
    use crate::snp::host_control::*;
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let mut owner =
        SnpHostOperationV1::new(operation(), source(&verifier), T412NewContext).unwrap();
    let frame = t412_frame(&package, false);
    owner.prepare(&frame, None).unwrap();
    let mut changed = frame.clone();
    let HostControlBodyV1::Prepare { ma_profiles, .. } = &mut changed.body else {
        unreachable!()
    };
    let SnpEvidenceInput::EmulatorV1(evidence) = &mut ma_profiles.source.evidence else {
        unreachable!()
    };
    evidence.supplement_signature[0] ^= 1;
    assert_eq!(
        owner.prepare(&changed, None),
        Err(HostControlErrorV1::ConflictingDelivery)
    );
    let mut query = HostControlFrameV1 {
        kind: HostControlKindV1::Query,
        response: false,
        operation: operation(),
        body: HostControlBodyV1::Empty,
    };
    query.operation.migration_id = MigrationId::new(999);
    assert_eq!(
        owner.control(&query),
        Err(HostControlErrorV1::CorrelationMismatch)
    );
    assert!(owner
        .finish(
            ReplayTerminalResultV1 {
                outcome: ReplayTerminalOutcomeV1::Succeeded,
                result_digest: [0; 48]
            },
            None
        )
        .is_err());
}

#[test]
fn inline_reference_retry_preserves_complete_receipt_without_replay_or_firmware_effects() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let store = Store::new();
    let loads = store.loads.clone();
    let commits = store.commits.clone();
    let mut source = source_with_store(&verifier, store);
    let first = source
        .evidence(request(&prepare(&package, false), &package))
        .unwrap()
        .clone();
    let retry = source
        .evidence(request(&prepare(&package, true), &package))
        .unwrap();
    assert_eq!(&first, retry);
    assert_eq!(retry.identity().as_bytes(), &[0x44; 32]);
    let evidence = match &package.evidence {
        SnpEvidenceInput::EmulatorV1(e) => e,
        _ => unreachable!(),
    };
    assert_eq!(
        retry
            .verified_delivery()
            .unwrap()
            .canonical_evidence_digest(),
        &canonical_tenant_evidence_digest_v1(
            &evidence.report,
            Some((&evidence.supplement, &evidence.supplement_signature))
        )
    );
    assert_ne!(
        retry
            .verified_delivery()
            .unwrap()
            .canonical_evidence_digest(),
        &canonical_tenant_evidence_digest_v1(&evidence.report, None)
    );
    assert_eq!(verifier.calls.get(), 1);
    assert_eq!(
        (loads.get(), commits.get(), source.firmware.calls.get()),
        (0, 0, 0)
    );
}

#[test]
fn changed_package_or_binding_never_replaces_an_accepted_receipt() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let mut source = source(&verifier);
    let prepare = prepare(&package, true);
    let accepted = source
        .evidence(request(&prepare, &package))
        .unwrap()
        .clone();
    for location in 0..3 {
        let mut changed = package.clone();
        if let SnpEvidenceInput::EmulatorV1(e) = &mut changed.evidence {
            match location {
                0 => e.supplement[219] ^= 1,
                1 => e.supplement_signature[95] ^= 1,
                _ => e.report[100] ^= 1,
            }
        }
        assert!(source.evidence(request(&prepare, &changed)).is_err());
        assert_eq!(source.receipt.as_ref(), Some(&accepted));
    }
    let mut changed_binding = request(&prepare, &package);
    changed_binding.binding = TenantEvidenceBinding::GuestProvidedReportData {
        expected_vmpl: 0,
        expected_report_data: [0; 64],
    };
    assert_eq!(
        source.evidence(changed_binding),
        Err(TenantEvidenceError::InvalidState)
    );
    assert_eq!(verifier.calls.get(), 1);
}

#[test]
fn changed_operation_reference_or_expected_identity_cannot_promote_a_receipt() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let mut source = source(&verifier);
    let mut op = operation();
    op.request_id = HostRequestId::new(2);
    let wrong = PrepareMigrationRequestV1::new(op, prepare(&package, false).delivery().clone());
    assert_eq!(
        source.evidence(request(&wrong, &package)),
        Err(TenantEvidenceError::InvalidState)
    );
    let wrong = PrepareMigrationRequestV1::new(
        operation(),
        TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new([0; 48])),
    );
    assert_eq!(
        source.evidence(request(&wrong, &package)),
        Err(TenantEvidenceError::IdentityMismatch)
    );
    let id = VerifiedTenantIdentity::from_verified_report_id([8; 32]);
    let prepare = prepare(&package, false);
    let mut wrong = request(&prepare, &package);
    wrong.expected_identity = Some(&id);
    assert_eq!(
        source.evidence(wrong),
        Err(TenantEvidenceError::IdentityMismatch)
    );
    assert!(source.receipt.is_none());
}

#[test]
fn guest_binding_uses_independent_full_expectation_and_never_enters_active_v1_authorization() {
    let classification = TenantEvidenceBinding::GuestProvidedReportData {
        expected_vmpl: 2,
        expected_report_data: [0xa5; 64],
    };
    let package = package(classification);
    let verifier = verifier(&package);
    let mut source = source(&verifier);
    let prepare = prepare(&package, false);
    let mut input = request(&prepare, &package);
    input.binding = classification;
    let receipt = source.evidence(input).unwrap();
    assert_eq!(receipt.binding(), classification);
    assert_eq!(
        receipt.verified_delivery(),
        Err(TenantEvidenceError::UnsupportedBinding)
    );
    assert_eq!(source.firmware.calls.get(), 0);
    for byte in 0..64 {
        let mut expected = [0xa5; 64];
        expected[byte] ^= 1;
        let mut fresh = self::source(&verifier);
        let mut wrong = request(&prepare, &package);
        wrong.binding = TenantEvidenceBinding::GuestProvidedReportData {
            expected_vmpl: 2,
            expected_report_data: expected,
        };
        assert_eq!(
            fresh.evidence(wrong),
            Err(TenantEvidenceError::InvalidReport(
                SnpReportVerificationError::ReportDataMismatch
            ))
        );
        assert!(fresh.receipt.is_none());
    }
}

#[test]
fn host_zero_and_guest_vmpl_rules_are_not_interchangeable() {
    let package = package(TenantEvidenceBinding::GuestProvidedReportData {
        expected_vmpl: 1,
        expected_report_data: [1; 64],
    });
    let verifier = verifier(&package);
    let mut source = source(&verifier);
    let prepare = prepare(&package, false);
    assert!(source.evidence(request(&prepare, &package)).is_err());
    for vmpl in [4, u32::MAX] {
        let mut wrong = request(&prepare, &package);
        wrong.binding = TenantEvidenceBinding::GuestProvidedReportData {
            expected_vmpl: vmpl,
            expected_report_data: [1; 64],
        };
        assert_eq!(
            source.evidence(wrong),
            Err(TenantEvidenceError::UnsupportedBinding)
        );
    }
    assert!(source.receipt.is_none());
}

#[test]
fn every_backend_failure_is_explicit_and_never_cached_as_success() {
    use SnpReportVerificationError::*;
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let prepare = prepare(&package, false);
    let store = Store::new();
    let observed = store.clone();
    let mut source = source_with_store(&verifier, store);
    for error in [
        ProviderUnavailable,
        InvalidReportLength,
        UnsupportedReportVersion,
        MalformedReport,
        InvalidReservedBits,
        UnsupportedSigningKey,
        SignatureVerificationFailed,
        MissingCollateral,
        MalformedCollateral,
        CollateralTooLarge,
        CollateralTrustDomainMismatch,
        MissingRevocationCollateral,
        UntrustedCertificateChain,
        ExpiredCollateral,
        RevokedCollateral,
        InvalidVerificationTime,
        UnexpectedVmpl,
        ReportDataMismatch,
        InvalidTcbEncoding,
        InvalidEtcbEncoding,
        InvalidMitigationVector,
        InvalidSupplementLength,
        InvalidSupplementReservedBits,
        SupplementSignatureFailed,
        SupplementReportDigestMismatch,
        SupplementEtcbMismatch,
        InvalidSupplementMigrationData,
        FixtureEvidenceInProduction,
        UnsupportedVersion6Layout,
        ConflictingAbiLayout,
    ] {
        verifier.error.set(Some(error));
        assert_eq!(
            source.evidence(request(&prepare, &package)),
            Err(error.into())
        );
        assert!(source.receipt.is_none());
        assert_eq!(observed.loads.get(), 0);
        assert_eq!(observed.commits.get(), 0);
        assert_eq!(source.firmware.calls.get(), 0);
    }
    verifier.error.set(None);
    assert!(source.evidence(request(&prepare, &package)).is_ok());
}

#[test]
fn inconsistent_authenticated_output_cannot_mint_a_receipt() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let prepare = prepare(&package, false);
    for field in 0..15 {
        let mut verifier = verifier(&package);
        match field {
            0 => verifier.claims.provenance.trust_domain = SnpTrustDomain::ProductionAmd,
            1 => verifier.claims.provenance.report_sha384[0] ^= 1,
            2 => verifier.claims.provenance.supplement_sha384 = None,
            3 => verifier.claims.report_id[0] ^= 1,
            4 => verifier.claims.report_id_ma[0] ^= 1,
            5 => verifier.claims.current_etcb.raw[0] = 1,
            6 => verifier.claims.launch_etcb.raw[31] = 1,
            7 => verifier.claims.migration_data[0] = 1,
            8 => verifier.claims.migration_data_valid = true,
            9 => {
                verifier
                    .claims
                    .collateral_status
                    .verification_time_unix_seconds = 11
            }
            10 => verifier.claims.collateral_status.certificate_chain_sha384[0] ^= 1,
            11 => verifier.claims.collateral_status.leaf_certificate_sha384[0] ^= 1,
            12 => {
                verifier.claims.collateral_status.revocation =
                    SnpRevocationStatus::CheckedNotRevoked
            }
            13 => verifier.claims.signing_key_kind = SnpSigningKeyKind::Vlek,
            _ => {
                verifier.claims.current_tcb = AuthenticatedTcb::MilanGenoa {
                    boot_loader: 0,
                    tee: 0,
                    snp: 0,
                    microcode: 0,
                }
            }
        }
        let mut source = source(&verifier);
        assert!(
            source.evidence(request(&prepare, &package)).is_err(),
            "field {field}"
        );
        assert!(source.receipt.is_none());
    }
}

#[test]
fn malformed_supplement_is_rejected_even_when_backend_returns_success() {
    for field in 0..6 {
        let mut package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        if let SnpEvidenceInput::EmulatorV1(e) = &mut package.evidence {
            match field {
                0 => e.supplement[149] = 1,
                1 => e.supplement[148] = 2,
                2 => e.supplement[4] ^= 1,
                3 => e.supplement[52] = 1,
                4 => e.supplement[0] = 2,
                _ => {
                    e.report[0x48] |= 0x20;
                    e.supplement[4..52].copy_from_slice(&sha384(&e.report));
                }
            }
        }
        let verifier = verifier(&package);
        let mut source = source(&verifier);
        assert!(source
            .evidence(request(&prepare(&package, false), &package))
            .is_err());
        assert!(source.receipt.is_none());
    }
}

#[test]
fn collateral_package_is_canonical_bounded_and_matches_local_verification_input() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    for field in 0..5 {
        let mut set = package.collateral.clone();
        match field {
            0 => set.leaf_certificate.certificate_der.clear(),
            1 => set.leaf_certificate.certificate_der = vec![1; MAX_SNP_CERTIFICATE_SIZE + 1],
            2 => {
                set.leaf_certificate.certificate_der = vec![1; 3000];
                set.ask_certificate.certificate_der = vec![2; 2000];
            }
            3 => set.evidence_profile = SnpEvidenceProfileV1::Production,
            _ => set.tcb_profile = SnpTcbProfileV1::Turin,
        }
        assert!(TenantEvidencePackage::new(package.evidence.clone(), set).is_err());
    }
    let mut changed = package.clone();
    changed.collateral.leaf_certificate.certificate_der[0] = 9;
    let verifier = verifier(&package);
    assert!(source(&verifier)
        .evidence(request(&prepare(&changed, true), &changed))
        .is_err());
    assert_eq!(verifier.calls.get(), 0);
}

#[test]
fn unavailable_common_verifier_has_no_legacy_backend_fallback() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let decoded =
        TenantEvidencePackage::decode_host_package_v1(&package.encode_host_package_v1().unwrap())
            .unwrap();
    for reference in [false, true] {
        let store = Store::new();
        let observed = store.clone();
        let mut source = source_with_store(&UnavailableSnpReportVerifier, store);
        assert_eq!(
            source.evidence(request(&prepare(&decoded, reference), &decoded)),
            Err(TenantEvidenceError::ProviderUnavailable)
        );
        assert!(source.receipt.is_none());
        assert_eq!(observed.loads.get(), 0);
        assert_eq!(observed.commits.get(), 0);
        assert_eq!(source.firmware.calls.get(), 0);
    }
}

#[test]
fn host_package_codecs_are_exact_for_both_profiles_but_do_not_authenticate() {
    let fixture = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let mut collateral = fixture.collateral.clone();
    collateral.evidence_profile = SnpEvidenceProfileV1::Production;
    let raw = TenantEvidencePackage::new(
        SnpEvidenceInput::RawAmdReport {
            report: Box::new(*fixture.evidence.report()),
        },
        collateral,
    )
    .unwrap();
    for package in [fixture, raw] {
        let bytes = package.encode_host_package_v1().unwrap();
        assert_eq!(
            TenantEvidencePackage::decode_host_package_v1(&bytes),
            Ok(package)
        );
        for end in 0..bytes.len() {
            assert!(TenantEvidencePackage::decode_host_package_v1(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(TenantEvidencePackage::decode_host_package_v1(&trailing).is_err());
        for offset in 1..4 {
            let mut reserved = bytes.clone();
            reserved[offset] = 1;
            assert!(TenantEvidencePackage::decode_host_package_v1(&reserved).is_err());
        }
        for profile in [2, u8::MAX] {
            let mut invalid = bytes.clone();
            invalid[0] = profile;
            assert!(TenantEvidencePackage::decode_host_package_v1(&invalid).is_err());
        }
        let mut oversized = bytes;
        oversized[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(TenantEvidencePackage::decode_host_package_v1(&oversized).is_err());
    }
}

#[test]
fn every_etcb_byte_is_consistent_across_claims_supplement_and_base_report() {
    for component in 0..3 {
        for copy in 0..3 {
            for byte in 0..32 {
                let mut package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
                let SnpEvidenceInput::EmulatorV1(evidence) = &mut package.evidence else {
                    unreachable!();
                };
                let (supplement_start, report_start) =
                    [(52, 0x220), (84, 0x240), (116, 0x260)][component];
                match copy {
                    1 => evidence.supplement[supplement_start + byte] ^= 1,
                    2 => evidence.report[report_start + byte] ^= 1,
                    _ => {}
                }
                evidence.supplement[4..52].copy_from_slice(&sha384(&evidence.report));
                let mut verifier = verifier(&package);
                if copy == 0 {
                    let claims = &mut verifier.claims;
                    let etcb = match component {
                        0 => &mut claims.current_etcb,
                        1 => &mut claims.launch_etcb,
                        _ => &mut claims.committed_etcb,
                    };
                    etcb.raw[byte] ^= 1;
                }
                let expected = if copy == 0 && byte >= 14 {
                    SnpReportVerificationError::InvalidEtcbEncoding
                } else {
                    SnpReportVerificationError::SupplementEtcbMismatch
                };
                assert_rejected_before_effects(&package, &verifier, expected);
            }
        }
    }
}

#[test]
fn every_digest_byte_and_profile_is_checked_after_the_controlled_verifier() {
    for byte in 0..48 {
        let mut package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        if let SnpEvidenceInput::EmulatorV1(evidence) = &mut package.evidence {
            evidence.supplement[4 + byte] ^= 1;
        }
        let verifier = verifier(&package);
        assert_rejected_before_effects(
            &package,
            &verifier,
            SnpReportVerificationError::SupplementReportDigestMismatch,
        );
    }
    for digest in 0..2 {
        for byte in 0..48 {
            let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
            let mut verifier = verifier(&package);
            if digest == 0 {
                verifier.claims.provenance.report_sha384[byte] ^= 1;
            } else {
                verifier
                    .claims
                    .provenance
                    .supplement_sha384
                    .as_mut()
                    .unwrap()[byte] ^= 1;
            }
            assert_rejected_before_effects(
                &package,
                &verifier,
                SnpReportVerificationError::SupplementReportDigestMismatch,
            );
        }
    }
    for profile in [
        SnpEvidenceProfile::FirmwareAbi159V6,
        SnpEvidenceProfile::ArgAbi120MigrationOverlayV1,
    ] {
        let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        let mut verifier = verifier(&package);
        verifier.claims.provenance.evidence_profile = profile;
        assert_rejected_before_effects(
            &package,
            &verifier,
            SnpReportVerificationError::SupplementReportDigestMismatch,
        );
    }
}

#[test]
fn typed_policy_identity_consumes_common_claims_without_provider_branches() {
    use crate::snp::{ma_policy::MaPolicyIdentityInputV1, wire::SnpCodecError};

    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let mut claims = verifier(&package).claims;
    claims.measurement = [1; 48];
    claims.guest_svn = 0x1234;
    claims.family_id = [2; 16];
    claims.image_id = [3; 16];
    claims.id_key_digest = [4; 48];
    claims.author_key_digest = [5; 48];
    claims.host_data = [6; 32];
    claims.policy = 0x78;
    let expected = MaPolicyIdentityInputV1 {
        measurement: [1; 48],
        guest_svn: 0x1234,
        family_id: [2; 16],
        image_id: [3; 16],
        id_key_digest: [4; 48],
        author_key_digest: [5; 48],
        host_data: [6; 32],
        guest_policy: 0x78,
        lm_policy_digest: [7; 48],
    };
    for profile in [
        SnpEvidenceProfile::FirmwareAbi159V6,
        SnpEvidenceProfile::ArgAbi120MigrationOverlayV1,
        SnpEvidenceProfile::SnpEmulatorV1,
    ] {
        for trust in [SnpTrustDomain::Fixture, SnpTrustDomain::ProductionAmd] {
            claims.provenance.evidence_profile = profile;
            claims.provenance.trust_domain = trust;
            let identity =
                MaPolicyIdentityInputV1::from_authenticated_claims(&claims, [7; 48]).unwrap();
            assert_eq!(identity, expected);
            assert_eq!(
                identity.encode_exact().unwrap(),
                expected.encode_exact().unwrap()
            );
            assert_eq!(identity.digest().unwrap(), expected.digest().unwrap());
        }
    }
    for version in [0, 5, 7, u32::MAX] {
        claims.report_version = version;
        assert_eq!(
            MaPolicyIdentityInputV1::from_authenticated_claims(&claims, [7; 48]),
            Err(SnpCodecError::UnsupportedVersion)
        );
    }
}

#[test]
fn supplement_reserved_and_migration_data_bytes_cannot_mint_receipts() {
    for flag in 1..=u8::MAX {
        let mut package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        if let SnpEvidenceInput::EmulatorV1(evidence) = &mut package.evidence {
            evidence.supplement[148] = flag;
        }
        let verifier = verifier(&package);
        assert_rejected_before_effects(
            &package,
            &verifier,
            SnpReportVerificationError::InvalidSupplementMigrationData,
        );
    }
    {
        let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        let mut verifier = verifier(&package);
        verifier.claims.migration_data_valid = true;
        assert_rejected_before_effects(
            &package,
            &verifier,
            SnpReportVerificationError::InvalidSupplementMigrationData,
        );
    }
    for offset in (0..4).chain(149..156) {
        let mut package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        if let SnpEvidenceInput::EmulatorV1(evidence) = &mut package.evidence {
            evidence.supplement[offset] ^= 2;
        }
        let verifier = verifier(&package);
        assert_rejected_before_effects(
            &package,
            &verifier,
            SnpReportVerificationError::InvalidSupplementReservedBits,
        );
    }
    for copy in 0..3 {
        for byte in 0..64 {
            let mut package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
            if copy != 0 {
                if let SnpEvidenceInput::EmulatorV1(evidence) = &mut package.evidence {
                    evidence.supplement[156 + byte] ^= 1;
                }
            }
            let mut verifier = verifier(&package);
            if copy != 1 {
                verifier.claims.migration_data[byte] ^= 1;
            }
            assert_rejected_before_effects(
                &package,
                &verifier,
                SnpReportVerificationError::InvalidSupplementMigrationData,
            );
        }
    }
}

#[test]
fn all_host_report_data_bytes_must_be_zero() {
    for byte in 0..64 {
        let mut package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
        if let SnpEvidenceInput::EmulatorV1(evidence) = &mut package.evidence {
            evidence.report[0x50 + byte] = 1;
            evidence.supplement[4..52].copy_from_slice(&sha384(&evidence.report));
        }
        let verifier = verifier(&package);
        let mut source = source(&verifier);
        assert_eq!(
            source.evidence(request(&prepare(&package, false), &package)),
            Err(TenantEvidenceError::InvalidReport(
                SnpReportVerificationError::ReportDataMismatch
            ))
        );
        assert!(source.receipt.is_none());
    }
}

#[test]
fn composition_requires_bounded_collateral_time_revocation_and_store_capacity() {
    for field in 0..5 {
        let mut collateral = collateral();
        match field {
            0 => collateral.root_certificate_der.clear(),
            1 => collateral.root_certificate_der = vec![3; MAX_SNP_CERTIFICATE_SIZE + 1],
            2 => collateral.verification_time_unix_seconds = 0,
            3 => collateral.revocation = SnpRevocationInput::AmdCrlsDer(vec![]),
            _ => collateral.expected_trust_domain = SnpTrustDomain::ProductionAmd,
        }
        assert!(HostPushedTenantEvidenceSource::new(
            operation(),
            &UnavailableSnpReportVerifier,
            collateral,
            UnavailableTenantReplayStoreV1,
            UnavailableTenantFirmwareStateV1,
            4,
        )
        .is_err());
    }
    assert!(matches!(
        HostPushedTenantEvidenceSource::new(
            operation(),
            &UnavailableSnpReportVerifier,
            collateral(),
            UnavailableTenantReplayStoreV1,
            UnavailableTenantFirmwareStateV1,
            0,
        ),
        Err(TenantEvidenceError::Replay(
            TenantReplayErrorV1::InvalidCapacity
        ))
    ));
}

#[test]
fn hardware_rejects_fixture_guest_binding_and_unqualified_raw_layout() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let mut production = collateral();
    production.expected_trust_domain = SnpTrustDomain::ProductionAmd;
    production.revocation = SnpRevocationInput::AmdCrlsDer(vec![vec![4]]);
    let mut source = HostPushedTenantEvidenceSource::new(
        operation(),
        &verifier,
        production,
        UnavailableTenantReplayStoreV1,
        UnavailableTenantFirmwareStateV1,
        4,
    )
    .unwrap();
    let prepare = prepare(&package, true);
    assert_eq!(
        source.evidence(request(&prepare, &package)),
        Err(TenantEvidenceError::InvalidReport(
            SnpReportVerificationError::FixtureEvidenceInProduction
        ))
    );
    let mut guest = request(&prepare, &package);
    guest.binding = TenantEvidenceBinding::GuestProvidedReportData {
        expected_vmpl: 0,
        expected_report_data: [0; 64],
    };
    assert_eq!(
        source.evidence(guest),
        Err(TenantEvidenceError::UnsupportedBinding)
    );
    let mut set = package.collateral.clone();
    set.evidence_profile = SnpEvidenceProfileV1::Production;
    let raw = TenantEvidencePackage::new(
        SnpEvidenceInput::RawAmdReport {
            report: Box::new(*package.evidence.report()),
        },
        set,
    )
    .unwrap();
    assert_eq!(
        source.evidence(request(&prepare, &raw)),
        Err(TenantEvidenceError::InvalidReport(
            SnpReportVerificationError::ConflictingAbiLayout
        ))
    );
    assert_eq!(verifier.calls.get(), 0);
}

#[test]
fn proof_handoff_preserves_stage_order_firmware_checks_and_terminal_replay() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let mut source = source(&verifier);
    let prepare = prepare(&package, false);
    let binding = binding(source.evidence(request(&prepare, &package)).unwrap());
    let authorization = VerifiedTenantAuthorizationV1::from_verified_roles(binding.clone());
    assert_eq!(
        source.authorize_after_role_proofs(&authorization),
        Err(TenantEvidenceError::Replay(
            TenantReplayErrorV1::InvalidTransition
        ))
    );
    assert_eq!(
        source.reserve_after_ma_proofs(&binding),
        Ok(TenantReplayAdmissionV1::FirstReservation)
    );
    assert_eq!(
        source.reserve_after_ma_proofs(&binding),
        Ok(TenantReplayAdmissionV1::IdempotentRetry(
            TenantReplayStateV1::Reserved
        ))
    );
    assert_eq!(
        source.authorize_after_role_proofs(&authorization),
        Ok(TenantReplayAuthorizationV1::FirstAuthorization)
    );
    assert_eq!(source.firmware.calls.get(), 1);
    let result = ReplayTerminalResultV1 {
        outcome: ReplayTerminalOutcomeV1::Succeeded,
        result_digest: [0x99; 48],
    };
    source.finish(&binding, result).unwrap();
    assert_eq!(
        source.query(&binding),
        Ok(Some(TenantReplayStateV1::Terminal(result)))
    );
    assert_eq!(
        source.evidence(request(&prepare, &package)),
        Err(TenantEvidenceError::ReplayDetected(
            TenantReplayErrorV1::TerminalOperation
        ))
    );
    assert_eq!(
        source.reserve_after_ma_proofs(&binding),
        Err(TenantEvidenceError::ReplayDetected(
            TenantReplayErrorV1::TerminalOperation
        ))
    );
}

#[test]
fn replay_absence_and_current_firmware_failure_never_authorize() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let prepare = prepare(&package, false);
    let mut unavailable = HostPushedTenantEvidenceSource::new(
        operation(),
        &verifier,
        collateral(),
        UnavailableTenantReplayStoreV1,
        UnavailableTenantFirmwareStateV1,
        4,
    )
    .unwrap();
    let binding = binding(unavailable.evidence(request(&prepare, &package)).unwrap());
    assert_eq!(
        unavailable.reserve_after_ma_proofs(&binding),
        Err(TenantEvidenceError::ProductionReplayStateUnavailable)
    );
    let mut source = source(&verifier);
    source.evidence(request(&prepare, &package)).unwrap();
    source.reserve_after_ma_proofs(&binding).unwrap();
    source.firmware.error = Some(TenantReplayErrorV1::FirmwareStateUnavailable);
    assert_eq!(
        source.authorize_after_role_proofs(&VerifiedTenantAuthorizationV1::from_verified_roles(
            binding.clone()
        )),
        Err(TenantEvidenceError::Replay(
            TenantReplayErrorV1::FirmwareStateUnavailable
        ))
    );
    assert_eq!(
        source.query(&binding),
        Ok(Some(TenantReplayStateV1::Reserved))
    );
}

#[test]
fn replay_rollback_and_unrelated_bindings_are_rejected_without_new_reservation() {
    let package = package(TenantEvidenceBinding::HostRequestedZeroReportData);
    let verifier = verifier(&package);
    let store = Store::new();
    let snapshot = store.snapshot.clone();
    let mut source = source_with_store(&verifier, store);
    let receipt = source
        .evidence(request(&prepare(&package, false), &package))
        .unwrap()
        .clone();
    let wrong = VerifiedTenantReplayBindingV1::from_verified_context(
        receipt.verified_delivery().unwrap(),
        [0x66; 48],
        [0; 32],
        [0x77; 32],
    );
    assert_eq!(
        source.reserve_after_ma_proofs(&wrong),
        Err(TenantEvidenceError::IdentityMismatch)
    );
    let binding = binding(&receipt);
    source.reserve_after_ma_proofs(&binding).unwrap();
    *snapshot.borrow_mut() = TenantReplaySnapshotV1 {
        revision: 0,
        records: vec![],
    };
    assert_eq!(
        source.reserve_after_ma_proofs(&binding),
        Err(TenantEvidenceError::ReplayDetected(
            TenantReplayErrorV1::RollbackDetected
        ))
    );
}
