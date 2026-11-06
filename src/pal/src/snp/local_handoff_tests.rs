// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::snp::{
    local_handoff::*,
    purpose_binding::{
        CanonicalFirmwareResultSetV1, CanonicalTenantSetV1, FirmwareRebindResultV1,
        LocalHandoffBindingV1, SnpOperationStageV1, VerifiedTenantReportIdV1,
    },
};

fn ids() -> Vec<VerifiedTenantReportIdV1> {
    [0x11, 0x22]
        .iter()
        .map(|v| VerifiedTenantReportIdV1::from_verified_report_id([*v; 32]))
        .collect()
}

fn metadata() -> LocalMetadataSnapshotV1 {
    let mut history = [0; 64];
    history[0] = 1;
    history[1] = SnpTcbProfileV1::Venice as u8;
    history[32..].fill(0x33);
    LocalMetadataSnapshotV1 {
        tenants: ids()
            .iter()
            .map(|id| LocalTenantMetadataV1 {
                tenant_report_id: *id.as_bytes(),
                tenant_evidence_digest: [0x12; 48],
                migration_data_valid: true,
                migration_data: history,
                replay_snapshot_digest: [0x34; 48],
            })
            .collect(),
    }
}

fn binding(setup: &Setup, recovery: bool) -> LocalHandoffBindingV1 {
    let ids = ids();
    LocalHandoffBindingV1 {
        purpose: if recovery {
            SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization
        } else {
            SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization
        },
        stage: SnpOperationStageV1::PrepareAuthorization,
        attempt_number: 1,
        operation_id: [0x77; 16],
        request_id: 0x0102_0304_0506_0708,
        operation_epoch: 9,
        deadline_unix_seconds: 150,
        previous_ma_report_id: [0x55; 32],
        new_ma_report_id: [0x66; 32],
        tenant_set_digest: CanonicalTenantSetV1::new(2, &ids).unwrap().digest(),
        ma_policy_identity_digest: setup.selected,
        firmware_result_set_digest: [0; 48],
    }
}

fn results(success: [bool; 2]) -> Vec<FirmwareRebindResultV1> {
    ids()
        .iter()
        .zip(success)
        .map(|(id, success)| FirmwareRebindResultV1 {
            tenant_report_id: *id.as_bytes(),
            raw_status: if success { 0 } else { 0x16 },
            binding_changed: u8::from(success),
            previous_ma_report_id: [0x55; 32],
            resulting_ma_report_id: [if success { 0x66 } else { 0x55 }; 32],
        })
        .collect()
}

fn result_binding(
    prepare: &LocalHandoffBindingV1,
    results: &[FirmwareRebindResultV1],
) -> LocalHandoffBindingV1 {
    let ids = ids();
    let tenants = CanonicalTenantSetV1::new(2, &ids).unwrap();
    let set = CanonicalFirmwareResultSetV1::new(
        2,
        results,
        &tenants,
        prepare.previous_ma_report_id,
        prepare.new_ma_report_id,
    )
    .unwrap();
    let mut binding = prepare.clone();
    binding.stage = SnpOperationStageV1::FirmwareResultConfirmation;
    binding.firmware_result_set_digest = set.digest().unwrap();
    binding
}

fn approval(
    setup: &mut Setup,
    binding: &LocalHandoffBindingV1,
    role: SnpMaRoleV1,
    results: Option<&[FirmwareRebindResultV1]>,
) -> VerifiedMaPolicyCollateral {
    let ids = ids();
    let tenants = CanonicalTenantSetV1::new(2, &ids).unwrap();
    let result_set = results.map(|results| {
        CanonicalFirmwareResultSetV1::new(
            2,
            results,
            &tenants,
            binding.previous_ma_report_id,
            binding.new_ma_report_id,
        )
        .unwrap()
    });
    let recovery = binding.purpose == SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization;
    let mut context = setup.context.clone();
    context.evidence_purpose = binding.purpose;
    context.role = role;
    context.request_id = binding.request_id;
    context.algorithm = if recovery {
        SnpMigrationAlgorithmV1::None
    } else {
        SnpMigrationAlgorithmV1::LocalHandoffSecretV1
    };
    context.tenant_binding_id = [0; 32];
    context.th1 = if recovery { [0; 48] } else { [0x88; 48] };
    context.purpose_binding_digest = binding.digest(&tenants, result_set.as_ref()).unwrap();
    setup.rebind_context(context);
    setup.evidence.ma_report[0x140..0x160].copy_from_slice(if role == SnpMaRoleV1::Outgoing {
        &binding.previous_ma_report_id
    } else {
        &binding.new_ma_report_id
    });
    setup.verify(&mut TestStore::default()).unwrap()
}

struct FixtureAuthority {
    calls: usize,
    planned_session: bool,
    operation_authorized: bool,
    ready: bool,
    cleanup: bool,
    shutdown: bool,
    recovery_equivalent: bool,
    retry: bool,
    statuses: Vec<u32>,
    moved: Vec<bool>,
    history_change: Option<usize>,
    validity_change: bool,
    binding_change: bool,
    unavailable: bool,
}

impl FixtureAuthority {
    fn new() -> Self {
        Self {
            calls: 0,
            planned_session: true,
            operation_authorized: true,
            ready: true,
            cleanup: true,
            shutdown: true,
            recovery_equivalent: true,
            retry: false,
            statuses: vec![0x16; 2],
            moved: vec![false; 2],
            history_change: None,
            validity_change: false,
            binding_change: false,
            unavailable: false,
        }
    }
}

impl LocalHandoffAuthorityV1 for FixtureAuthority {
    fn verify_transition(
        &mut self,
        request: &LocalTransitionRequestV1<'_>,
        metadata: &LocalMetadataSnapshotV1,
    ) -> Result<Vec<CurrentLocalTenantStateV1>, LocalHandoffErrorV1> {
        self.calls += 1;
        if self.unavailable {
            return Err(LocalHandoffErrorV1::ProviderUnavailable);
        }
        let recovery =
            request.binding.purpose == SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization;
        if !self.operation_authorized
            || (!recovery && !self.planned_session)
            || (recovery && !self.recovery_equivalent)
            || (request.transition == LocalTransitionV1::Ready && !self.ready)
            || (matches!(
                request.transition,
                LocalTransitionV1::Abort | LocalTransitionV1::Finalize
            ) && !self.cleanup)
            || (request.transition == LocalTransitionV1::Finalize && !self.shutdown)
        {
            return Err(LocalHandoffErrorV1::ReconciliationRequired);
        }
        if request.transition == LocalTransitionV1::Retry
            && (!self.retry || self.statuses.iter().any(|s| *s != 0 && *s != 0x16))
        {
            return Err(LocalHandoffErrorV1::RetryDenied);
        }
        if request.transition == LocalTransitionV1::Results {
            self.statuses = request.results.iter().map(|r| r.raw_status).collect();
            self.moved = request.results.iter().map(|r| r.raw_status == 0).collect();
        }
        Ok(metadata
            .tenants
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let mut history = m.migration_data;
                if let Some(offset) = self.history_change {
                    history[offset] ^= 1;
                }
                CurrentLocalTenantStateV1 {
                    tenant_report_id: m.tenant_report_id,
                    bound_ma_report_id: if self.binding_change {
                        [0xff; 32]
                    } else if self.moved[i] {
                        request.binding.new_ma_report_id
                    } else {
                        request.binding.previous_ma_report_id
                    },
                    migration_data_valid: m.migration_data_valid ^ self.validity_change,
                    migration_data: history,
                }
            })
            .collect())
    }
}

fn planned(setup: &Setup, binding: &LocalHandoffBindingV1) -> PlannedHandoffContractV1 {
    PlannedHandoffContractV1::new(binding.clone(), metadata(), &ids(), &setup.policy).unwrap()
}

fn step(
    operation: &mut PlannedHandoffContractV1,
    setup: &mut Setup,
    transition: LocalTransitionV1,
    binding: &LocalHandoffBindingV1,
    results: &[FirmwareRebindResultV1],
    authority: &mut dyn LocalHandoffAuthorityV1,
) -> Result<(), LocalHandoffErrorV1> {
    let mut approvals = Vec::new();
    if matches!(
        transition,
        LocalTransitionV1::Prepare | LocalTransitionV1::Retry | LocalTransitionV1::Results
    ) {
        let outcomes = (transition == LocalTransitionV1::Results).then_some(results);
        approvals.push(approval(setup, binding, SnpMaRoleV1::Outgoing, outcomes));
        approvals.push(approval(setup, binding, SnpMaRoleV1::Incoming, outcomes));
    }
    let approvals: Vec<_> = approvals.iter().collect();
    operation.advance(
        &LocalTransitionRequestV1 {
            transition,
            binding,
            policy: &setup.policy,
            ma_approvals: &approvals,
            results,
        },
        100,
        authority,
    )
}

fn prepare_ready(
    setup: &mut Setup,
    binding: &LocalHandoffBindingV1,
    authority: &mut dyn LocalHandoffAuthorityV1,
) -> PlannedHandoffContractV1 {
    let mut operation = planned(setup, binding);
    step(
        &mut operation,
        setup,
        LocalTransitionV1::Prepare,
        binding,
        &[],
        authority,
    )
    .unwrap();
    step(
        &mut operation,
        setup,
        LocalTransitionV1::Ready,
        binding,
        &[],
        authority,
    )
    .unwrap();
    operation
}

#[test]
fn t412_binding_boundary_retains_frozen_contract_gates_and_never_fakes_effects() {
    use crate::{snp::binding_manager::*, types::ManagedGuestHandle};
    let mut setup = Setup::new();
    let binding = binding(&setup, false);
    let target = ManagedGuestHandle::new(17);
    let tenant = ids()[0].clone();
    let unready = planned(&setup, &binding);
    assert!(BindingRebindRequestV1::planned(&binding, target, &tenant, &unready).is_err());
    let mut authority = FixtureAuthority::new();
    let ready = prepare_ready(&mut setup, &binding, &mut authority);
    let request = BindingRebindRequestV1::planned(&binding, target, &tenant, &ready).unwrap();
    assert_eq!(request.mode(), LocalHandoffModeV1::Planned);
    assert!(request.still_ready());
    let wrong = VerifiedTenantReportIdV1::from_verified_report_id([99; 32]);
    assert!(BindingRebindRequestV1::planned(&binding, target, &wrong, &ready).is_err());
    let mut substituted = binding.clone();
    substituted.operation_epoch += 1;
    assert!(BindingRebindRequestV1::planned(&substituted, target, &tenant, &ready).is_err());
    let secret = [173; 32];
    let mut manager = UnavailableMaBindingManagerV1;
    for role in [SnpMaRoleV1::Outgoing, SnpMaRoleV1::Incoming] {
        let slot = BindingSecretRequestV1::new(&binding, target, role, &secret).unwrap();
        assert_eq!(slot.secret(), &secret);
        assert!(!format!("{slot:?}").contains("173"));
        let failure = manager.set_handoff_secret(&slot).unwrap_err();
        assert_eq!(&*failure.correlation, slot.correlation());
        assert_eq!(
            failure.effect,
            crate::snp::migration_install::MigrationInstallEffectV1::NotApplied
        );
        let mut clear = slot.correlation().clone();
        clear.operation = BindingOperationV1::ClearSecret;
        assert_eq!(
            manager.clear_handoff_secret(&clear).unwrap_err().failure,
            BindingFailureV1::Unavailable
        );
    }
    assert_eq!(
        manager.rebind_handoff(&request).unwrap_err().failure,
        BindingFailureV1::Unavailable
    );
    assert_eq!(
        manager.rebind_recovery(&request).unwrap_err().failure,
        BindingFailureV1::Unavailable
    );
    let mut query = request.correlation().clone();
    query.operation = BindingOperationV1::Query;
    assert_eq!(
        manager.query_binding(&query).unwrap_err().failure,
        BindingFailureV1::Unavailable
    );
    let failed = BindingCompletionV1::from_firmware_status(request.correlation(), 9).unwrap_err();
    assert_eq!(failed.raw_firmware_status, Some(9));
    assert_eq!(
        failed.effect,
        crate::snp::migration_install::MigrationInstallEffectV1::Unknown
    );
    assert_eq!(
        BindingCompletionV1::from_firmware_status(request.correlation(), 0)
            .unwrap()
            .correlation(),
        request.correlation()
    );
}

#[test]
fn all_twelve_control_records_round_trip_in_an_isolated_local_namespace() {
    let setup = Setup::new();
    use LocalControlKindV1::*;
    for kind in [
        PrepareMaHandoffRequest,
        MaHandoffReady,
        MaRebindResult,
        ConfirmRebindResult,
        FinalizeMaHandoff,
        AbortMaHandoff,
        QueryMaHandoffStatus,
        RetryMaRebind,
        PrepareMaRecoveryRequest,
        MaRecoveryReady,
        ConfirmRecoveryResult,
        FinalizeMaRecovery,
    ] {
        let recovery = matches!(
            kind,
            PrepareMaRecoveryRequest | MaRecoveryReady | ConfirmRecoveryResult | FinalizeMaRecovery
        );
        let mut b = binding(&setup, recovery);
        if matches!(
            kind,
            MaRebindResult
                | ConfirmRebindResult
                | FinalizeMaHandoff
                | ConfirmRecoveryResult
                | FinalizeMaRecovery
        ) {
            b = result_binding(&b, &results([true, true]));
        }
        let record = LocalMaControlV1 {
            kind,
            mode: if recovery {
                LocalHandoffModeV1::Recovery
            } else {
                LocalHandoffModeV1::Planned
            },
            role: if recovery {
                SnpMaRoleV1::Incoming
            } else {
                SnpMaRoleV1::Outgoing
            },
            phase: LocalHandoffPhaseV1::Prepared,
            status: LocalControlStatusV1::Pending,
            previous_ma_handle: 1,
            new_ma_handle: 2,
            tenant_handle: 3,
            binding: b,
            result: (kind == MaRebindResult).then(|| results([true, true])[0].clone()),
        };
        let bytes = record.encode_exact().unwrap();
        assert_eq!(LocalMaControlV1::decode_exact(&bytes).unwrap(), record);
        for n in 0..bytes.len() {
            assert!(LocalMaControlV1::decode_exact(&bytes[..n]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(LocalMaControlV1::decode_exact(&trailing).is_err());
        for offset in [0, 8, 9, 10, 11, 12, 16, 17, 18, 19, 20, 21, 22, 23] {
            let mut bad = bytes.clone();
            bad[offset] = 0xff;
            assert!(
                LocalMaControlV1::decode_exact(&bad).is_err(),
                "{kind:?}/{offset}"
            );
        }
    }
}

#[test]
fn control_rejects_recovery_outgoing_cross_mode_and_result_fabrication() {
    let setup = Setup::new();
    let mut c = LocalMaControlV1 {
        kind: LocalControlKindV1::PrepareMaRecoveryRequest,
        mode: LocalHandoffModeV1::Recovery,
        role: SnpMaRoleV1::Outgoing,
        phase: LocalHandoffPhaseV1::Prepared,
        status: LocalControlStatusV1::Pending,
        previous_ma_handle: 1,
        new_ma_handle: 2,
        tenant_handle: 3,
        binding: binding(&setup, true),
        result: None,
    };
    assert!(c.encode_exact().is_err());
    c.role = SnpMaRoleV1::Incoming;
    c.mode = LocalHandoffModeV1::Planned;
    assert!(c.encode_exact().is_err());
    c.mode = LocalHandoffModeV1::Recovery;
    c.result = Some(results([true, true])[0].clone());
    assert!(c.encode_exact().is_err());
    c.kind = LocalControlKindV1::MaRebindResult;
    c.binding = result_binding(&c.binding, &results([true, true]));
    c.result.as_mut().unwrap().binding_changed = 0;
    assert!(c.encode_exact().is_err());
}

#[test]
fn metadata_is_bounded_sorted_strict_and_keeps_all_history_bytes() {
    let m = metadata();
    let bytes = m.encode_exact().unwrap();
    assert_eq!(LocalMetadataSnapshotV1::decode_exact(&bytes).unwrap(), m);
    for n in 0..bytes.len() {
        assert!(LocalMetadataSnapshotV1::decode_exact(&bytes[..n]).is_err());
    }
    for offset in [0, 8, 10, 12, 16, 100, 101, 102, 107] {
        let mut bad = bytes.clone();
        bad[offset] = 0xff;
        assert!(
            LocalMetadataSnapshotV1::decode_exact(&bad).is_err(),
            "{offset}"
        );
    }
    let mut bad = m.clone();
    bad.tenants.swap(0, 1);
    assert!(bad.encode_exact().is_err());
    bad.tenants[1] = bad.tenants[0].clone();
    assert!(bad.encode_exact().is_err());
    bad.tenants.clear();
    assert!(bad.encode_exact().is_err());
    let mut max = m.clone();
    max.tenants = (0..32)
        .map(|i| {
            let mut t = m.tenants[0].clone();
            t.tenant_report_id = [i; 32];
            t
        })
        .collect();
    assert_eq!(
        max.encode_exact().unwrap().len(),
        LocalMetadataSnapshotV1::MAX_ENCODED_SIZE
    );
    assert!(LocalMetadataSnapshotV1::decode_exact(&max.encode_exact().unwrap()).is_ok());
    max.tenants.push(m.tenants[0].clone());
    assert!(max.encode_exact().is_err());
    bad = m.clone();
    bad.tenants[0].migration_data_valid = false;
    assert!(bad.encode_exact().is_err());
    bad.tenants[0].migration_data = [0; 64];
    assert!(bad.encode_exact().is_ok());
}

#[test]
fn independent_control_and_metadata_vectors_match() {
    let setup = Setup::new();
    let record = LocalMaControlV1 {
        kind: LocalControlKindV1::PrepareMaHandoffRequest,
        mode: LocalHandoffModeV1::Planned,
        role: SnpMaRoleV1::Outgoing,
        phase: LocalHandoffPhaseV1::Prepared,
        status: LocalControlStatusV1::Pending,
        previous_ma_handle: 1,
        new_ma_handle: 2,
        tenant_handle: 3,
        binding: binding(&setup, false),
        result: None,
    };
    assert_eq!(record.encode_exact().unwrap().len(), 329);
    assert_eq!(hex(&sha384(&record.encode_exact().unwrap())),"d9043c8a029433f673047de7724b28c0d82179884d62af20c653e4c56074b9b130b1c8aa5a3f8a9f1c3a1311e22f8794");
    assert_eq!(hex(&metadata().digest().unwrap()),"a07af590a49c8dd43c27e51658d61ab82ee9fde88516ce12dd667062bbcb79a65e5936804820069582a3b91a85c2d026");
}

#[test]
fn planned_handoff_requires_each_gate_and_only_finishes_after_results_cleanup_and_shutdown() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut authority = FixtureAuthority::new();
    let mut op = planned(&setup, &b);
    assert!(step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Ready,
        &b,
        &[],
        &mut authority
    )
    .is_err());
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Prepare,
        &b,
        &[],
        &mut authority,
    )
    .unwrap();
    let calls = authority.calls;
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Prepare,
        &b,
        &[],
        &mut authority,
    )
    .unwrap();
    assert_eq!(authority.calls, calls + 1);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Ready,
        &b,
        &[],
        &mut authority,
    )
    .unwrap();
    assert!(step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Finalize,
        &b,
        &[],
        &mut authority
    )
    .is_err());
    let outcomes = results([true, true]);
    let confirmed = result_binding(&b, &outcomes);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Results,
        &confirmed,
        &outcomes,
        &mut authority,
    )
    .unwrap();
    assert_eq!(op.phase(), LocalHandoffPhaseV1::Confirmed);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Finalize,
        &confirmed,
        &[],
        &mut authority,
    )
    .unwrap();
    assert_eq!(op.phase(), LocalHandoffPhaseV1::Complete);
    assert!(step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Abort,
        &confirmed,
        &[],
        &mut authority
    )
    .is_err());
}

#[test]
fn partial_success_preserves_split_ownership_and_requires_explicit_retry_appraisal() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut a = FixtureAuthority::new();
    let mut op = prepare_ready(&mut setup, &b, &mut a);
    let outcomes = results([true, false]);
    let confirmed = result_binding(&b, &outcomes);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Results,
        &confirmed,
        &outcomes,
        &mut a,
    )
    .unwrap();
    assert_eq!(op.phase(), LocalHandoffPhaseV1::Partial);
    assert_eq!(a.moved, [true, false]);
    assert!(step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Finalize,
        &confirmed,
        &[],
        &mut a
    )
    .is_err());
    let mut next = b.clone();
    next.attempt_number = 2;
    a.retry = true;
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Retry,
        &next,
        &[],
        &mut a,
    )
    .unwrap();
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Ready,
        &next,
        &[],
        &mut a,
    )
    .unwrap();
    let bad = results([false, true]);
    let bad_binding = result_binding(&next, &bad);
    assert_eq!(
        step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Results,
            &bad_binding,
            &bad,
            &mut a
        ),
        Err(LocalHandoffErrorV1::BindingMismatch)
    );
    let good = results([true, true]);
    let final_binding = result_binding(&next, &good);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Results,
        &final_binding,
        &good,
        &mut a,
    )
    .unwrap();
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Finalize,
        &final_binding,
        &[],
        &mut a,
    )
    .unwrap();
    assert_eq!(op.phase(), LocalHandoffPhaseV1::Complete);
}

#[test]
fn unknown_status_retry_and_nonincrementing_attempts_fail_closed() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut a = FixtureAuthority::new();
    let mut op = prepare_ready(&mut setup, &b, &mut a);
    let mut outcomes = results([true, false]);
    outcomes[1].raw_status = 0xffff;
    let confirmed = result_binding(&b, &outcomes);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Results,
        &confirmed,
        &outcomes,
        &mut a,
    )
    .unwrap();
    assert!(step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Retry,
        &b,
        &[],
        &mut a
    )
    .is_err());
    let mut next = b.clone();
    next.attempt_number = 2;
    a.retry = true;
    assert_eq!(
        step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Retry,
            &next,
            &[],
            &mut a
        ),
        Err(LocalHandoffErrorV1::RetryDenied)
    );
    assert_eq!(op.phase(), LocalHandoffPhaseV1::ReconciliationRequired);
}

#[test]
fn every_history_byte_validity_and_current_binding_are_rechecked() {
    for offset in 0..66 {
        let mut setup = Setup::new();
        let b = binding(&setup, false);
        let mut a = FixtureAuthority::new();
        let mut op = prepare_ready(&mut setup, &b, &mut a);
        if offset < 64 {
            a.history_change = Some(offset)
        } else if offset == 64 {
            a.validity_change = true
        } else {
            a.binding_change = true
        }
        let outcomes = results([true, true]);
        let confirmed = result_binding(&b, &outcomes);
        assert!(
            step(
                &mut op,
                &mut setup,
                LocalTransitionV1::Results,
                &confirmed,
                &outcomes,
                &mut a
            )
            .is_err(),
            "{offset}"
        );
        assert_eq!(op.phase(), LocalHandoffPhaseV1::ReconciliationRequired);
    }
}

#[test]
fn operation_authority_session_readiness_cleanup_and_shutdown_are_not_host_flags() {
    for field in 0..5 {
        let mut setup = Setup::new();
        let b = binding(&setup, false);
        let mut a = FixtureAuthority::new();
        let mut op = planned(&setup, &b);
        if field == 0 {
            a.operation_authorized = false
        }
        if field == 1 {
            a.planned_session = false
        }
        if field < 2 {
            assert!(step(
                &mut op,
                &mut setup,
                LocalTransitionV1::Prepare,
                &b,
                &[],
                &mut a
            )
            .is_err());
            continue;
        }
        step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Prepare,
            &b,
            &[],
            &mut a,
        )
        .unwrap();
        if field == 2 {
            a.ready = false;
            assert!(step(
                &mut op,
                &mut setup,
                LocalTransitionV1::Ready,
                &b,
                &[],
                &mut a
            )
            .is_err());
            continue;
        }
        step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Ready,
            &b,
            &[],
            &mut a,
        )
        .unwrap();
        let outcomes = results([true, true]);
        let confirmed = result_binding(&b, &outcomes);
        step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Results,
            &confirmed,
            &outcomes,
            &mut a,
        )
        .unwrap();
        if field == 3 {
            a.cleanup = false
        } else {
            a.shutdown = false
        }
        assert!(step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Finalize,
            &confirmed,
            &[],
            &mut a
        )
        .is_err());
        assert_eq!(op.phase(), LocalHandoffPhaseV1::ReconciliationRequired);
    }
}

#[test]
fn expired_operation_still_permits_gated_abort_and_cleanup_not_success() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut a = FixtureAuthority::new();
    let mut op = prepare_ready(&mut setup, &b, &mut a);
    let req = LocalTransitionRequestV1 {
        transition: LocalTransitionV1::Finalize,
        binding: &b,
        policy: &setup.policy,
        ma_approvals: &[],
        results: &[],
    };
    assert_eq!(
        op.advance(&req, 150, &mut a),
        Err(LocalHandoffErrorV1::Expired)
    );
    let req = LocalTransitionRequestV1 {
        transition: LocalTransitionV1::Abort,
        ..req
    };
    op.advance(&req, 150, &mut a).unwrap();
    assert_eq!(op.phase(), LocalHandoffPhaseV1::Aborted);
}

#[test]
fn recovery_is_incoming_only_without_spdm_or_secret_and_checks_firmware_equivalence() {
    for equivalent in [false, true] {
        let mut setup = Setup::new();
        let b = binding(&setup, true);
        let mut op = RecoveryContractV1::new(b.clone(), metadata(), &ids(), &setup.policy).unwrap();
        let mut a = FixtureAuthority::new();
        a.planned_session = false;
        a.recovery_equivalent = equivalent;
        let incoming = approval(&mut setup, &b, SnpMaRoleV1::Incoming, None);
        let approvals = [&incoming];
        let req = LocalTransitionRequestV1 {
            transition: LocalTransitionV1::Prepare,
            binding: &b,
            policy: &setup.policy,
            ma_approvals: &approvals,
            results: &[],
        };
        assert_eq!(op.advance(&req, 100, &mut a).is_ok(), equivalent);
        if !equivalent {
            continue;
        }
        op.advance(
            &LocalTransitionRequestV1 {
                transition: LocalTransitionV1::Ready,
                ma_approvals: &[],
                ..req
            },
            100,
            &mut a,
        )
        .unwrap();
        let outcomes = results([true, true]);
        let confirmed = result_binding(&b, &outcomes);
        let incoming = approval(
            &mut setup,
            &confirmed,
            SnpMaRoleV1::Incoming,
            Some(&outcomes),
        );
        op.advance(
            &LocalTransitionRequestV1 {
                transition: LocalTransitionV1::Results,
                binding: &confirmed,
                policy: &setup.policy,
                ma_approvals: &[&incoming],
                results: &outcomes,
            },
            100,
            &mut a,
        )
        .unwrap();
        op.advance(
            &LocalTransitionRequestV1 {
                transition: LocalTransitionV1::Finalize,
                binding: &confirmed,
                policy: &setup.policy,
                ma_approvals: &[],
                results: &[],
            },
            100,
            &mut a,
        )
        .unwrap();
        assert_eq!(op.phase(), LocalHandoffPhaseV1::Complete);
    }
}

#[test]
fn missing_transition_provider_never_creates_readiness() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut op = planned(&setup, &b);
    assert_eq!(
        step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Prepare,
            &b,
            &[],
            &mut UnavailableLocalHandoffServicesV1
        ),
        Err(LocalHandoffErrorV1::ProviderUnavailable)
    );
    assert_eq!(op.phase(), LocalHandoffPhaseV1::ReconciliationRequired);
    let mut op = planned(&setup, &b);
    let mut authority = FixtureAuthority::new();
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Prepare,
        &b,
        &[],
        &mut authority,
    )
    .unwrap();
    authority.unavailable = true;
    assert_eq!(
        step(
            &mut op,
            &mut setup,
            LocalTransitionV1::Prepare,
            &b,
            &[],
            &mut authority
        ),
        Err(LocalHandoffErrorV1::ProviderUnavailable)
    );
    assert_eq!(authority.calls, 2);
    assert_eq!(op.phase(), LocalHandoffPhaseV1::ReconciliationRequired);
}

fn prepared_for_random_services() -> PlannedHandoffContractV1 {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut authority = FixtureAuthority::new();
    let mut op = planned(&setup, &b);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Prepare,
        &b,
        &[],
        &mut authority,
    )
    .unwrap();
    op
}

#[test]
fn shared_service_draws_independent_msk_and_handoff_without_retry_draws() {
    use crate::random::{DeterministicRandomSource, RandomSource};
    use crate::snp::direct_key::MigrationKeyV2;
    use crate::types::MigrationRole;

    let mut source = DeterministicRandomSource::new(vec![[0x31; 32], [0x72; 32]]);
    let context = crate::snp::direct_exchange::tests::context(MigrationRole::Source, 17);
    let key = MigrationKeyV2::generate(&context, &mut source).unwrap();
    let first = key.encode_delivery().unwrap();
    assert_eq!(key.encode_delivery().unwrap(), first);
    assert_eq!(key.for_installation(&context).unwrap(), &[0x31; 32]);
    key.clear();
    let prepared = prepared_for_random_services();
    let random: &mut dyn RandomSource = &mut source;
    let handoff = HandoffSecretV1::generate(&prepared, random).unwrap();
    assert_eq!(format!("{handoff:?}"), "HandoffSecretV1(<redacted>)");
    let mut sink = FixtureSecretSink::default();
    handoff.install(&mut sink).unwrap();
    assert_eq!(sink.installed, Some([0x72; 32]));
    assert_eq!(sink.cleared, 0);
    assert_eq!(source.calls, 2);
}

#[test]
fn shared_partial_failure_never_returns_migration_or_handoff_owner() {
    use crate::random::{RandomError, RandomSource};
    use crate::snp::direct_key::{DirectKeyErrorV2, MigrationKeyV2};
    use crate::types::MigrationRole;

    struct PartialFailure(usize);
    impl RandomSource for PartialFailure {
        fn fill_random32(&mut self, bytes: &mut [u8; 32]) -> Result<(), RandomError> {
            bytes[..self.0].fill(0x42);
            Err(RandomError::Unavailable)
        }
    }
    let context = crate::snp::direct_exchange::tests::context(MigrationRole::Source, 17);
    let prepared = prepared_for_random_services();
    for prefix in 0..=32 {
        let mut source = PartialFailure(prefix);
        assert!(matches!(
            MigrationKeyV2::generate(&context, &mut source),
            Err(DirectKeyErrorV2::RandomnessUnavailable)
        ));
        assert!(matches!(
            HandoffSecretV1::generate(&prepared, &mut source),
            Err(LocalHandoffErrorV1::RandomnessUnavailable)
        ));
    }
}

#[test]
fn rejected_generation_does_not_consume_randomness() {
    use crate::random::DeterministicRandomSource;
    use crate::snp::direct_key::{DirectKeyErrorV2, MigrationKeyV2};
    use crate::types::MigrationRole;

    let mut source = DeterministicRandomSource::new(vec![[0x42; 32]]);
    let destination = crate::snp::direct_exchange::tests::context(MigrationRole::Destination, 17);
    assert!(matches!(
        MigrationKeyV2::generate(&destination, &mut source),
        Err(DirectKeyErrorV2::WrongRole)
    ));
    let setup = Setup::new();
    let op = planned(&setup, &binding(&setup, false));
    assert!(matches!(
        HandoffSecretV1::generate(&op, &mut source),
        Err(LocalHandoffErrorV1::InvalidTransition)
    ));
    assert_eq!(source.calls, 0);
}

#[test]
fn handoff_install_unwind_attempts_slot_cleanup_once() {
    struct PanickingSink(FixtureSecretSink);
    impl ProtectedHandoffSecretProviderV1 for PanickingSink {
        fn install_and_transfer(
            &mut self,
            _: &LocalHandoffBindingV1,
            secret: &[u8; 32],
        ) -> Result<(), LocalHandoffErrorV1> {
            self.0.installed = Some(*secret);
            panic!("test partial installation panic");
        }
        fn clear_both(
            &mut self,
            binding: &LocalHandoffBindingV1,
        ) -> Result<(), LocalHandoffErrorV1> {
            self.0.clear_both(binding)
        }
    }
    let prepared = prepared_for_random_services();
    for clear_fail in [false, true] {
        let secret = HandoffSecretV1::generate(&prepared, &mut FixtureRandom).unwrap();
        let mut sink = PanickingSink(FixtureSecretSink {
            clear_fail,
            ..Default::default()
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = secret.install(&mut sink);
        }));
        assert!(result.is_err());
        assert_eq!(sink.0.cleared, 1);
        assert_eq!(sink.0.installed, None);
    }
}

struct FixtureRandom;
impl HandoffRandomSourceV1 for FixtureRandom {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), LocalHandoffErrorV1> {
        output.fill(0x42);
        Ok(())
    }
}

#[derive(Default)]
struct FixtureSecretSink {
    installed: Option<[u8; 32]>,
    fail: bool,
    clear_fail: bool,
    cleared: usize,
}
impl ProtectedHandoffSecretProviderV1 for FixtureSecretSink {
    fn install_and_transfer(
        &mut self,
        _: &LocalHandoffBindingV1,
        s: &[u8; 32],
    ) -> Result<(), LocalHandoffErrorV1> {
        self.installed = Some(*s);
        if self.fail {
            Err(LocalHandoffErrorV1::SecretProviderUnavailable)
        } else {
            Ok(())
        }
    }
    fn clear_both(&mut self, _: &LocalHandoffBindingV1) -> Result<(), LocalHandoffErrorV1> {
        self.cleared += 1;
        self.installed = None;
        if self.clear_fail {
            Err(LocalHandoffErrorV1::ReconciliationRequired)
        } else {
            Ok(())
        }
    }
}

#[test]
fn handoff_secret_is_exact_direct_random32_and_never_uses_host_codec() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut a = FixtureAuthority::new();
    let mut op = planned(&setup, &b);
    assert!(HandoffSecretV1::generate(&op, &mut FixtureRandom).is_err());
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Prepare,
        &b,
        &[],
        &mut a,
    )
    .unwrap();
    let secret = HandoffSecretV1::generate(&op, &mut FixtureRandom).unwrap();
    assert_eq!(format!("{secret:?}"), "HandoffSecretV1(<redacted>)");
    let mut sink = FixtureSecretSink::default();
    secret.install(&mut sink).unwrap();
    assert_eq!(sink.installed.unwrap(), [0x42; 32]);
    assert!(HandoffSecretV1::generate(&op, &mut UnavailableLocalHandoffServicesV1).is_err());
}

#[test]
fn failed_secret_install_attempts_cleanup_and_propagates_cleanup_failure() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut a = FixtureAuthority::new();
    let mut op = planned(&setup, &b);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Prepare,
        &b,
        &[],
        &mut a,
    )
    .unwrap();
    for clear_fail in [false, true] {
        let secret = HandoffSecretV1::generate(&op, &mut FixtureRandom).unwrap();
        let mut sink = FixtureSecretSink {
            fail: true,
            clear_fail,
            ..Default::default()
        };
        assert_eq!(
            secret.install(&mut sink),
            Err(if clear_fail {
                LocalHandoffErrorV1::ReconciliationRequired
            } else {
                LocalHandoffErrorV1::SecretProviderUnavailable
            })
        );
        assert_eq!(sink.cleared, 1);
        assert!(sink.installed.is_none());
    }
}

#[test]
fn operation_binding_substitutions_never_reach_the_trusted_transition_provider() {
    for field in 0..9 {
        let mut setup = Setup::new();
        let b = binding(&setup, false);
        let mut operation = planned(&setup, &b);
        let outgoing = approval(&mut setup, &b, SnpMaRoleV1::Outgoing, None);
        let incoming = approval(&mut setup, &b, SnpMaRoleV1::Incoming, None);
        let mut substituted = b.clone();
        match field {
            0 => substituted.operation_id[0] ^= 1,
            1 => substituted.request_id ^= 1,
            2 => substituted.operation_epoch ^= 1,
            3 => substituted.deadline_unix_seconds += 1,
            4 => substituted.attempt_number += 1,
            5 => substituted.previous_ma_report_id[0] ^= 1,
            6 => substituted.new_ma_report_id[0] ^= 1,
            7 => substituted.tenant_set_digest[0] ^= 1,
            _ => substituted.ma_policy_identity_digest[0] ^= 1,
        }
        let mut authority = FixtureAuthority::new();
        assert!(
            operation
                .advance(
                    &LocalTransitionRequestV1 {
                        transition: LocalTransitionV1::Prepare,
                        binding: &substituted,
                        policy: &setup.policy,
                        ma_approvals: &[&outgoing, &incoming],
                        results: &[],
                    },
                    100,
                    &mut authority
                )
                .is_err(),
            "{field}"
        );
        assert_eq!(authority.calls, 0);
    }
}

#[test]
fn recovery_rejects_multiple_proofs_and_planned_binding() {
    let mut setup = Setup::new();
    let b = binding(&setup, true);
    assert!(
        RecoveryContractV1::new(binding(&setup, false), metadata(), &ids(), &setup.policy,)
            .is_err()
    );
    let mut recovery =
        RecoveryContractV1::new(b.clone(), metadata(), &ids(), &setup.policy).unwrap();
    let incoming = approval(&mut setup, &b, SnpMaRoleV1::Incoming, None);
    let mut authority = FixtureAuthority::new();
    assert!(recovery
        .advance(
            &LocalTransitionRequestV1 {
                transition: LocalTransitionV1::Prepare,
                binding: &b,
                policy: &setup.policy,
                ma_approvals: &[&incoming, &incoming],
                results: &[],
            },
            100,
            &mut authority
        )
        .is_err());
    assert_eq!(authority.calls, 0);
}

#[test]
fn retries_cannot_regenerate_the_operation_secret_and_metadata_debug_is_redacted() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut a = FixtureAuthority::new();
    let mut op = prepare_ready(&mut setup, &b, &mut a);
    let outcomes = results([true, false]);
    let confirmed = result_binding(&b, &outcomes);
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Results,
        &confirmed,
        &outcomes,
        &mut a,
    )
    .unwrap();
    let mut next = b.clone();
    next.attempt_number = 2;
    a.retry = true;
    step(
        &mut op,
        &mut setup,
        LocalTransitionV1::Retry,
        &next,
        &[],
        &mut a,
    )
    .unwrap();
    assert!(HandoffSecretV1::generate(&op, &mut FixtureRandom).is_err());
    assert_eq!(
        format!("{:?}", metadata().tenants[0]),
        "LocalTenantMetadataV1(<protected>)"
    );
}

#[test]
fn results_require_fresh_stage_approvals_and_exact_complete_tenant_coverage() {
    let mut setup = Setup::new();
    let b = binding(&setup, false);
    let mut a = FixtureAuthority::new();
    let mut op = prepare_ready(&mut setup, &b, &mut a);
    let outcomes = results([true, true]);
    let confirmed = result_binding(&b, &outcomes);
    let outgoing = approval(&mut setup, &b, SnpMaRoleV1::Outgoing, None);
    let incoming = approval(&mut setup, &b, SnpMaRoleV1::Incoming, None);
    assert!(op
        .advance(
            &LocalTransitionRequestV1 {
                transition: LocalTransitionV1::Results,
                binding: &confirmed,
                policy: &setup.policy,
                ma_approvals: &[&outgoing, &incoming],
                results: &outcomes,
            },
            100,
            &mut a
        )
        .is_err());
    let outgoing = approval(
        &mut setup,
        &confirmed,
        SnpMaRoleV1::Outgoing,
        Some(&outcomes),
    );
    let incoming = approval(
        &mut setup,
        &confirmed,
        SnpMaRoleV1::Incoming,
        Some(&outcomes),
    );
    let mut reversed = outcomes.clone();
    reversed.reverse();
    let mut unrelated = outcomes.clone();
    unrelated[0].tenant_report_id = [0xff; 32];
    for incomplete in [vec![], outcomes[..1].to_vec(), reversed, unrelated] {
        assert!(op
            .advance(
                &LocalTransitionRequestV1 {
                    transition: LocalTransitionV1::Results,
                    binding: &confirmed,
                    policy: &setup.policy,
                    ma_approvals: &[&outgoing, &incoming],
                    results: &incomplete,
                },
                100,
                &mut a
            )
            .is_err());
    }
    let substituted_session: Vec<_> = [SnpMaRoleV1::Outgoing, SnpMaRoleV1::Incoming]
        .iter()
        .map(|role| {
            approval(&mut setup, &confirmed, *role, Some(&outcomes));
            let mut context = setup.context.clone();
            context.th1 = [0x99; 48];
            setup.rebind_context(context);
            setup.verify(&mut TestStore::default()).unwrap()
        })
        .collect();
    assert_eq!(
        op.advance(
            &LocalTransitionRequestV1 {
                transition: LocalTransitionV1::Results,
                binding: &confirmed,
                policy: &setup.policy,
                ma_approvals: &[&substituted_session[0], &substituted_session[1]],
                results: &outcomes,
            },
            100,
            &mut a
        ),
        Err(LocalHandoffErrorV1::ContextMismatch)
    );
    assert_eq!(op.phase(), LocalHandoffPhaseV1::Ready);
}
