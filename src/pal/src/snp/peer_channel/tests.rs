// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::{
    snp::{
        authorization_result::{
            SnpAuthorizationDecisionV1, SnpAuthorizationFailureV1, SnpAuthorizationResultV1,
        },
        direct_exchange::{
            InstallExchangeSequenceV2, InstallSessionControlKindV2, InstallSessionControlV2,
        },
        direct_key::{MigrationSessionContextV2, SnpSessionReferenceV2},
        local_handoff::{LocalMetadataSnapshotV1, LocalTenantMetadataV1},
        peer_channel::*,
        purpose_binding::{LocalHandoffBindingV1, SnpOperationStageV1},
        tenant_evidence::SnpTenantEvidenceV1,
        tenant_policy_context::TenantPolicyContextV1,
    },
    types::{HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, SnpOperationContext},
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Clock(Rc<Cell<u64>>, Rc<Cell<bool>>);
impl PeerClockV1 for Clock {
    fn unix_seconds(&self) -> Result<u64, PeerProviderErrorV1> {
        if self.1.get() {
            Err(PeerProviderErrorV1::Unavailable)
        } else {
            Ok(self.0.get())
        }
    }
}
#[derive(Default)]
struct BackendState {
    binding: Option<SpdmPeerBindingV1>,
    queue: VecDeque<PeerPacketV1>,
    sends: usize,
    receives: usize,
    policies: usize,
    closes: usize,
    aborts: usize,
    deny_policy: bool,
    fail_send: bool,
    fail_receive: bool,
    fail_close: bool,
    fail_abort: bool,
    fail_binding: bool,
    change_on_send: bool,
    advance_on_send: Option<u64>,
}
struct Backend(Rc<RefCell<BackendState>>, Clock);
impl PeerSession for Backend {
    fn current_binding(&self) -> Result<SpdmPeerBindingV1, PeerProviderErrorV1> {
        let state = self.0.borrow();
        if state.fail_binding {
            return Err(PeerProviderErrorV1::Authentication);
        }
        state
            .binding
            .clone()
            .ok_or(PeerProviderErrorV1::Unavailable)
    }
    fn recheck_policy(
        &mut self,
        _: &SpdmPeerBindingV1,
        _: &VerifiedLmPolicyV1,
        _: &VerifiedMaPolicyCollateral,
        _: &VerifiedMaPolicyCollateral,
    ) -> Result<(), PeerProviderErrorV1> {
        // Test-only admission double; not production fixed/ordered-release appraisal.
        let mut state = self.0.borrow_mut();
        state.policies += 1;
        if state.deny_policy {
            Err(PeerProviderErrorV1::Policy)
        } else {
            Ok(())
        }
    }
    fn send(&mut self, packet: &PeerPacketV1, deadline: u64) -> Result<(), PeerProviderErrorV1> {
        let mut state = self.0.borrow_mut();
        state.sends += 1;
        assert_eq!(deadline, packet.binding.request.deadline());
        if let Some(time) = state.advance_on_send {
            self.1 .0.set(time);
        }
        if state.change_on_send {
            state.binding.as_mut().unwrap().spdm_session_id += 1;
        }
        if state.fail_send {
            Err(PeerProviderErrorV1::Transport)
        } else {
            Ok(())
        }
    }
    fn receive(&mut self, _: u64) -> Result<PeerPacketV1, PeerProviderErrorV1> {
        let mut state = self.0.borrow_mut();
        state.receives += 1;
        if state.fail_receive {
            return Err(PeerProviderErrorV1::Transport);
        }
        state
            .queue
            .pop_front()
            .ok_or(PeerProviderErrorV1::Transport)
    }
    fn close(&mut self, _: u64) -> Result<(), PeerProviderErrorV1> {
        let mut state = self.0.borrow_mut();
        state.closes += 1;
        if state.fail_close {
            Err(PeerProviderErrorV1::Transport)
        } else {
            Ok(())
        }
    }
    fn abort(&mut self, _: u64) -> Result<(), PeerProviderErrorV1> {
        let mut state = self.0.borrow_mut();
        state.aborts += 1;
        if state.fail_abort {
            Err(PeerProviderErrorV1::Cleanup)
        } else {
            Ok(())
        }
    }
}
struct Factory(Rc<RefCell<BackendState>>, Clock);
impl PeerTransportFactory for Factory {
    type Session = Backend;
    fn establish(&mut self, request: &PeerSessionRequestV1) -> Result<Backend, PeerChannelErrorV1> {
        self.0.borrow_mut().binding = Some(SpdmPeerBindingV1 {
            request: request.clone(),
            spdm_session_id: 0x1234,
            th1: [0x88; 48],
        });
        Ok(Backend(self.0.clone(), self.1.clone()))
    }
}
struct Harness {
    state: Rc<RefCell<BackendState>>,
    clock: Clock,
}
impl Harness {
    fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(BackendState::default())),
            clock: Clock(Rc::new(Cell::new(100)), Rc::new(Cell::new(false))),
        }
    }
    fn open(
        &self,
        request: PeerSessionRequestV1,
    ) -> Result<PendingPeerSessionV1<Backend, Clock>, PeerChannelErrorV1> {
        PendingPeerSessionV1::establish(
            &mut Factory(self.state.clone(), self.clock.clone()),
            request,
            self.clock.clone(),
        )
    }
    fn queue(&self, message: PeerMessageV1) {
        let binding = self.state.borrow().binding.clone().unwrap();
        self.state
            .borrow_mut()
            .queue
            .push_back(PeerPacketV1 { binding, message });
    }
}
struct Pair {
    local: Setup,
    peer: Setup,
}
impl Pair {
    fn new(local_handoff: bool, reverse: bool) -> Self {
        let mut local = Setup::new();
        let mut peer = Setup::new();
        let (a, b) = if local_handoff {
            (SnpMaRoleV1::Outgoing, SnpMaRoleV1::Incoming)
        } else {
            (SnpMaRoleV1::Source, SnpMaRoleV1::Destination)
        };
        for (setup, role, id) in [
            (&mut local, if reverse { b } else { a }, 0x11),
            (&mut peer, if reverse { a } else { b }, 0x22),
        ] {
            let mut context = setup.context.clone();
            context.role = role;
            if local_handoff {
                context.evidence_purpose = SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization;
                context.algorithm = SnpMigrationAlgorithmV1::LocalHandoffSecretV1;
                context.tenant_binding_id = [0; 32];
            } else {
                context.evidence_purpose = SnpEvidencePurposeV1::InterNodeSessionV2;
            }
            setup.evidence.ma_report[0x140..0x160].fill(id);
            setup.rebind_context(context);
        }
        Self { local, peer }
    }
    fn proofs(&self) -> [VerifiedMaPolicyCollateral; 2] {
        [
            self.local.verify(&mut TestStore::default()).unwrap(),
            self.peer.verify(&mut TestStore::default()).unwrap(),
        ]
    }
    fn request(&self) -> PeerSessionRequestV1 {
        PeerSessionRequestV1::inter_node(
            SnpOperationContext::new(
                HostRequestId::new(self.local.context.request_id),
                MigrationId::new(2),
                if self.local.context.role == SnpMaRoleV1::Source {
                    MigrationRole::Source
                } else {
                    MigrationRole::Destination
                },
                ManagedGuestHandle::new(3),
            ),
            self.local.context.clone(),
            self.peer.context.clone(),
            150,
        )
        .unwrap()
    }
    fn local_request(&self) -> PeerSessionRequestV1 {
        let reverse = self.local.context.role == SnpMaRoleV1::Incoming;
        PeerSessionRequestV1::local_handoff(
            LocalHandoffBindingV1 {
                purpose: SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
                stage: SnpOperationStageV1::PrepareAuthorization,
                attempt_number: 1,
                operation_id: [4; 16],
                request_id: self.local.context.request_id,
                operation_epoch: 5,
                deadline_unix_seconds: 150,
                previous_ma_report_id: [if reverse { 0x22 } else { 0x11 }; 32],
                new_ma_report_id: [if reverse { 0x11 } else { 0x22 }; 32],
                tenant_set_digest: [7; 48],
                ma_policy_identity_digest: self.local.selected,
                firmware_result_set_digest: [0; 48],
            },
            self.local.context.clone(),
            self.peer.context.clone(),
            metadata().digest().unwrap(),
        )
        .unwrap()
    }
    fn frame(&self, local: bool, opcode: u8) -> InterNodeVdmV1 {
        let setup = if local { &self.local } else { &self.peer };
        InterNodeVdmV1::new(opcode, &setup.evidence.encode_exact().unwrap()).unwrap()
    }
    fn installation_context(&self, reference: SnpSessionReferenceV2) -> MigrationSessionContextV2 {
        let (source, destination) = if self.local.context.role == SnpMaRoleV1::Source {
            (&self.local.context, &self.peer.context)
        } else {
            (&self.peer.context, &self.local.context)
        };
        let mut history = [0; 64];
        history[0] = 1;
        history[1] = 3;
        MigrationSessionContextV2::for_test(
            reference,
            source.clone(),
            destination.clone(),
            history,
            if self.local.context.role == SnpMaRoleV1::Source {
                MigrationRole::Source
            } else {
                MigrationRole::Destination
            },
        )
    }
}
fn metadata() -> LocalMetadataSnapshotV1 {
    LocalMetadataSnapshotV1 {
        tenants: vec![LocalTenantMetadataV1 {
            tenant_report_id: [1; 32],
            tenant_evidence_digest: [2; 48],
            migration_data_valid: false,
            migration_data: [0; 64],
            replay_snapshot_digest: [3; 48],
        }],
    }
}
fn failure<T>(result: Result<T, PeerChannelErrorV1>) -> PeerChannelErrorV1 {
    match result {
        Err(error) => error,
        Ok(_) => panic!("unexpected success"),
    }
}

#[test]
fn current_th1_overrides_template_and_bootstrap_is_correlated_in_both_roles() {
    for reverse in [false, true] {
        let p = Pair::new(false, reverse);
        let h = Harness::new();
        let mut pending = h.open(p.request()).unwrap();
        assert_eq!(pending.expected_context(true).th1, [0x88; 48]);
        let src = if reverse { 0x21 } else { 0x20 };
        let dst = if reverse { 0x20 } else { 0x21 };
        if reverse {
            h.queue(PeerMessageV1::InterNode(p.frame(false, dst)));
            pending.receive_bootstrap().unwrap();
        }
        pending
            .send_bootstrap(PeerMessageV1::InterNode(p.frame(true, src)))
            .unwrap();
        if !reverse {
            h.queue(PeerMessageV1::InterNode(p.frame(false, dst)));
            pending.receive_bootstrap().unwrap();
        }
        let [local, peer] = p.proofs();
        let mut session = pending
            .into_inter_node(&p.local.policy, &local, &peer)
            .unwrap();
        session.close().unwrap();
        session.close().unwrap();
        assert_eq!(h.state.borrow().closes, 1);
        assert_eq!(h.state.borrow().aborts, 0);
    }
}
#[test]
fn template_transcript_is_never_used_as_current_session_authority() {
    let p = Pair::new(false, false);
    let h = Harness::new();
    let mut request = p.request();
    // Both contexts are immutable outside the boundary; a stale proof must fail.
    let mut stale = Setup::new();
    let mut context = p.peer.context.clone();
    context.th1 = [9; 48];
    stale.rebind_context(context);
    let proof = stale.verify(&mut TestStore::default()).unwrap();
    let [local, _peer] = p.proofs();
    let pending = h.open(request.clone()).unwrap();
    assert_eq!(
        failure(pending.into_inter_node(&p.local.policy, &local, &proof)).failure,
        PeerFailureV1::ContextMismatch
    );
    // Merely changing the expected template is not an engine transcript change.
    let mut template = p.local.context.clone();
    template.th1 = [9; 48];
    request = PeerSessionRequestV1::inter_node(
        match request.purpose() {
            PeerPurposeV1::InterNode(o) => *o,
            _ => unreachable!(),
        },
        template,
        p.peer.context.clone(),
        150,
    )
    .unwrap();
    assert_eq!(
        h.open(request).unwrap().expected_context(true).th1,
        [0x88; 48]
    );
}
#[test]
fn promotion_rejects_wrong_purpose_and_unverified_or_denied_context() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    let h = Harness::new();
    let pending = h.open(p.request()).unwrap();
    assert_eq!(
        failure(pending.into_local_handoff(&p.local.policy, &local, &peer)).failure,
        PeerFailureV1::ContextMismatch
    );
    let h = Harness::new();
    h.state.borrow_mut().deny_policy = true;
    let pending = h.open(p.request()).unwrap();
    assert_eq!(
        failure(pending.into_inter_node(&p.local.policy, &local, &peer)).failure,
        PeerFailureV1::Provider(PeerProviderErrorV1::Policy)
    );
    assert_eq!(h.state.borrow().aborts, 1);
}
#[test]
fn application_cannot_be_sent_during_bootstrap() {
    let p = Pair::new(false, false);
    let h = Harness::new();
    let mut pending = h.open(p.request()).unwrap();
    let frame = InterNodeVdmV1::new(0x30, &[7; 168]).unwrap();
    assert_eq!(
        failure(pending.send_bootstrap(PeerMessageV1::InterNode(frame))).failure,
        PeerFailureV1::UnexpectedMessage
    );
    assert_eq!(h.state.borrow().sends, 0);
    assert_eq!(h.state.borrow().aborts, 1);
}
#[test]
fn second_pending_request_and_unsolicited_responses_abort_without_io_retries() {
    let p = Pair::new(false, false);
    for unsolicited in [false, true] {
        let h = Harness::new();
        let mut pending = h.open(p.request()).unwrap();
        if unsolicited {
            h.queue(PeerMessageV1::InterNode(p.frame(false, 0x21)));
            assert_eq!(
                failure(pending.receive_bootstrap()).failure,
                PeerFailureV1::UnexpectedMessage
            );
        } else {
            pending
                .send_bootstrap(PeerMessageV1::InterNode(p.frame(true, 0x20)))
                .unwrap();
            assert_eq!(
                failure(pending.send_bootstrap(PeerMessageV1::InterNode(p.frame(true, 0x20))))
                    .failure,
                PeerFailureV1::InvalidState
            );
        }
        assert!(pending.receive_bootstrap().is_err());
        assert_eq!(h.state.borrow().aborts, 1);
    }
}
#[test]
fn wrong_role_request_and_wrong_opcode_response_are_rejected() {
    let p = Pair::new(false, false);
    let h = Harness::new();
    let mut pending = h.open(p.request()).unwrap();
    assert_eq!(
        failure(pending.send_bootstrap(PeerMessageV1::InterNode(p.frame(false, 0x21)))).failure,
        PeerFailureV1::UnexpectedMessage
    );
    let h = Harness::new();
    let mut pending = h.open(p.request()).unwrap();
    pending
        .send_bootstrap(PeerMessageV1::InterNode(p.frame(true, 0x20)))
        .unwrap();
    h.queue(PeerMessageV1::InterNode(
        InterNodeVdmV1::new(0x23, &p.peer.report_collateral.encode_exact().unwrap()).unwrap(),
    ));
    assert_eq!(
        failure(pending.receive_bootstrap()).failure,
        PeerFailureV1::UnexpectedMessage
    );
}
#[test]
fn full_packet_correlation_rejects_changed_handle_transcript_or_session() {
    let p = Pair::new(false, false);
    for change in 0..3 {
        let h = Harness::new();
        let mut pending = h.open(p.request()).unwrap();
        pending
            .send_bootstrap(PeerMessageV1::InterNode(p.frame(true, 0x20)))
            .unwrap();
        h.queue(PeerMessageV1::InterNode(p.frame(false, 0x21)));
        let mut state = h.state.borrow_mut();
        let binding = &mut state.queue.front_mut().unwrap().binding;
        match change {
            0 => binding.th1[0] ^= 1,
            1 => binding.spdm_session_id += 1,
            _ => {
                let mut operation = match binding.request.purpose() {
                    PeerPurposeV1::InterNode(o) => *o,
                    _ => unreachable!(),
                };
                operation.managed_guest = ManagedGuestHandle::new(99);
                binding.request = PeerSessionRequestV1::inter_node(
                    operation,
                    p.local.context.clone(),
                    p.peer.context.clone(),
                    150,
                )
                .unwrap();
            }
        }
        drop(state);
        assert_eq!(
            failure(pending.receive_bootstrap()).failure,
            PeerFailureV1::ContextMismatch
        );
    }
}
#[test]
fn engine_session_changes_and_deadlines_are_checked_after_io() {
    let p = Pair::new(false, false);
    for changed in [false, true] {
        let h = Harness::new();
        let mut pending = h.open(p.request()).unwrap();
        if changed {
            h.state.borrow_mut().change_on_send = true;
        } else {
            h.state.borrow_mut().advance_on_send = Some(150);
        }
        let error = failure(pending.send_bootstrap(PeerMessageV1::InterNode(p.frame(true, 0x20))));
        assert_eq!(
            error.failure,
            if changed {
                PeerFailureV1::ContextMismatch
            } else {
                PeerFailureV1::Expired
            }
        );
        assert_eq!(h.state.borrow().sends, 1);
        assert_eq!(h.state.borrow().aborts, 1);
    }
}
#[test]
fn expiry_clock_rollback_and_unavailable_time_fail_closed_before_io() {
    let p = Pair::new(false, false);
    for change in 0..3 {
        let h = Harness::new();
        let mut pending = h.open(p.request()).unwrap();
        let expected = match change {
            0 => {
                h.clock.0.set(150);
                PeerFailureV1::Expired
            }
            1 => {
                h.clock.0.set(99);
                PeerFailureV1::ClockRollback
            }
            _ => {
                h.clock.1.set(true);
                PeerFailureV1::Provider(PeerProviderErrorV1::Unavailable)
            }
        };
        assert_eq!(
            failure(pending.send_bootstrap(PeerMessageV1::InterNode(p.frame(true, 0x20)))).failure,
            expected
        );
        assert_eq!(h.state.borrow().sends, 0);
        assert_eq!(h.state.borrow().aborts, 1);
    }
}
#[test]
fn send_receive_and_cleanup_errors_are_retained_without_retry() {
    let p = Pair::new(false, false);
    for send in [false, true] {
        let h = Harness::new();
        let mut pending = h.open(p.request()).unwrap();
        {
            let mut s = h.state.borrow_mut();
            s.fail_send = send;
            s.fail_receive = !send;
            s.fail_abort = true;
        }
        let error = if send {
            failure(pending.send_bootstrap(PeerMessageV1::InterNode(p.frame(true, 0x20))))
        } else {
            failure(pending.receive_bootstrap())
        };
        assert_eq!(
            error.failure,
            PeerFailureV1::Provider(PeerProviderErrorV1::Transport)
        );
        assert_eq!(error.cleanup_error, Some(PeerProviderErrorV1::Cleanup));
        assert!(pending.abort().is_err());
        drop(pending);
        assert_eq!(h.state.borrow().aborts, 1);
    }
}
#[test]
fn active_policy_reappraisal_failure_and_close_failure_abort() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    for policy in [false, true] {
        let h = Harness::new();
        let pending = h.open(p.request()).unwrap();
        let mut session = pending
            .into_inter_node(&p.local.policy, &local, &peer)
            .unwrap();
        {
            let mut s = h.state.borrow_mut();
            s.deny_policy = policy;
            s.fail_close = !policy;
        }
        assert!(session.close().is_err());
        assert_eq!(h.state.borrow().aborts, 1);
        assert_eq!(session.state(), PeerSessionStateV1::Aborted);
    }
}
#[test]
fn drop_aborts_once_and_explicit_abort_is_idempotent() {
    let p = Pair::new(false, false);
    for explicit in [false, true] {
        let h = Harness::new();
        let mut pending = h.open(p.request()).unwrap();
        if explicit {
            pending.abort().unwrap();
            pending.abort().unwrap();
        }
        drop(pending);
        assert_eq!(h.state.borrow().aborts, 1);
    }
}
#[test]
fn local_metadata_and_secret_are_separate_and_directional() {
    for reverse in [false, true] {
        let p = Pair::new(true, reverse);
        let [local, peer] = p.proofs();
        let h = Harness::new();
        let pending = h.open(p.local_request()).unwrap();
        let mut session = pending
            .into_local_handoff(&p.local.policy, &local, &peer)
            .unwrap();
        session
            .send(LocalPeerMessageV1::Metadata(metadata()))
            .unwrap();
        if reverse {
            h.queue(PeerMessageV1::Local(LocalPeerMessageV1::HandoffSecret(
                Zeroizing::new([7; 32]),
            )));
            assert!(matches!(
                session.receive().unwrap(),
                LocalPeerMessageV1::HandoffSecret(_)
            ));
            assert_eq!(
                failure(session.send(LocalPeerMessageV1::HandoffSecret(Zeroizing::new([7; 32]))))
                    .failure,
                PeerFailureV1::UnexpectedMessage
            );
        } else {
            session
                .send(LocalPeerMessageV1::HandoffSecret(Zeroizing::new([7; 32])))
                .unwrap();
            session.close().unwrap();
        }
    }
}
#[test]
fn local_metadata_mismatch_and_cross_protocol_packets_abort() {
    let p = Pair::new(true, false);
    let [local, peer] = p.proofs();
    for crossed in [false, true] {
        let h = Harness::new();
        let pending = h.open(p.local_request()).unwrap();
        let mut session = pending
            .into_local_handoff(&p.local.policy, &local, &peer)
            .unwrap();
        if crossed {
            let other = Pair::new(false, false);
            h.queue(PeerMessageV1::InterNode(other.frame(false, 0x21)));
            assert_eq!(
                failure(session.receive()).failure,
                PeerFailureV1::UnexpectedMessage
            );
        } else {
            let mut value = metadata();
            value.tenants[0].replay_snapshot_digest[0] ^= 1;
            assert_eq!(
                failure(session.send(LocalPeerMessageV1::Metadata(value))).failure,
                PeerFailureV1::ContextMismatch
            );
        }
    }
}
#[test]
fn recovery_never_demands_a_failed_ma_peer_session() {
    let p = Pair::new(true, false);
    let req = p.local_request();
    let (mut binding, metadata_digest) = match req.purpose() {
        PeerPurposeV1::LocalPlanned {
            binding,
            metadata_digest,
        } => (binding.as_ref().clone(), *metadata_digest),
        _ => unreachable!(),
    };
    binding.purpose = SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization;
    assert_eq!(
        failure(PeerSessionRequestV1::local_handoff(
            binding,
            p.local.context.clone(),
            p.peer.context.clone(),
            metadata_digest
        ))
        .failure,
        PeerFailureV1::ContextMismatch
    );
}
#[test]
fn local_identity_substitution_and_secret_before_promotion_are_rejected() {
    let p = Pair::new(true, false);
    let [local, peer] = p.proofs();
    let h = Harness::new();
    let request = p.local_request();
    let (mut binding, digest) = match request.purpose() {
        PeerPurposeV1::LocalPlanned {
            binding,
            metadata_digest,
        } => (binding.as_ref().clone(), *metadata_digest),
        _ => unreachable!(),
    };
    binding.new_ma_report_id = [9; 32];
    let req = PeerSessionRequestV1::local_handoff(
        binding,
        p.local.context.clone(),
        p.peer.context.clone(),
        digest,
    )
    .unwrap();
    assert_eq!(
        failure(
            h.open(req)
                .unwrap()
                .into_local_handoff(&p.local.policy, &local, &peer)
        )
        .failure,
        PeerFailureV1::ContextMismatch
    );
    let h = Harness::new();
    let mut pending = h.open(p.local_request()).unwrap();
    assert_eq!(
        failure(
            pending.send_bootstrap(PeerMessageV1::Local(LocalPeerMessageV1::HandoffSecret(
                Zeroizing::new([7; 32])
            )))
        )
        .failure,
        PeerFailureV1::UnexpectedMessage
    );
}
#[test]
fn exact_wire_bounds_versions_tags_lengths_and_redaction() {
    let p = Pair::new(false, false);
    let valid = p.frame(true, 0x20);
    for (offset, value) in [(0, 1), (1, 1), (2, 0x2e), (3, 2), (4, 9), (6, 0)] {
        let mut bytes = Zeroizing::new(valid.encoded().to_vec());
        bytes[offset] = value;
        assert!(InterNodeVdmV1::decode_exact(bytes).is_err());
    }
    for size in [0, 9, 1549, 1551, 8193] {
        let mut bytes = Zeroizing::new(valid.encoded().to_vec());
        bytes.resize(size, 0);
        assert!(InterNodeVdmV1::decode_exact(bytes).is_err());
    }
    let frame = InterNodeVdmV1::new(0x30, &[0x77; 168]).unwrap();
    assert_eq!(format!("{frame:?}"), "InterNodeVdmV1(<redacted>)");
    assert_eq!(
        format!(
            "{:?}",
            LocalPeerMessageV1::HandoffSecret(Zeroizing::new([7; 32]))
        ),
        "LocalPeerMessageV1(<redacted>)"
    );
    assert!(InterNodeVdmV1::new(0x2e, &[]).is_err());
    assert!(InterNodeVdmV1::new(0x22, &vec![0; 4609]).is_err());
}
#[test]
fn malformed_records_never_enter_application_path() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    for malformed in [false, true] {
        let h = Harness::new();
        let pending = h.open(p.request()).unwrap();
        let mut session = pending
            .into_inter_node(&p.local.policy, &local, &peer)
            .unwrap();
        let frame = if malformed {
            InterNodeVdmV1::new(0x20, &[0; 1540]).unwrap()
        } else {
            InterNodeVdmV1::new(0x30, &[0; 168]).unwrap()
        };
        assert!(session.send(frame).is_err());
        assert_eq!(h.state.borrow().sends, 0);
    }
}
#[test]
fn genuine_purpose_three_evidence_is_rejected_without_reactivating_the_deferred_flow() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    let h = Harness::new();
    let pending = h.open(p.request()).unwrap();
    let mut session = pending
        .into_inter_node(&p.local.policy, &local, &peer)
        .unwrap();
    session.send(p.frame(true, 0x20)).unwrap();
    let mut evidence = p.peer.evidence.clone();
    evidence.header.evidence_purpose = SnpEvidencePurposeV1::InterNodePostInstallConfirmation;
    evidence.report_data_context.evidence_purpose =
        SnpEvidencePurposeV1::InterNodePostInstallConfirmation;
    let frame = InterNodeVdmV1::new(0x21, &evidence.encode_exact().unwrap()).unwrap();
    h.queue(PeerMessageV1::InterNode(frame));
    assert_eq!(
        failure(session.receive()).failure,
        PeerFailureV1::ContextMismatch
    );
    assert_eq!(h.state.borrow().aborts, 1);
}
#[test]
fn closed_session_cannot_send_receive_or_bind_a_replacement_installation() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    let h = Harness::new();
    let pending = h.open(p.request()).unwrap();
    let mut session = pending
        .into_inter_node(&p.local.policy, &local, &peer)
        .unwrap();
    session.close().unwrap();
    assert_eq!(
        failure(session.send(p.frame(true, 0x20))).failure,
        PeerFailureV1::InvalidState
    );
    assert_eq!(
        failure(session.receive()).failure,
        PeerFailureV1::InvalidState
    );
    assert_eq!(h.state.borrow().sends, 0);
    assert_eq!(h.state.borrow().receives, 0);
    assert_eq!(h.state.borrow().aborts, 0);
    assert!(session
        .bind_installation(&p.installation_context(SnpSessionReferenceV2 {
            request_id: p.local.context.request_id,
            session_context_digest: [0x42; 48]
        }))
        .is_err());
}
#[test]
fn installation_reference_is_not_spdm_th1_and_is_bound_once() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    let h = Harness::new();
    let pending = h.open(p.request()).unwrap();
    let mut session = pending
        .into_inter_node(&p.local.policy, &local, &peer)
        .unwrap();
    let reference = SnpSessionReferenceV2 {
        request_id: p.local.context.request_id,
        session_context_digest: [0x42; 48],
    };
    session
        .bind_installation(&p.installation_context(reference.clone()))
        .unwrap();
    let control = InstallSessionControlV2 {
        session: reference,
        kind: InstallSessionControlKindV2::PollDestinationCompletion,
    };
    session
        .send(InterNodeVdmV1::new(0x32, &control.encode_exact().unwrap()).unwrap())
        .unwrap();
    assert_eq!(h.state.borrow().sends, 1);
    assert!(session.close().is_err()); // Outstanding request cannot be closed as completed.
    assert_eq!(h.state.borrow().aborts, 1);
}
#[test]
fn wrong_installation_reference_and_control_kind_are_rejected() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    for wrong_kind in [false, true] {
        let h = Harness::new();
        let pending = h.open(p.request()).unwrap();
        let mut session = pending
            .into_inter_node(&p.local.policy, &local, &peer)
            .unwrap();
        let mut reference = SnpSessionReferenceV2 {
            request_id: p.local.context.request_id,
            session_context_digest: [0x42; 48],
        };
        session
            .bind_installation(&p.installation_context(reference.clone()))
            .unwrap();
        let kind = if wrong_kind {
            InstallSessionControlKindV2::AcknowledgeSourceCompletion
        } else {
            reference.session_context_digest[0] ^= 1;
            InstallSessionControlKindV2::PollDestinationCompletion
        };
        let control = InstallSessionControlV2 {
            session: reference,
            kind,
        };
        assert!(session
            .send(InterNodeVdmV1::new(0x32, &control.encode_exact().unwrap()).unwrap())
            .is_err());
        assert_eq!(h.state.borrow().sends, 0);
    }
}
#[test]
fn unavailable_production_factory_and_failed_initial_binding_have_no_success_fallback() {
    let p = Pair::new(false, false);
    let h = Harness::new();
    assert_eq!(
        failure(PendingPeerSessionV1::establish(
            &mut UnavailablePeerTransportFactoryV1,
            p.request(),
            h.clock.clone()
        ))
        .failure,
        PeerFailureV1::Provider(PeerProviderErrorV1::Unavailable)
    );
    h.state.borrow_mut().fail_binding = true;
    assert_eq!(
        failure(h.open(p.request())).failure,
        PeerFailureV1::Provider(PeerProviderErrorV1::Authentication)
    );
    assert_eq!(h.state.borrow().aborts, 1);
}

// Codec/transport fixtures, not HMAC, attestation or installation receipts.
fn active_frame(p: &Pair, opcode: u8, session: &SnpSessionReferenceV2) -> InterNodeVdmV1 {
    let role = if opcode & 1 == 0 {
        SnpMaRoleV1::Source
    } else {
        SnpMaRoleV1::Destination
    };
    let setup = if p.local.context.role == role {
        &p.local
    } else {
        &p.peer
    };
    match opcode {
        0x20 | 0x21 => {
            InterNodeVdmV1::new(opcode, &setup.evidence.encode_exact().unwrap()).unwrap()
        }
        0x22 | 0x23 => {
            InterNodeVdmV1::new(opcode, &setup.report_collateral.encode_exact().unwrap()).unwrap()
        }
        0x24 => {
            let mut context = setup.context.clone();
            context.evidence_purpose = SnpEvidencePurposeV1::InterNodeTenantAuthorizationV2;
            context.purpose_binding_digest = [0xcc; 48];
            let mut header = setup.evidence.header.clone();
            header.record_type = SnpRecordTypeV1::TenantEvidence;
            header.record_length = SnpTenantEvidenceV1::ENCODED_SIZE as u32;
            header.evidence_purpose = context.evidence_purpose;
            let record = SnpTenantEvidenceV1 {
                header,
                report_data_context: context,
                policy_identity: setup.evidence.policy_identity.clone(),
                tenant_policy_context: TenantPolicyContextV1::venice(),
                collateral_digest: setup.evidence.collateral_digest,
                tenant_report: setup.evidence.ma_report,
            };
            InterNodeVdmV1::new(opcode, &record.encode_exact().unwrap()).unwrap()
        }
        0x25 => {
            let record = SnpAuthorizationResultV1 {
                request_id: session.request_id,
                decision: SnpAuthorizationDecisionV1::Accepted,
                evidence_profile: SnpEvidenceProfileV1::Fixture,
                tcb_profile: SnpTcbProfileV1::Venice,
                failure: SnpAuthorizationFailureV1::None,
                algorithm: setup.context.algorithm,
                negotiated_migration_version: 1,
                authorization_context_digest: [0xaa; 48],
            };
            InterNodeVdmV1::new(opcode, &record.encode_exact().unwrap()).unwrap()
        }
        0x30..=0x35 => {
            let context = p.installation_context(session.clone());
            let bytes = crate::snp::direct_exchange::tests::payload(&context, opcode);
            InterNodeVdmV1::new(opcode, &bytes).unwrap()
        }
        _ => panic!("not an active opcode"),
    }
}

#[test]
fn all_twelve_active_opcodes_pass_both_directional_boundaries_and_mint_protected_receipts() {
    for reverse in [false, true] {
        let p = Pair::new(false, reverse);
        let [local, peer] = p.proofs();
        let h = Harness::new();
        let pending = h.open(p.request()).unwrap();
        let mut channel = pending
            .into_inter_node(&p.local.policy, &local, &peer)
            .unwrap();
        let reference = SnpSessionReferenceV2 {
            request_id: p.local.context.request_id,
            session_context_digest: [0x42; 48],
        };
        let context = p.installation_context(reference.clone());
        channel.bind_installation(&context).unwrap();
        let mut exchange = InstallExchangeSequenceV2::new(&context);
        for request in [0x20, 0x22, 0x24, 0x30, 0x32, 0x34] {
            let a = active_frame(&p, request, &reference);
            let b = active_frame(&p, request + 1, &reference);
            if reverse {
                h.queue(PeerMessageV1::InterNode(a));
                if request >= 0x30 {
                    exchange
                        .observe(channel.receive_installation().unwrap())
                        .unwrap();
                    exchange
                        .observe(channel.send_installation(b).unwrap())
                        .unwrap();
                } else {
                    assert!(channel.receive().is_ok());
                    channel.send(b).unwrap();
                }
            } else {
                if request >= 0x30 {
                    exchange
                        .observe(channel.send_installation(a).unwrap())
                        .unwrap();
                } else {
                    channel.send(a).unwrap();
                }
                h.queue(PeerMessageV1::InterNode(b));
                if request >= 0x30 {
                    exchange
                        .observe(channel.receive_installation().unwrap())
                        .unwrap();
                } else {
                    assert!(channel.receive().is_ok());
                }
            }
        }
        channel.close().unwrap();
        assert_eq!(exchange.finish().unwrap().session(), &reference);
        assert_eq!(h.state.borrow().sends, 6);
        assert_eq!(h.state.borrow().receives, 6);
        assert_eq!(h.state.borrow().aborts, 0);
    }
}

#[test]
fn changed_session_evidence_context_is_rejected_even_with_a_canonical_record() {
    let mut p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    let h = Harness::new();
    let pending = h.open(p.request()).unwrap();
    let mut channel = pending
        .into_inter_node(&p.local.policy, &local, &peer)
        .unwrap();
    p.local.context.purpose_binding_digest[0] ^= 1;
    p.local.evidence.report_data_context = p.local.context.clone();
    let frame = p.frame(true, 0x20);
    assert_eq!(
        failure(channel.send(frame)).failure,
        PeerFailureV1::ContextMismatch
    );
    assert_eq!(h.state.borrow().sends, 0);
}

#[test]
fn protected_installation_receipts_never_escape_failed_or_replaced_peer_io() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    for failure_case in 0..3 {
        let h = Harness::new();
        let mut channel = h
            .open(p.request())
            .unwrap()
            .into_inter_node(&p.local.policy, &local, &peer)
            .unwrap();
        let reference = SnpSessionReferenceV2 {
            request_id: p.local.context.request_id,
            session_context_digest: [0x42; 48],
        };
        let context = p.installation_context(reference.clone());
        channel.bind_installation(&context).unwrap();
        match failure_case {
            0 => h.state.borrow_mut().fail_send = true,
            1 => h.state.borrow_mut().change_on_send = true,
            _ => h.state.borrow_mut().advance_on_send = Some(150),
        }
        assert!(channel
            .send_installation(active_frame(&p, 0x30, &reference))
            .is_err());
        assert_eq!(h.state.borrow().sends, 1);
        assert_eq!(h.state.borrow().aborts, 1);
        assert!(channel
            .send_installation(active_frame(&p, 0x30, &reference))
            .is_err());
        assert_eq!(h.state.borrow().sends, 1);
    }
}

#[test]
fn unbound_or_rebound_installation_and_historical_protocol_are_rejected() {
    let p = Pair::new(false, false);
    let [local, peer] = p.proofs();
    let reference = SnpSessionReferenceV2 {
        request_id: p.local.context.request_id,
        session_context_digest: [0x42; 48],
    };
    for bind_first in [false, true] {
        let h = Harness::new();
        let mut channel = h
            .open(p.request())
            .unwrap()
            .into_inter_node(&p.local.policy, &local, &peer)
            .unwrap();
        if bind_first {
            let context = p.installation_context(reference.clone());
            channel.bind_installation(&context).unwrap();
            assert!(channel.bind_installation(&context).is_err());
        } else {
            assert!(channel
                .send_installation(active_frame(&p, 0x30, &reference))
                .is_err());
        }
        assert_eq!(h.state.borrow().sends, 0);
    }
    for opcode in 0x26..=0x2d {
        assert!(InterNodeVdmV1::new(opcode, &[0; 272]).is_err());
        assert!(active_inter_node_layout(opcode).is_none());
    }
    let mut old = p.local.context.clone();
    old.evidence_purpose = SnpEvidencePurposeV1::InterNodeKeyContribution;
    assert!(PeerSessionRequestV1::inter_node(
        match p.request().purpose() {
            PeerPurposeV1::InterNode(o) => *o,
            _ => unreachable!(),
        },
        old,
        p.peer.context.clone(),
        150,
    )
    .is_err());
}
