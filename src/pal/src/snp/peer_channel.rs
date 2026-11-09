// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Purpose-separated channel contracts, not activated SPDM/network adapters.
//! Trusted backends must bind every operation to the actual encrypted SPDM
//! session, honor absolute deadlines, reappraise policy, bound allocations and
//! erase transport copies. A connection, routing handle or packet is not proof.

use core::fmt;
use zeroize::Zeroizing;

use super::{
    authorization_result::SnpAuthorizationResultV1,
    collateral_set::SnpCollateralSetV1,
    direct_exchange::{
        FirmwareCompletionRecordV2, InstallSessionControlV2, KeyAcceptanceV2,
        ProtectedInstallRecordV2,
    },
    direct_key::{MigrationKeyV2, MigrationSessionContextV2},
    limits::{validate_snp_application_message_size, MAX_SNP_COLLATERAL_SET_SIZE},
    local_handoff::LocalMetadataSnapshotV1,
    ma_evidence::SnpMaEvidenceV1,
    ma_policy::{VerifiedLmPolicyV1, VerifiedMaPolicyCollateral},
    purpose_binding::{LocalHandoffBindingV1, SnpOperationStageV1},
    report_data_context::{ReportDataContextV1, SnpEvidencePurposeV1, SnpMaRoleV1},
    tenant_evidence::SnpTenantEvidenceV1,
    wire::{SnpCodecError, StrictReader, StrictWriter},
};
use crate::types::{MigrationRole, SnpOperationContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerProviderErrorV1 {
    Unavailable,
    Transport,
    Authentication,
    Policy,
    Timeout,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerFailureV1 {
    Provider(PeerProviderErrorV1),
    Codec(SnpCodecError),
    ContextMismatch,
    UnexpectedMessage,
    InvalidState,
    Expired,
    ClockRollback,
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerChannelErrorV1 {
    pub failure: PeerFailureV1,
    pub cleanup_error: Option<PeerProviderErrorV1>,
}

impl From<PeerFailureV1> for PeerChannelErrorV1 {
    fn from(failure: PeerFailureV1) -> Self {
        Self {
            failure,
            cleanup_error: None,
        }
    }
}
impl From<SnpCodecError> for PeerFailureV1 {
    fn from(error: SnpCodecError) -> Self {
        Self::Codec(error)
    }
}
impl From<PeerProviderErrorV1> for PeerFailureV1 {
    fn from(error: PeerProviderErrorV1) -> Self {
        Self::Provider(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPurposeV1 {
    InterNode(SnpOperationContext),
    LocalPlanned {
        binding: Box<LocalHandoffBindingV1>,
        metadata_digest: [u8; 48],
    },
}

/// Expected contexts are reconstructed by trusted orchestration. Their TH1
/// fields are replaced with the backend's current transcript after establishment.
/// Migration/protocol versions are distinct; no conversion is inferred here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionRequestV1 {
    purpose: PeerPurposeV1,
    local: ReportDataContextV1,
    peer: ReportDataContextV1,
    deadline: u64,
}

impl PeerSessionRequestV1 {
    pub fn inter_node(
        operation: SnpOperationContext,
        local: ReportDataContextV1,
        peer: ReportDataContextV1,
        deadline: u64,
    ) -> Result<Self, PeerChannelErrorV1> {
        let roles = match operation.role {
            MigrationRole::Source => (SnpMaRoleV1::Source, SnpMaRoleV1::Destination),
            MigrationRole::Destination => (SnpMaRoleV1::Destination, SnpMaRoleV1::Source),
        };
        if (local.role, peer.role) != roles
            || local.evidence_purpose != SnpEvidencePurposeV1::InterNodeSessionV2
            || local.request_id != operation.request_id.value()
        {
            return Err(PeerFailureV1::ContextMismatch.into());
        }
        Self::new(PeerPurposeV1::InterNode(operation), local, peer, deadline)
    }

    pub fn local_handoff(
        binding: LocalHandoffBindingV1,
        local: ReportDataContextV1,
        peer: ReportDataContextV1,
        metadata_digest: [u8; 48],
    ) -> Result<Self, PeerChannelErrorV1> {
        binding
            .encode_exact()
            .map_err(|e| PeerChannelErrorV1::from(PeerFailureV1::Codec(e)))?;
        if binding.purpose != SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization
            || local.evidence_purpose != binding.purpose
            || local.request_id != binding.request_id
            || !matches!(
                (local.role, peer.role),
                (SnpMaRoleV1::Outgoing, SnpMaRoleV1::Incoming)
                    | (SnpMaRoleV1::Incoming, SnpMaRoleV1::Outgoing)
            )
            || local.purpose_binding_digest != peer.purpose_binding_digest
        {
            return Err(PeerFailureV1::ContextMismatch.into());
        }
        let deadline = binding.deadline_unix_seconds;
        Self::new(
            PeerPurposeV1::LocalPlanned {
                binding: Box::new(binding),
                metadata_digest,
            },
            local,
            peer,
            deadline,
        )
    }

    fn new(
        purpose: PeerPurposeV1,
        mut local: ReportDataContextV1,
        mut peer: ReportDataContextV1,
        deadline: u64,
    ) -> Result<Self, PeerChannelErrorV1> {
        for context in [&local, &peer] {
            context
                .validate()
                .map_err(|e| PeerChannelErrorV1::from(PeerFailureV1::Codec(e)))?;
        }
        if local.evidence_purpose != peer.evidence_purpose
            || local.request_id != peer.request_id
            || local.tenant_binding_id != peer.tenant_binding_id
            || local.algorithm != peer.algorithm
            || local.negotiated_migration_version != peer.negotiated_migration_version
        {
            return Err(PeerFailureV1::ContextMismatch.into());
        }
        local.th1 = [0; 48];
        peer.th1 = [0; 48];
        Ok(Self {
            purpose,
            local,
            peer,
            deadline,
        })
    }

    pub fn purpose(&self) -> &PeerPurposeV1 {
        &self.purpose
    }
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
}

/// Backend observation, not an authentication receipt.
/// Only a trusted backend connected to the real SPDM engine may supply it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdmPeerBindingV1 {
    pub request: PeerSessionRequestV1,
    pub spdm_session_id: u32,
    pub th1: [u8; 48],
}

pub trait PeerClockV1 {
    fn unix_seconds(&self) -> Result<u64, PeerProviderErrorV1>;
}

/// Selects actual transport adapters; failed establishment must release partial
/// resources or return a cleanup error. There is no plaintext/TCP fallback.
pub trait PeerTransportFactory {
    type Session: PeerSession;
    fn establish(
        &mut self,
        request: &PeerSessionRequestV1,
    ) -> Result<Self::Session, PeerChannelErrorV1>;
}

/// Trusted adapter, not an untrusted host callback. Bootstrap delivery must
/// already have SPDM confidentiality/integrity; application authority is added
/// only after verified evidence is correlated to that same engine transcript.
pub trait PeerSession {
    fn current_binding(&self) -> Result<SpdmPeerBindingV1, PeerProviderErrorV1>;
    /// Recheck current policy validity and the selected fixed/ordered-release
    /// pair admission, including local handoff identity/epoch/attempt/stage.
    /// No tenant admission, firmware effect or durable write is implied.
    fn recheck_policy(
        &mut self,
        binding: &SpdmPeerBindingV1,
        policy: &VerifiedLmPolicyV1,
        local: &VerifiedMaPolicyCollateral,
        peer: &VerifiedMaPolicyCollateral,
    ) -> Result<(), PeerProviderErrorV1>;
    fn send(&mut self, packet: &PeerPacketV1, deadline: u64) -> Result<(), PeerProviderErrorV1>;
    fn receive(&mut self, deadline: u64) -> Result<PeerPacketV1, PeerProviderErrorV1>;
    fn close(&mut self, deadline: u64) -> Result<(), PeerProviderErrorV1>;
    fn abort(&mut self, deadline: u64) -> Result<(), PeerProviderErrorV1>;
}

/// Shared registry lookup for both the PAL boundary and MigTD's static validator.
pub fn active_inter_node_layout(opcode: u8) -> Option<(u16, usize, usize)> {
    let (tag, minimum, maximum) = match opcode {
        0x20 | 0x21 => (
            0x0100,
            SnpMaEvidenceV1::ENCODED_SIZE,
            SnpMaEvidenceV1::ENCODED_SIZE,
        ),
        0x22 | 0x23 => (
            0x0101,
            SnpCollateralSetV1::MINIMUM_SIZE_BEFORE_DER + 2,
            MAX_SNP_COLLATERAL_SET_SIZE,
        ),
        0x24 => (
            0x0102,
            SnpTenantEvidenceV1::ENCODED_SIZE,
            SnpTenantEvidenceV1::ENCODED_SIZE,
        ),
        0x25 => (
            0x0103,
            SnpAuthorizationResultV1::ENCODED_SIZE,
            SnpAuthorizationResultV1::ENCODED_SIZE,
        ),
        0x30 => (
            0x0109,
            MigrationKeyV2::DELIVERY_SIZE,
            MigrationKeyV2::DELIVERY_SIZE,
        ),
        0x31 => (
            0x010a,
            KeyAcceptanceV2::ENCODED_SIZE,
            KeyAcceptanceV2::ENCODED_SIZE,
        ),
        0x32 | 0x35 => (
            0x010c,
            InstallSessionControlV2::ENCODED_SIZE,
            InstallSessionControlV2::ENCODED_SIZE,
        ),
        0x33 | 0x34 => (
            0x010b,
            FirmwareCompletionRecordV2::ENCODED_SIZE,
            FirmwareCompletionRecordV2::ENCODED_SIZE,
        ),
        _ => return None,
    };
    Some((tag, minimum, maximum))
}

/// Owned secret-bearing application bytes; diagnostics redact the entire frame.
pub struct InterNodeVdmV1(Zeroizing<Vec<u8>>);
impl fmt::Debug for InterNodeVdmV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InterNodeVdmV1(<redacted>)")
    }
}
impl InterNodeVdmV1 {
    pub fn new(opcode: u8, payload: &[u8]) -> Result<Self, PeerChannelErrorV1> {
        let (tag, minimum, maximum) = active_inter_node_layout(opcode)
            .ok_or_else(|| PeerChannelErrorV1::from(PeerFailureV1::UnexpectedMessage))?;
        if !(minimum..=maximum).contains(&payload.len()) {
            return Err(PeerFailureV1::Codec(SnpCodecError::InvalidLength).into());
        }
        let mut bytes = Zeroizing::new(vec![0; 10 + payload.len()]);
        let mut w = StrictWriter::new(&mut bytes);
        let encoded = (|| {
            w.write_u8(0)?;
            w.write_u8(0)?;
            w.write_u8(opcode)?;
            w.write_u8(1)?;
            w.write_u16(tag)?;
            w.write_u32(payload.len() as u32)?;
            w.write_bytes(payload)
        })();
        encoded.map_err(|e| PeerChannelErrorV1::from(PeerFailureV1::Codec(e)))?;
        Self::decode_exact(bytes)
    }
    pub fn decode_exact(bytes: Zeroizing<Vec<u8>>) -> Result<Self, PeerChannelErrorV1> {
        let value = Self(bytes);
        value.layout().map_err(PeerChannelErrorV1::from)?;
        Ok(value)
    }
    pub fn encoded(&self) -> &[u8] {
        &self.0
    }
    fn layout(&self) -> Result<(u8, &[u8]), PeerFailureV1> {
        validate_snp_application_message_size(self.0.len())?;
        let mut r = StrictReader::new(&self.0);
        if r.read_u8()? != 0 || r.read_u8()? != 0 {
            return Err(PeerFailureV1::UnexpectedMessage);
        }
        let opcode = r.read_u8()?;
        if r.read_u8()? != 1 {
            return Err(PeerFailureV1::UnexpectedMessage);
        }
        let (tag, min, max) =
            active_inter_node_layout(opcode).ok_or(PeerFailureV1::UnexpectedMessage)?;
        if r.read_u16()? != tag {
            return Err(PeerFailureV1::UnexpectedMessage);
        }
        let length = r.read_u32()? as usize;
        if !(min..=max).contains(&length) {
            return Err(SnpCodecError::InvalidLength.into());
        }
        r.take(length)?;
        r.finish()?;
        Ok((opcode, &self.0[10..]))
    }
}

/// Logical protected records, NOT new VDM tags or an approved local wire ABI.
pub enum LocalPeerMessageV1 {
    MaEvidence(Box<SnpMaEvidenceV1>),
    Collateral(SnpCollateralSetV1),
    Metadata(LocalMetadataSnapshotV1),
    HandoffSecret(Zeroizing<[u8; 32]>),
}
impl fmt::Debug for LocalPeerMessageV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPeerMessageV1(<redacted>)")
    }
}
#[derive(Debug)]
pub enum PeerMessageV1 {
    InterNode(InterNodeVdmV1),
    Local(LocalPeerMessageV1),
}
#[derive(Debug)]
pub struct PeerPacketV1 {
    pub binding: SpdmPeerBindingV1,
    pub message: PeerMessageV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSessionStateV1 {
    Bootstrap,
    Active,
    Closed,
    Aborted,
    ReconciliationRequired,
}

struct PeerAuthorizationV1<'a> {
    policy: &'a VerifiedLmPolicyV1,
    local: &'a VerifiedMaPolicyCollateral,
    peer: &'a VerifiedMaPolicyCollateral,
}

struct PeerCore<B: PeerSession, C: PeerClockV1> {
    backend: B,
    clock: C,
    binding: SpdmPeerBindingV1,
    state: PeerSessionStateV1,
    last_time: u64,
    pending: Option<u8>,
    installation: Option<MigrationSessionContextV2>,
}

impl<B: PeerSession, C: PeerClockV1> PeerCore<B, C> {
    fn fail(&mut self, failure: PeerFailureV1) -> PeerChannelErrorV1 {
        let cleanup_error = if matches!(
            self.state,
            PeerSessionStateV1::Bootstrap | PeerSessionStateV1::Active
        ) {
            self.state = PeerSessionStateV1::Aborted;
            self.backend.abort(self.binding.request.deadline).err()
        } else {
            None
        };
        if cleanup_error.is_some() {
            self.state = PeerSessionStateV1::ReconciliationRequired;
        }
        PeerChannelErrorV1 {
            failure,
            cleanup_error,
        }
    }
    fn time(&mut self) -> Result<(), PeerFailureV1> {
        let now = self.clock.unix_seconds()?;
        if now < self.last_time {
            return Err(PeerFailureV1::ClockRollback);
        }
        self.last_time = now;
        if now >= self.binding.request.deadline {
            return Err(PeerFailureV1::Expired);
        }
        Ok(())
    }
    fn check(&mut self, auth: Option<&PeerAuthorizationV1<'_>>) -> Result<(), PeerFailureV1> {
        if !matches!(
            self.state,
            PeerSessionStateV1::Bootstrap | PeerSessionStateV1::Active
        ) {
            return Err(PeerFailureV1::InvalidState);
        }
        self.time()?;
        if self.backend.current_binding()? != self.binding {
            return Err(PeerFailureV1::ContextMismatch);
        }
        if let Some(auth) = auth {
            self.backend
                .recheck_policy(&self.binding, auth.policy, auth.local, auth.peer)?;
            self.time()?;
            if self.backend.current_binding()? != self.binding {
                return Err(PeerFailureV1::ContextMismatch);
            }
        }
        Ok(())
    }
    fn context(&self, sending: bool) -> ReportDataContextV1 {
        let mut context = if sending {
            self.binding.request.local.clone()
        } else {
            self.binding.request.peer.clone()
        };
        context.th1 = self.binding.th1;
        context
    }
    fn validate(
        &self,
        message: &PeerMessageV1,
        sending: bool,
    ) -> Result<Option<u8>, PeerFailureV1> {
        let expected = self.context(sending);
        match (&self.binding.request.purpose, message) {
            (PeerPurposeV1::InterNode(_), PeerMessageV1::InterNode(frame)) => {
                let (opcode, payload) = frame.layout()?;
                let source = expected.role == SnpMaRoleV1::Source;
                if (opcode & 1 == 0) != source
                    || (self.state == PeerSessionStateV1::Bootstrap
                        && !matches!(opcode, 0x20..=0x23))
                {
                    return Err(PeerFailureV1::UnexpectedMessage);
                }
                match opcode {
                    0x20 | 0x21 => {
                        let evidence = SnpMaEvidenceV1::decode_exact(payload)?;
                        if self.state == PeerSessionStateV1::Bootstrap {
                            if evidence.report_data_context != expected {
                                return Err(PeerFailureV1::ContextMismatch);
                            }
                        } else {
                            self.validate_context(&evidence.report_data_context, &expected)?;
                        }
                    }
                    0x22 | 0x23 => {
                        SnpCollateralSetV1::decode_exact(payload)?;
                    }
                    0x24 => {
                        self.validate_context(
                            &SnpTenantEvidenceV1::decode_exact(payload)?.report_data_context,
                            &expected,
                        )?;
                    }
                    0x25 => {
                        let result = SnpAuthorizationResultV1::decode_exact(payload)?;
                        if result.request_id != expected.request_id
                            || result.algorithm != expected.algorithm
                            || result.negotiated_migration_version
                                != expected.negotiated_migration_version
                        {
                            return Err(PeerFailureV1::ContextMismatch);
                        }
                    }
                    0x30..=0x35 => {
                        let context = self
                            .installation
                            .as_ref()
                            .ok_or(PeerFailureV1::InvalidState)?;
                        ProtectedInstallRecordV2::from_peer(opcode, payload, context)?;
                    }
                    _ => return Err(PeerFailureV1::UnexpectedMessage),
                }
                Ok(Some(opcode))
            }
            (
                PeerPurposeV1::LocalPlanned {
                    binding,
                    metadata_digest,
                },
                PeerMessageV1::Local(message),
            ) => {
                match message {
                    LocalPeerMessageV1::MaEvidence(evidence) => {
                        evidence.encode_exact()?;
                        if evidence.report_data_context != expected {
                            return Err(PeerFailureV1::ContextMismatch);
                        }
                    }
                    LocalPeerMessageV1::Collateral(collateral) => {
                        collateral.encode_exact()?;
                    }
                    LocalPeerMessageV1::Metadata(metadata)
                        if self.state == PeerSessionStateV1::Active =>
                    {
                        if metadata.digest()? != *metadata_digest {
                            return Err(PeerFailureV1::ContextMismatch);
                        }
                    }
                    LocalPeerMessageV1::HandoffSecret(_)
                        if self.state == PeerSessionStateV1::Active
                            && expected.role == SnpMaRoleV1::Outgoing
                            && binding.stage == SnpOperationStageV1::PrepareAuthorization => {}
                    _ => return Err(PeerFailureV1::UnexpectedMessage),
                }
                Ok(None)
            }
            _ => Err(PeerFailureV1::UnexpectedMessage),
        }
    }
    fn validate_context(
        &self,
        context: &ReportDataContextV1,
        expected: &ReportDataContextV1,
    ) -> Result<(), PeerFailureV1> {
        if !matches!(
            context.evidence_purpose,
            SnpEvidencePurposeV1::InterNodeSessionV2
                | SnpEvidencePurposeV1::InterNodeTenantAuthorizationV2
        ) || context.role != expected.role
            || context.th1 != expected.th1
            || context.request_id != expected.request_id
            || context.tenant_binding_id != expected.tenant_binding_id
            || context.algorithm != expected.algorithm
            || context.negotiated_migration_version != expected.negotiated_migration_version
            || context.ma_policy_identity_digest != expected.ma_policy_identity_digest
            || (context.evidence_purpose == SnpEvidencePurposeV1::InterNodeSessionV2
                && context.purpose_binding_digest != expected.purpose_binding_digest)
        {
            return Err(PeerFailureV1::ContextMismatch);
        }
        Ok(())
    }
    fn correlate(&mut self, opcode: Option<u8>, sending: bool) -> Result<(), PeerFailureV1> {
        if let Some(opcode) = opcode {
            let local_source = self.binding.request.local.role == SnpMaRoleV1::Source;
            if local_source == sending {
                if self.pending.is_some() {
                    return Err(PeerFailureV1::InvalidState);
                }
                self.pending = Some(opcode + 1);
            } else {
                if self.pending != Some(opcode) {
                    return Err(PeerFailureV1::UnexpectedMessage);
                }
                self.pending = None;
            }
        }
        Ok(())
    }
    fn send(
        &mut self,
        message: PeerMessageV1,
        auth: Option<&PeerAuthorizationV1<'_>>,
    ) -> Result<(), PeerChannelErrorV1> {
        let result = (|| {
            self.check(auth)?;
            let opcode = self.validate(&message, true)?;
            self.correlate(opcode, true)?;
            self.backend.send(
                &PeerPacketV1 {
                    binding: self.binding.clone(),
                    message,
                },
                self.binding.request.deadline,
            )?;
            self.check(auth)
        })();
        result.map_err(|e| self.fail(e))
    }
    fn receive(
        &mut self,
        auth: Option<&PeerAuthorizationV1<'_>>,
    ) -> Result<PeerMessageV1, PeerChannelErrorV1> {
        let result = (|| {
            self.check(auth)?;
            let packet = self.backend.receive(self.binding.request.deadline)?;
            self.check(auth)?;
            if packet.binding != self.binding {
                return Err(PeerFailureV1::ContextMismatch);
            }
            let opcode = self.validate(&packet.message, false)?;
            self.correlate(opcode, false)?;
            Ok(packet.message)
        })();
        result.map_err(|e| self.fail(e))
    }
    fn close(&mut self, auth: Option<&PeerAuthorizationV1<'_>>) -> Result<(), PeerChannelErrorV1> {
        if self.state == PeerSessionStateV1::Closed {
            return Ok(());
        }
        let result = (|| {
            self.check(auth)?;
            if self.pending.is_some() {
                return Err(PeerFailureV1::InvalidState);
            }
            self.backend.close(self.binding.request.deadline)?;
            self.time()?;
            self.state = PeerSessionStateV1::Closed;
            Ok(())
        })();
        result.map_err(|e| self.fail(e))
    }
    fn abort(&mut self) -> Result<(), PeerChannelErrorV1> {
        match self.state {
            PeerSessionStateV1::Closed | PeerSessionStateV1::Aborted => Ok(()),
            PeerSessionStateV1::ReconciliationRequired => Err(PeerFailureV1::InvalidState.into()),
            _ => {
                let error = self.fail(PeerFailureV1::Aborted);
                if error.cleanup_error.is_some() {
                    Err(error)
                } else {
                    Ok(())
                }
            }
        }
    }
}
impl<B: PeerSession, C: PeerClockV1> Drop for PeerCore<B, C> {
    fn drop(&mut self) {
        if matches!(
            self.state,
            PeerSessionStateV1::Bootstrap | PeerSessionStateV1::Active
        ) {
            log::warn!("SNP peer session dropped without explicit close/abort");
            let error = self.fail(PeerFailureV1::Aborted);
            if let Some(cleanup) = error.cleanup_error {
                log::error!(
                    "SNP peer cleanup failed; reconciliation required: {:?}",
                    cleanup
                );
            }
        }
    }
}

/// No application send API exists until evidence/policy promotion succeeds.
///
/// ```compile_fail
/// use pal::snp::peer_channel::*;
/// fn bypass<B: PeerSession,C: PeerClockV1>(mut pending: PendingPeerSessionV1<B,C>,
///     message: InterNodeVdmV1) { pending.send(message); }
/// ```
pub struct PendingPeerSessionV1<B: PeerSession, C: PeerClockV1> {
    core: PeerCore<B, C>,
}
impl<B: PeerSession, C: PeerClockV1> PendingPeerSessionV1<B, C> {
    pub fn establish<F: PeerTransportFactory<Session = B>>(
        factory: &mut F,
        request: PeerSessionRequestV1,
        clock: C,
    ) -> Result<Self, PeerChannelErrorV1> {
        let now = clock
            .unix_seconds()
            .map_err(|e| PeerChannelErrorV1::from(PeerFailureV1::Provider(e)))?;
        if now >= request.deadline {
            return Err(PeerFailureV1::Expired.into());
        }
        let backend = factory.establish(&request)?;
        let observed = backend.current_binding();
        let mut core = PeerCore {
            backend,
            clock,
            binding: SpdmPeerBindingV1 {
                request: request.clone(),
                spdm_session_id: 0,
                th1: [0; 48],
            },
            state: PeerSessionStateV1::Bootstrap,
            last_time: now,
            pending: None,
            installation: None,
        };
        let binding = observed.map_err(|e| core.fail(e.into()))?;
        if binding.request != request {
            return Err(core.fail(PeerFailureV1::ContextMismatch));
        }
        core.binding = binding;
        core.check(None).map_err(|e| core.fail(e))?;
        Ok(Self { core })
    }
    pub fn expected_context(&self, local: bool) -> ReportDataContextV1 {
        self.core.context(local)
    }
    pub fn send_bootstrap(&mut self, message: PeerMessageV1) -> Result<(), PeerChannelErrorV1> {
        self.core.send(message, None)
    }
    pub fn receive_bootstrap(&mut self) -> Result<PeerMessageV1, PeerChannelErrorV1> {
        self.core.receive(None)
    }
    fn authorize<'a>(
        &mut self,
        policy: &'a VerifiedLmPolicyV1,
        local: &'a VerifiedMaPolicyCollateral,
        peer: &'a VerifiedMaPolicyCollateral,
    ) -> Result<PeerAuthorizationV1<'a>, PeerChannelErrorV1> {
        let auth = PeerAuthorizationV1 {
            policy,
            local,
            peer,
        };
        let result = (|| {
            self.core.check(None)?;
            if self.core.pending.is_some()
                || local.context() != &self.core.context(true)
                || peer.context() != &self.core.context(false)
                || local.policy_digest() != policy.digest()
                || peer.policy_digest() != policy.digest()
            {
                return Err(PeerFailureV1::ContextMismatch);
            }
            if let PeerPurposeV1::LocalPlanned { binding, .. } = &self.core.binding.request.purpose
            {
                let (outgoing, incoming) = if local.context().role == SnpMaRoleV1::Outgoing {
                    (local, peer)
                } else {
                    (peer, local)
                };
                if outgoing.report_id() != &binding.previous_ma_report_id
                    || incoming.report_id() != &binding.new_ma_report_id
                {
                    return Err(PeerFailureV1::ContextMismatch);
                }
            }
            self.core.check(Some(&auth))?;
            self.core.state = PeerSessionStateV1::Active;
            Ok(())
        })();
        result.map_err(|e| self.core.fail(e))?;
        Ok(auth)
    }
    pub fn into_inter_node<'a>(
        mut self,
        policy: &'a VerifiedLmPolicyV1,
        local: &'a VerifiedMaPolicyCollateral,
        peer: &'a VerifiedMaPolicyCollateral,
    ) -> Result<InterNodeMigrationPeerSession<'a, B, C>, PeerChannelErrorV1> {
        if !matches!(
            self.core.binding.request.purpose,
            PeerPurposeV1::InterNode(_)
        ) {
            return Err(self.core.fail(PeerFailureV1::ContextMismatch));
        }
        let auth = self.authorize(policy, local, peer)?;
        Ok(InterNodeMigrationPeerSession {
            core: self.core,
            auth,
        })
    }
    pub fn into_local_handoff<'a>(
        mut self,
        policy: &'a VerifiedLmPolicyV1,
        local: &'a VerifiedMaPolicyCollateral,
        peer: &'a VerifiedMaPolicyCollateral,
    ) -> Result<LocalMaHandoffPeerSession<'a, B, C>, PeerChannelErrorV1> {
        if !matches!(
            self.core.binding.request.purpose,
            PeerPurposeV1::LocalPlanned { .. }
        ) {
            return Err(self.core.fail(PeerFailureV1::ContextMismatch));
        }
        let auth = self.authorize(policy, local, peer)?;
        Ok(LocalMaHandoffPeerSession {
            core: self.core,
            auth,
        })
    }
    pub fn abort(&mut self) -> Result<(), PeerChannelErrorV1> {
        self.core.abort()
    }
}

/// These types cannot be interchanged, cloned or publicly constructed.
///
/// ```compile_fail
/// use pal::snp::peer_channel::*;
/// fn crossed<B: PeerSession,C: PeerClockV1>(local: LocalMaHandoffPeerSession<'_,B,C>) {
///     let migration: InterNodeMigrationPeerSession<'_,B,C> = local;
/// }
/// ```
///
/// ```compile_fail
/// use pal::snp::peer_channel::*;
/// fn duplicate<B: PeerSession,C: PeerClockV1>(s: InterNodeMigrationPeerSession<'_,B,C>) {
///     s.clone();
/// }
/// ```
pub struct InterNodeMigrationPeerSession<'a, B: PeerSession, C: PeerClockV1> {
    core: PeerCore<B, C>,
    auth: PeerAuthorizationV1<'a>,
}
pub struct LocalMaHandoffPeerSession<'a, B: PeerSession, C: PeerClockV1> {
    core: PeerCore<B, C>,
    auth: PeerAuthorizationV1<'a>,
}

impl<B: PeerSession, C: PeerClockV1> InterNodeMigrationPeerSession<'_, B, C> {
    /// Trusted orchestration supplies the independently reconstructed V2 context,
    /// not a peer reference. Policy/replay/current-firmware admission is separate.
    pub fn bind_installation(
        &mut self,
        session: &MigrationSessionContextV2,
    ) -> Result<(), PeerChannelErrorV1> {
        let result = (|| {
            self.core.check(Some(&self.auth))?;
            if self.core.installation.is_some()
                || self.core.pending.is_some()
                || session.reference().request_id != self.core.binding.request.local.request_id
                || session.role()
                    != match self.core.binding.request.local.role {
                        SnpMaRoleV1::Source => MigrationRole::Source,
                        _ => MigrationRole::Destination,
                    }
                || session.source_context()
                    != if self.auth.local.context().role == SnpMaRoleV1::Source {
                        self.auth.local.context()
                    } else {
                        self.auth.peer.context()
                    }
                || session.destination_context()
                    != if self.auth.local.context().role == SnpMaRoleV1::Destination {
                        self.auth.local.context()
                    } else {
                        self.auth.peer.context()
                    }
            {
                return Err(PeerFailureV1::ContextMismatch);
            }
            self.core.installation = Some(session.clone());
            Ok(())
        })();
        result.map_err(|e| self.core.fail(e))
    }
    pub fn send(&mut self, frame: InterNodeVdmV1) -> Result<(), PeerChannelErrorV1> {
        self.core
            .send(PeerMessageV1::InterNode(frame), Some(&self.auth))
    }
    pub fn receive(&mut self) -> Result<InterNodeVdmV1, PeerChannelErrorV1> {
        match self.core.receive(Some(&self.auth))? {
            PeerMessageV1::InterNode(frame) => Ok(frame),
            _ => Err(self.core.fail(PeerFailureV1::UnexpectedMessage)),
        }
    }
    /// The receipt escapes only after successful encrypted I/O and both current
    /// binding/policy checks. Parsing a public acceptance record is insufficient.
    pub fn send_installation(
        &mut self,
        frame: InterNodeVdmV1,
    ) -> Result<ProtectedInstallRecordV2, PeerChannelErrorV1> {
        let token = self.installation_record(&frame)?;
        self.send(frame)?;
        Ok(token)
    }
    pub fn receive_installation(&mut self) -> Result<ProtectedInstallRecordV2, PeerChannelErrorV1> {
        let frame = self.receive()?;
        self.installation_record(&frame)
    }
    pub fn send_key(
        &mut self,
        key: MigrationKeyV2,
    ) -> Result<ProtectedInstallRecordV2, PeerChannelErrorV1> {
        let bytes = key
            .encode_delivery()
            .map_err(|e| self.core.fail(e.into()))?;
        let frame = InterNodeVdmV1::new(0x30, bytes.as_ref())?;
        self.send_installation(frame)
    }
    fn installation_record(
        &mut self,
        frame: &InterNodeVdmV1,
    ) -> Result<ProtectedInstallRecordV2, PeerChannelErrorV1> {
        let result = (|| {
            self.core.check(Some(&self.auth))?;
            let context = self
                .core
                .installation
                .as_ref()
                .ok_or(PeerFailureV1::InvalidState)?;
            let (opcode, payload) = frame.layout()?;
            ProtectedInstallRecordV2::from_peer(opcode, payload, context)
                .map_err(PeerFailureV1::from)
        })();
        result.map_err(|e| self.core.fail(e))
    }
}
impl<B: PeerSession, C: PeerClockV1> LocalMaHandoffPeerSession<'_, B, C> {
    pub fn send(&mut self, message: LocalPeerMessageV1) -> Result<(), PeerChannelErrorV1> {
        self.core
            .send(PeerMessageV1::Local(message), Some(&self.auth))
    }
    pub fn receive(&mut self) -> Result<LocalPeerMessageV1, PeerChannelErrorV1> {
        match self.core.receive(Some(&self.auth))? {
            PeerMessageV1::Local(message) => Ok(message),
            _ => Err(self.core.fail(PeerFailureV1::UnexpectedMessage)),
        }
    }
}
macro_rules! lifecycle {
    ($name:ident) => {
        impl<B: PeerSession, C: PeerClockV1> $name<'_, B, C> {
            pub fn state(&self) -> PeerSessionStateV1 {
                self.core.state
            }
            pub fn close(&mut self) -> Result<(), PeerChannelErrorV1> {
                self.core.close(Some(&self.auth))
            }
            pub fn abort(&mut self) -> Result<(), PeerChannelErrorV1> {
                self.core.abort()
            }
        }
    };
}
lifecycle!(InterNodeMigrationPeerSession);
lifecycle!(LocalMaHandoffPeerSession);

pub struct UnavailablePeerTransportFactoryV1;
pub struct UnavailablePeerSessionV1;
impl PeerTransportFactory for UnavailablePeerTransportFactoryV1 {
    type Session = UnavailablePeerSessionV1;
    fn establish(&mut self, _: &PeerSessionRequestV1) -> Result<Self::Session, PeerChannelErrorV1> {
        Err(PeerFailureV1::Provider(PeerProviderErrorV1::Unavailable).into())
    }
}
impl PeerSession for UnavailablePeerSessionV1 {
    fn current_binding(&self) -> Result<SpdmPeerBindingV1, PeerProviderErrorV1> {
        Err(PeerProviderErrorV1::Unavailable)
    }
    fn recheck_policy(
        &mut self,
        _: &SpdmPeerBindingV1,
        _: &VerifiedLmPolicyV1,
        _: &VerifiedMaPolicyCollateral,
        _: &VerifiedMaPolicyCollateral,
    ) -> Result<(), PeerProviderErrorV1> {
        Err(PeerProviderErrorV1::Unavailable)
    }
    fn send(&mut self, _: &PeerPacketV1, _: u64) -> Result<(), PeerProviderErrorV1> {
        Err(PeerProviderErrorV1::Unavailable)
    }
    fn receive(&mut self, _: u64) -> Result<PeerPacketV1, PeerProviderErrorV1> {
        Err(PeerProviderErrorV1::Unavailable)
    }
    fn close(&mut self, _: u64) -> Result<(), PeerProviderErrorV1> {
        Err(PeerProviderErrorV1::Unavailable)
    }
    fn abort(&mut self, _: u64) -> Result<(), PeerProviderErrorV1> {
        Err(PeerProviderErrorV1::Unavailable)
    }
}
