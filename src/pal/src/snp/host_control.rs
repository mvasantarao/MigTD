// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SNP logical host frames and operation ownership, not a GHCB or kernel ABI.

use super::{
    collateral_set::SnpCollateralSetV1,
    local_handoff::LocalMaControlV1,
    migration_install::{MigrationInstallCompletionV1, MigrationInstallErrorV1},
    purpose_binding::sha384,
    tenant_source::{
        HostPushedTenantEvidenceSource, TenantEvidence, TenantEvidenceBinding, TenantEvidenceError,
        TenantEvidencePackage, TenantEvidenceRequest, TenantEvidenceSource,
    },
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};
use crate::{
    snp_report::{SnpEmulatorEvidenceV1, SnpEvidenceInput},
    tenant_identity::{
        HostPushedTenantReportV1, PrepareMigrationRequestV1, TenantReportDeliveryV1,
        TenantReportReferenceV1,
    },
    tenant_replay::{
        CurrentTenantFirmwareStateV1, DurableTenantReplayStoreV1, ReplayTerminalOutcomeV1,
        ReplayTerminalResultV1, TenantReplayAdmissionV1, TenantReplayStateV1,
        VerifiedTenantAuthorizationV1, VerifiedTenantReplayBindingV1,
    },
    types::{
        HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, PeerRoutingReference,
        PolicyIdentity, ProtocolVersion, SnpOperationContext,
    },
};

pub const MAX_HOST_CONTROL_FRAME_V1: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HostControlKindV1 {
    Prepare = 1,
    Cancel = 2,
    Abort = 3,
    Query = 4,
    LocalHandoff = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HostOperationPhaseV1 {
    AwaitingEvidence = 0,
    EvidenceReceived = 1,
    SourceEvidenceMatched = 2,
    SessionEvidenceVerified = 3,
    Authorized = 4,
    InstallationStarted = 5,
    InstalledLocally = 6,
    Terminal = 7,
    ReconciliationRequired = 8,
}

impl HostOperationPhaseV1 {
    fn decode(value: u8) -> SnpCodecResult<Self> {
        match value {
            0 => Ok(Self::AwaitingEvidence),
            1 => Ok(Self::EvidenceReceived),
            2 => Ok(Self::SourceEvidenceMatched),
            3 => Ok(Self::SessionEvidenceVerified),
            4 => Ok(Self::Authorized),
            5 => Ok(Self::InstallationStarted),
            6 => Ok(Self::InstalledLocally),
            7 => Ok(Self::Terminal),
            8 => Ok(Self::ReconciliationRequired),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }
}

/// Complete untrusted report/supplement/signature/collateral for each MA.
/// These profiles select no verifier, root, policy or expected REPORT_DATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMaProfilesV1 {
    pub source: TenantEvidencePackage,
    pub destination: TenantEvidencePackage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostControlBodyV1 {
    Prepare {
        request: PrepareMigrationRequestV1,
        package: Option<Box<TenantEvidencePackage>>,
        package_digest: [u8; 48],
        ma_profiles: Box<HostMaProfilesV1>,
    },
    Empty,
    Status {
        phase: HostOperationPhaseV1,
        terminal: Option<ReplayTerminalResultV1>,
    },
    Local(Box<LocalMaControlV1>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostControlFrameV1 {
    pub kind: HostControlKindV1,
    pub response: bool,
    pub operation: SnpOperationContext,
    pub body: HostControlBodyV1,
}

pub(crate) fn encode_operation(
    w: &mut StrictWriter<'_>,
    operation: &SnpOperationContext,
) -> SnpCodecResult<()> {
    w.write_u64(operation.request_id.value())?;
    w.write_u64(operation.migration_id.value())?;
    w.write_u64(operation.managed_guest.value())?;
    w.write_u64(operation.peer.map_or(0, |v| v.value()))?;
    w.write_u64(operation.policy.map_or(0, |v| v.value()))?;
    let version = operation
        .protocol_version
        .unwrap_or(ProtocolVersion::new(0, 0));
    w.write_u16(version.major)?;
    w.write_u16(version.minor)?;
    w.write_u8(match operation.role {
        MigrationRole::Source => 1,
        MigrationRole::Destination => 0,
    })?;
    w.write_u8(
        u8::from(operation.peer.is_some())
            | (u8::from(operation.policy.is_some()) << 1)
            | (u8::from(operation.protocol_version.is_some()) << 2),
    )?;
    w.write_zeroes(2)
}

pub(crate) fn decode_operation(r: &mut StrictReader<'_>) -> SnpCodecResult<SnpOperationContext> {
    let request_id = HostRequestId::new(r.read_u64()?);
    let migration_id = MigrationId::new(r.read_u64()?);
    let managed_guest = ManagedGuestHandle::new(r.read_u64()?);
    let peer = r.read_u64()?;
    let policy = r.read_u64()?;
    let version = ProtocolVersion::new(r.read_u16()?, r.read_u16()?);
    let role =
        MigrationRole::try_from(r.read_u8()?).map_err(|_| SnpCodecError::UnknownEnumValue)?;
    let flags = r.read_u8()?;
    r.read_zeroes(2)?;
    if flags & !7 != 0
        || (flags & 1 == 0 && peer != 0)
        || (flags & 2 == 0 && policy != 0)
        || (flags & 4 == 0 && version != ProtocolVersion::new(0, 0))
    {
        return Err(SnpCodecError::NonCanonicalEncoding);
    }
    Ok(SnpOperationContext {
        request_id,
        migration_id,
        managed_guest,
        role,
        peer: (flags & 1 != 0).then_some(PeerRoutingReference::new(peer)),
        policy: (flags & 2 != 0).then_some(PolicyIdentity::new(policy)),
        protocol_version: (flags & 4 != 0).then_some(version),
    })
}

impl TenantEvidencePackage {
    /// Application packaging only; this digest is not verification or a new
    /// meaning for the frozen SHA384(base-report) reference.
    pub fn encode_host_package_v1(&self) -> SnpCodecResult<Vec<u8>> {
        let collateral = self.collateral().encode_exact()?;
        let extra = match self.evidence() {
            SnpEvidenceInput::EmulatorV1(_) => 316,
            SnpEvidenceInput::RawAmdReport { .. } => 0,
        };
        let mut bytes = vec![0; 8 + 1184 + extra + collateral.len()];
        let mut w = StrictWriter::new(&mut bytes);
        w.write_u8(u8::from(extra != 0))?;
        w.write_zeroes(3)?;
        w.write_u32(collateral.len() as u32)?;
        w.write_bytes(self.evidence().report())?;
        if let SnpEvidenceInput::EmulatorV1(evidence) = self.evidence() {
            w.write_bytes(&evidence.supplement)?;
            w.write_bytes(&evidence.supplement_signature)?;
        }
        w.write_bytes(&collateral)?;
        Ok(bytes)
    }

    pub fn decode_host_package_v1(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut r = StrictReader::new(bytes);
        let profile = r.read_u8()?;
        r.read_zeroes(3)?;
        let length = r.read_u32()?;
        let report = r.read_array()?;
        let evidence = match profile {
            0 => SnpEvidenceInput::RawAmdReport {
                report: Box::new(report),
            },
            1 => SnpEvidenceInput::EmulatorV1(Box::new(SnpEmulatorEvidenceV1 {
                report,
                supplement: r.read_array()?,
                supplement_signature: r.read_array()?,
            })),
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let collateral = SnpCollateralSetV1::decode_exact(
            r.read_bounded_bytes(length, super::limits::MAX_SNP_COLLATERAL_SET_SIZE)?,
        )?;
        r.finish()?;
        Self::new(evidence, collateral).map_err(|_| SnpCodecError::NonCanonicalEncoding)
    }
}

fn write_package(w: &mut StrictWriter<'_>, package: &TenantEvidencePackage) -> SnpCodecResult<()> {
    let bytes = package.encode_host_package_v1()?;
    w.write_u32(bytes.len() as u32)?;
    w.write_bytes(&bytes)
}

fn read_package(r: &mut StrictReader<'_>) -> SnpCodecResult<TenantEvidencePackage> {
    let length = r.read_u32()?;
    TenantEvidencePackage::decode_host_package_v1(
        r.read_bounded_bytes(length, MAX_HOST_CONTROL_FRAME_V1)?,
    )
}

impl HostControlFrameV1 {
    pub const HEADER_SIZE: usize = 72;

    fn validate(&self) -> SnpCodecResult<()> {
        match (&self.body, self.response, self.kind) {
            (
                HostControlBodyV1::Prepare {
                    request,
                    package,
                    package_digest,
                    ..
                },
                false,
                HostControlKindV1::Prepare,
            ) => {
                if request.operation() != &self.operation {
                    return Err(SnpCodecError::NonCanonicalEncoding);
                }
                match (request.delivery(), package) {
                    (TenantReportDeliveryV1::Inline(report), Some(package))
                        if package.evidence().report() == report.as_bytes()
                            && sha384(&package.encode_host_package_v1()?) == *package_digest => {}
                    (TenantReportDeliveryV1::Reference(_), None) => {}
                    _ => return Err(SnpCodecError::NonCanonicalEncoding),
                }
            }
            (
                HostControlBodyV1::Empty,
                false,
                HostControlKindV1::Cancel | HostControlKindV1::Abort | HostControlKindV1::Query,
            ) => {}
            (HostControlBodyV1::Status { phase, terminal }, true, kind)
                if kind != HostControlKindV1::LocalHandoff
                    && (*phase == HostOperationPhaseV1::Terminal) == terminal.is_some() => {}
            (HostControlBodyV1::Local(local), _, HostControlKindV1::LocalHandoff) => {
                if local.binding.request_id != self.operation.request_id.value() {
                    return Err(SnpCodecError::NonCanonicalEncoding);
                }
                local.encode_exact()?;
            }
            _ => return Err(SnpCodecError::NonCanonicalEncoding),
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = vec![0; MAX_HOST_CONTROL_FRAME_V1];
        let mut w = StrictWriter::new(&mut bytes);
        w.write_bytes(b"SNP-HC01")?;
        w.write_u16(1)?;
        w.write_u16(self.kind as u16)?;
        w.write_u8(u8::from(self.response))?;
        w.write_zeroes(3)?;
        w.write_u32(0)?;
        w.write_zeroes(4)?;
        encode_operation(&mut w, &self.operation)?;
        match &self.body {
            HostControlBodyV1::Prepare {
                request,
                package,
                package_digest,
                ma_profiles,
            } => {
                w.write_bytes(package_digest)?;
                match request.delivery() {
                    TenantReportDeliveryV1::Inline(_) => {
                        w.write_u8(1)?;
                        write_package(
                            &mut w,
                            package
                                .as_ref()
                                .ok_or(SnpCodecError::NonCanonicalEncoding)?,
                        )?;
                    }
                    TenantReportDeliveryV1::Reference(reference) => {
                        w.write_u8(2)?;
                        w.write_bytes(reference.sha384())?;
                    }
                }
                write_package(&mut w, &ma_profiles.source)?;
                write_package(&mut w, &ma_profiles.destination)?;
            }
            HostControlBodyV1::Empty => {}
            HostControlBodyV1::Status { phase, terminal } => {
                w.write_u8(*phase as u8)?;
                w.write_u8(match terminal.map(|v| v.outcome) {
                    None => 0,
                    Some(ReplayTerminalOutcomeV1::Succeeded) => 1,
                    Some(ReplayTerminalOutcomeV1::Aborted) => 2,
                    Some(ReplayTerminalOutcomeV1::Failed) => 3,
                })?;
                w.write_zeroes(2)?;
                w.write_bytes(&terminal.map_or([0; 48], |v| v.result_digest))?;
            }
            HostControlBodyV1::Local(local) => w.write_bytes(&local.encode_exact()?)?,
        }
        let length = w.written();
        bytes.truncate(length);
        bytes[16..20].copy_from_slice(&(length as u32).to_le_bytes());
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        if bytes.len() > MAX_HOST_CONTROL_FRAME_V1 {
            return Err(SnpCodecError::RecordTooLarge);
        }
        let mut r = StrictReader::new(bytes);
        if r.read_array::<8>()? != *b"SNP-HC01" {
            return Err(SnpCodecError::InvalidMagic);
        }
        if r.read_u16()? != 1 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        let kind = match r.read_u16()? {
            1 => HostControlKindV1::Prepare,
            2 => HostControlKindV1::Cancel,
            3 => HostControlKindV1::Abort,
            4 => HostControlKindV1::Query,
            5 => HostControlKindV1::LocalHandoff,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let response = match r.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        r.read_zeroes(3)?;
        if r.read_u32()? as usize != bytes.len() {
            return Err(SnpCodecError::InvalidLength);
        }
        r.read_zeroes(4)?;
        let operation = decode_operation(&mut r)?;
        let body = if kind == HostControlKindV1::LocalHandoff {
            let remaining = r.remaining();
            HostControlBodyV1::Local(Box::new(LocalMaControlV1::decode_exact(
                r.take(remaining)?,
            )?))
        } else if response {
            let phase = HostOperationPhaseV1::decode(r.read_u8()?)?;
            let outcome = r.read_u8()?;
            r.read_zeroes(2)?;
            let result_digest = r.read_array()?;
            let terminal = match outcome {
                0 if result_digest == [0; 48] => None,
                1 => Some(ReplayTerminalResultV1 {
                    outcome: ReplayTerminalOutcomeV1::Succeeded,
                    result_digest,
                }),
                2 => Some(ReplayTerminalResultV1 {
                    outcome: ReplayTerminalOutcomeV1::Aborted,
                    result_digest,
                }),
                3 => Some(ReplayTerminalResultV1 {
                    outcome: ReplayTerminalOutcomeV1::Failed,
                    result_digest,
                }),
                _ => return Err(SnpCodecError::NonCanonicalEncoding),
            };
            HostControlBodyV1::Status { phase, terminal }
        } else if kind == HostControlKindV1::Prepare {
            let package_digest = r.read_array()?;
            let (delivery, package) = match r.read_u8()? {
                1 => {
                    let package = read_package(&mut r)?;
                    let report = HostPushedTenantReportV1::from_bytes(package.evidence().report())
                        .map_err(|_| SnpCodecError::InvalidLength)?;
                    (
                        TenantReportDeliveryV1::Inline(report),
                        Some(Box::new(package)),
                    )
                }
                2 => (
                    TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new(
                        r.read_array()?,
                    )),
                    None,
                ),
                _ => return Err(SnpCodecError::UnknownEnumValue),
            };
            HostControlBodyV1::Prepare {
                request: PrepareMigrationRequestV1::new(operation, delivery),
                package,
                package_digest,
                ma_profiles: Box::new(HostMaProfilesV1 {
                    source: read_package(&mut r)?,
                    destination: read_package(&mut r)?,
                }),
            }
        } else {
            HostControlBodyV1::Empty
        };
        r.finish()?;
        let value = Self {
            kind,
            response,
            operation,
            body,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostControlErrorV1 {
    Codec(SnpCodecError),
    Evidence(TenantEvidenceError),
    CorrelationMismatch,
    InvalidState,
    ConflictingDelivery,
    ReconciliationRequired,
    ProviderUnavailable,
    #[cfg(test)]
    Confirmation(super::confirmation::SnpConfirmationVerificationErrorV1),
    #[cfg(test)]
    PeerInstallation {
        outcome: super::control_exchange::FirmwareCompletionOutcomeV1,
        effect: super::control_exchange::FirmwareCompletionEffectV1,
        raw_firmware_status: Option<u32>,
    },
    PeerInstallationV2 {
        outcome: super::direct_exchange::FirmwareCompletionOutcomeV2,
        effect: super::direct_exchange::FirmwareCompletionEffectV2,
        raw_firmware_status: Option<u32>,
    },
}

impl From<TenantEvidenceError> for HostControlErrorV1 {
    fn from(error: TenantEvidenceError) -> Self {
        Self::Evidence(error)
    }
}
impl From<SnpCodecError> for HostControlErrorV1 {
    fn from(error: SnpCodecError) -> Self {
        Self::Codec(error)
    }
}

/// Transport adapters move bounded logical frames only. They neither authorize
/// effects nor select trusted state/verifiers. Production GHCB support is external.
pub trait SnpHostControlTransportV1 {
    fn receive(&mut self) -> Result<HostControlFrameV1, HostControlErrorV1>;
    fn respond(&mut self, response: &HostControlFrameV1) -> Result<(), HostControlErrorV1>;
}

pub struct UnavailableSnpHostControlTransportV1;
impl SnpHostControlTransportV1 for UnavailableSnpHostControlTransportV1 {
    fn receive(&mut self) -> Result<HostControlFrameV1, HostControlErrorV1> {
        Err(HostControlErrorV1::ProviderUnavailable)
    }
    fn respond(&mut self, _: &HostControlFrameV1) -> Result<(), HostControlErrorV1> {
        Err(HostControlErrorV1::ProviderUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostControlClaimV1 {
    ReservedNewOperation,
    ExistingOperation,
    Terminal(ReplayTerminalResultV1),
}

/// Trusted, bounded, authenticated and rollback-anchored pre-proof tombstones.
/// Atomically reserve the complete operation before starting any peer session.
/// Retain across restart/handoff; reject conflicting request IDs and missing/
/// unprovisioned state. Existing operations cannot establish a replacement
/// session. P0.6 remains the separate verified authorization/result journal.
pub trait HostControlContextAuthorityV1 {
    fn reserve_operation(
        &mut self,
        operation: &SnpOperationContext,
    ) -> Result<HostControlClaimV1, HostControlErrorV1>;
    /// Durably record failure/abort before a verified P0.6 binding exists.
    fn finish_before_proofs(
        &mut self,
        operation: &SnpOperationContext,
        result: ReplayTerminalResultV1,
    ) -> Result<(), HostControlErrorV1>;
}

pub struct UnavailableHostControlContextAuthorityV1;
impl HostControlContextAuthorityV1 for UnavailableHostControlContextAuthorityV1 {
    fn reserve_operation(
        &mut self,
        _: &SnpOperationContext,
    ) -> Result<HostControlClaimV1, HostControlErrorV1> {
        Err(HostControlErrorV1::ProviderUnavailable)
    }
    fn finish_before_proofs(
        &mut self,
        _: &SnpOperationContext,
        _: ReplayTerminalResultV1,
    ) -> Result<(), HostControlErrorV1> {
        Err(HostControlErrorV1::ProviderUnavailable)
    }
}

/// Retain this owner across all delivery retries. Cryptography, policy, key
/// scheduling and protected sessions remain independently required composition.
pub struct SnpHostOperationV1<'a, S, F, C> {
    operation: SnpOperationContext,
    source: HostPushedTenantEvidenceSource<'a, S, F>,
    phase: HostOperationPhaseV1,
    profiles: Option<Box<HostMaProfilesV1>>,
    package_digest: Option<[u8; 48]>,
    binding: Option<VerifiedTenantReplayBindingV1>,
    session: Option<super::direct_key::SnpSessionReferenceV2>,
    terminal: Option<ReplayTerminalResultV1>,
    context: C,
}

impl<
        'a,
        S: DurableTenantReplayStoreV1,
        F: CurrentTenantFirmwareStateV1,
        C: HostControlContextAuthorityV1,
    > SnpHostOperationV1<'a, S, F, C>
{
    pub fn new(
        operation: SnpOperationContext,
        mut source: HostPushedTenantEvidenceSource<'a, S, F>,
        mut context: C,
    ) -> Result<Self, HostControlErrorV1> {
        let restored = source.query_operation(&operation)?;
        let (phase, terminal) = match restored {
            None => match context.reserve_operation(&operation)? {
                HostControlClaimV1::ReservedNewOperation => {
                    (HostOperationPhaseV1::AwaitingEvidence, None)
                }
                HostControlClaimV1::ExistingOperation => {
                    (HostOperationPhaseV1::ReconciliationRequired, None)
                }
                HostControlClaimV1::Terminal(result)
                    if result.outcome != ReplayTerminalOutcomeV1::Succeeded =>
                {
                    (HostOperationPhaseV1::Terminal, Some(result))
                }
                HostControlClaimV1::Terminal(_) => return Err(HostControlErrorV1::InvalidState),
            },
            Some(TenantReplayStateV1::Terminal(result)) => {
                (HostOperationPhaseV1::Terminal, Some(result))
            }
            Some(_) => (HostOperationPhaseV1::ReconciliationRequired, None),
        };
        Ok(Self {
            operation,
            source,
            phase,
            profiles: None,
            package_digest: None,
            binding: None,
            session: None,
            terminal,
            context,
        })
    }

    pub const fn phase(&self) -> HostOperationPhaseV1 {
        self.phase
    }

    pub fn prepare(
        &mut self,
        frame: &HostControlFrameV1,
        cached: Option<&TenantEvidencePackage>,
    ) -> Result<(), HostControlErrorV1> {
        frame.validate()?;
        if frame.response || frame.operation != self.operation {
            return Err(HostControlErrorV1::CorrelationMismatch);
        }
        let HostControlBodyV1::Prepare {
            request,
            package,
            package_digest,
            ma_profiles,
        } = &frame.body
        else {
            return Err(HostControlErrorV1::InvalidState);
        };
        let package = match (package.as_deref(), cached) {
            (Some(package), None) | (None, Some(package)) => package,
            _ => return Err(HostControlErrorV1::InvalidState),
        };
        if sha384(&package.encode_host_package_v1()?) != *package_digest
            || self
                .package_digest
                .is_some_and(|digest| digest != *package_digest)
            || self
                .profiles
                .as_ref()
                .is_some_and(|profiles| profiles != ma_profiles)
        {
            return Err(HostControlErrorV1::ConflictingDelivery);
        }
        if matches!(
            self.phase,
            HostOperationPhaseV1::ReconciliationRequired | HostOperationPhaseV1::Terminal
        ) {
            return Err(HostControlErrorV1::ReconciliationRequired);
        }
        self.source.evidence(TenantEvidenceRequest {
            prepare: request,
            package,
            binding: TenantEvidenceBinding::HostRequestedZeroReportData,
            expected_identity: None,
        })?;
        self.package_digest = Some(*package_digest);
        self.profiles = Some(ma_profiles.clone());
        if self.phase == HostOperationPhaseV1::AwaitingEvidence {
            self.phase = HostOperationPhaseV1::EvidenceReceived;
        }
        Ok(())
    }

    /// The peer digest must arrive over the authenticated peer path. Equality
    /// here is association, not proof of the peer's verification or policy.
    pub fn match_source_evidence(
        &mut self,
        peer_complete_digest: &[u8; 48],
    ) -> Result<(), HostControlErrorV1> {
        let evidence = self
            .source
            .received_evidence()
            .ok_or(HostControlErrorV1::InvalidState)?;
        if self.phase != HostOperationPhaseV1::EvidenceReceived
            || evidence.verified_delivery()?.operation() != &self.operation
            || Some(sha384(&evidence.package().encode_host_package_v1()?)) != self.package_digest
            || evidence.verified_delivery()?.canonical_evidence_digest() != peer_complete_digest
        {
            return Err(HostControlErrorV1::CorrelationMismatch);
        }
        self.phase = HostOperationPhaseV1::SourceEvidenceMatched;
        Ok(())
    }

    pub fn received_evidence(&self) -> Option<&TenantEvidence> {
        self.source.received_evidence()
    }

    pub fn reserve_after_ma_proofs(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<(), HostControlErrorV1> {
        if self.phase != HostOperationPhaseV1::SourceEvidenceMatched {
            return Err(HostControlErrorV1::InvalidState);
        }
        // An existing durable operation is never treated as a fresh live session.
        if let Some(state) = self.source.query(binding)? {
            self.binding = Some(binding.clone());
            self.phase = match state {
                TenantReplayStateV1::Terminal(result) => {
                    self.terminal = Some(result);
                    HostOperationPhaseV1::Terminal
                }
                _ => HostOperationPhaseV1::ReconciliationRequired,
            };
            return Err(HostControlErrorV1::ReconciliationRequired);
        }
        let reservation = match self.source.reserve_after_ma_proofs(binding) {
            Ok(value) => value,
            Err(error) => {
                self.phase = HostOperationPhaseV1::ReconciliationRequired;
                return Err(error.into());
            }
        };
        if reservation != TenantReplayAdmissionV1::FirstReservation {
            self.phase = HostOperationPhaseV1::ReconciliationRequired;
            return Err(HostControlErrorV1::ReconciliationRequired);
        }
        self.binding = Some(binding.clone());
        self.phase = HostOperationPhaseV1::SessionEvidenceVerified;
        Ok(())
    }

    pub fn authorize_after_role_proofs(
        &mut self,
        authorization: &VerifiedTenantAuthorizationV1,
    ) -> Result<(), HostControlErrorV1> {
        if self.phase != HostOperationPhaseV1::SessionEvidenceVerified
            || self.binding.as_ref() != Some(authorization.binding())
        {
            return Err(HostControlErrorV1::InvalidState);
        }
        self.source.authorize_after_role_proofs(authorization)?;
        self.phase = HostOperationPhaseV1::Authorized;
        Ok(())
    }

    /// Call only after policy and protected delivery acceptance. Persisted replay
    /// is already Authorized; a crash now requires reconciliation, never resubmit.
    pub fn begin_installation(
        &mut self,
        acceptance: &super::direct_exchange::AcceptedInstallSessionV2,
    ) -> Result<(), HostControlErrorV1> {
        let session = acceptance.session().clone();
        if self.phase != HostOperationPhaseV1::Authorized
            || session.request_id != self.operation.request_id.value()
            || !acceptance.permits_installation(self.operation.role)
            || self
                .binding
                .as_ref()
                .map(|b| &b.as_stored().authorization_context_digest)
                != Some(acceptance.authorization_digest())
        {
            return Err(HostControlErrorV1::InvalidState);
        }
        self.session = Some(session);
        self.phase = HostOperationPhaseV1::InstallationStarted;
        Ok(())
    }

    pub fn observe_installation(
        &mut self,
        result: Result<&MigrationInstallCompletionV1, &MigrationInstallErrorV1>,
    ) -> Result<(), HostControlErrorV1> {
        if self.phase != HostOperationPhaseV1::InstallationStarted {
            return Err(HostControlErrorV1::InvalidState);
        }
        let correlation = match result {
            Ok(value) => value.correlation(),
            Err(error) => error.correlation(),
        };
        let binding = self
            .binding
            .as_ref()
            .ok_or(HostControlErrorV1::InvalidState)?;
        if correlation.operation() != &self.operation
            || Some(correlation.session()) != self.session.as_ref()
            || correlation.tenant_report_id() != &binding.as_stored().tenant_report_id
        {
            self.phase = HostOperationPhaseV1::ReconciliationRequired;
            return Err(HostControlErrorV1::CorrelationMismatch);
        }
        self.phase = match result {
            Ok(_) => HostOperationPhaseV1::InstalledLocally,
            Err(_) => HostOperationPhaseV1::ReconciliationRequired,
        };
        if result.is_err() {
            return Err(HostControlErrorV1::ReconciliationRequired);
        }
        Ok(())
    }

    /// A terminal digest is a caller-authored operation result, not a persistence
    /// attestation. Success additionally needs the current-scope peer receipt.
    pub fn finish(
        &mut self,
        result: ReplayTerminalResultV1,
        peer: Option<&super::direct_exchange::CompletedInstallExchangeV2>,
    ) -> Result<(), HostControlErrorV1> {
        if self.phase == HostOperationPhaseV1::Terminal {
            return if self.terminal == Some(result) {
                Ok(())
            } else {
                Err(HostControlErrorV1::ConflictingDelivery)
            };
        }
        if result.outcome == ReplayTerminalOutcomeV1::Succeeded {
            let peer = peer.ok_or(HostControlErrorV1::InvalidState)?;
            if self.phase != HostOperationPhaseV1::InstalledLocally
                || Some(peer.session()) != self.session.as_ref()
                || peer.local_role() != self.operation.role
                || self
                    .binding
                    .as_ref()
                    .map(|b| &b.as_stored().authorization_context_digest)
                    != Some(peer.authorization_digest())
            {
                return Err(HostControlErrorV1::InvalidState);
            }
        } else if matches!(
            self.phase,
            HostOperationPhaseV1::InstallationStarted
                | HostOperationPhaseV1::InstalledLocally
                | HostOperationPhaseV1::ReconciliationRequired
        ) {
            return Err(HostControlErrorV1::ReconciliationRequired);
        }
        let persisted = match self.binding.as_ref() {
            Some(binding) => self
                .source
                .finish(binding, result)
                .map_err(HostControlErrorV1::from),
            None if result.outcome != ReplayTerminalOutcomeV1::Succeeded => {
                self.context.finish_before_proofs(&self.operation, result)
            }
            None => Err(HostControlErrorV1::InvalidState),
        };
        if let Err(error) = persisted {
            self.phase = HostOperationPhaseV1::ReconciliationRequired;
            return Err(error);
        }
        self.terminal = Some(result);
        self.phase = HostOperationPhaseV1::Terminal;
        Ok(())
    }

    pub fn control(
        &mut self,
        frame: &HostControlFrameV1,
    ) -> Result<HostControlFrameV1, HostControlErrorV1> {
        frame.validate()?;
        if frame.response
            || frame.operation != self.operation
            || !matches!(frame.body, HostControlBodyV1::Empty)
        {
            return Err(HostControlErrorV1::CorrelationMismatch);
        }
        if let Some(TenantReplayStateV1::Terminal(result)) =
            self.source.query_operation(&self.operation)?
        {
            self.terminal = Some(result);
            self.phase = HostOperationPhaseV1::Terminal;
        }
        if matches!(
            frame.kind,
            HostControlKindV1::Cancel | HostControlKindV1::Abort
        ) && self.phase != HostOperationPhaseV1::Terminal
        {
            self.finish(
                ReplayTerminalResultV1 {
                    outcome: ReplayTerminalOutcomeV1::Aborted,
                    result_digest: [0; 48],
                },
                None,
            )?;
        }
        Ok(HostControlFrameV1 {
            kind: frame.kind,
            response: true,
            operation: self.operation,
            body: HostControlBodyV1::Status {
                phase: self.phase,
                terminal: self.terminal,
            },
        })
    }
}

#[cfg(test)]
mod tests;
