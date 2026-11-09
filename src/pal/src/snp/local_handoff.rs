// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! P0.11 logical contracts, not host transport, SPDM drivers or firmware effects.
//! Trusted transition providers own current evidence, durable replay and cleanup.

use crate::random::{RandomSource, Secret32};
use core::fmt;

use super::{
    ma_policy::{
        admit_fixed_release_pair_v1, MaPolicyErrorV1, VerifiedLmPolicyV1,
        VerifiedMaPolicyCollateral,
    },
    migration_data::MigrationDataV1,
    purpose_binding::{
        sha384, CanonicalFirmwareResultSetV1, CanonicalTenantSetV1, FirmwareRebindResultV1,
        LocalHandoffBindingV1, SnpOperationStageV1, VerifiedTenantReportIdV1,
    },
    report_data_context::{SnpEvidencePurposeV1, SnpMaRoleV1},
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

pub const MAX_LOCAL_HANDOFF_TENANTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalHandoffErrorV1 {
    Codec(SnpCodecError),
    Policy(MaPolicyErrorV1),
    ContextMismatch,
    InvalidTransition,
    Expired,
    HistoryChanged,
    BindingMismatch,
    ProviderUnavailable,
    RandomnessUnavailable,
    SecretProviderUnavailable,
    ReconciliationRequired,
    RetryDenied,
}

impl From<SnpCodecError> for LocalHandoffErrorV1 {
    fn from(error: SnpCodecError) -> Self {
        Self::Codec(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalHandoffModeV1 {
    Planned = 1,
    Recovery = 2,
}

impl LocalHandoffModeV1 {
    fn purpose(self) -> SnpEvidencePurposeV1 {
        match self {
            Self::Planned => SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
            Self::Recovery => SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LocalControlKindV1 {
    PrepareMaHandoffRequest = 1,
    MaHandoffReady = 2,
    MaRebindResult = 3,
    ConfirmRebindResult = 4,
    FinalizeMaHandoff = 5,
    AbortMaHandoff = 6,
    QueryMaHandoffStatus = 7,
    RetryMaRebind = 8,
    PrepareMaRecoveryRequest = 9,
    MaRecoveryReady = 10,
    ConfirmRecoveryResult = 11,
    FinalizeMaRecovery = 12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalHandoffPhaseV1 {
    Unprepared = 0,
    Prepared = 1,
    Ready = 2,
    Partial = 3,
    Confirmed = 4,
    Complete = 5,
    Aborted = 6,
    ReconciliationRequired = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalControlStatusV1 {
    Success = 0,
    Pending = 1,
    Retryable = 2,
    Terminal = 3,
    Indeterminate = 4,
    Unavailable = 5,
}

/// Untrusted, secret-free host-control record in a LOCAL namespace, not a VDM tag.
/// Routing handles confer no identity or authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMaControlV1 {
    pub kind: LocalControlKindV1,
    pub mode: LocalHandoffModeV1,
    pub role: SnpMaRoleV1,
    pub phase: LocalHandoffPhaseV1,
    pub status: LocalControlStatusV1,
    pub previous_ma_handle: u64,
    pub new_ma_handle: u64,
    pub tenant_handle: u64,
    pub binding: LocalHandoffBindingV1,
    pub result: Option<FirmwareRebindResultV1>,
}

impl LocalMaControlV1 {
    pub const MAX_ENCODED_SIZE: usize = 512;

    fn validate(&self) -> SnpCodecResult<()> {
        use LocalControlKindV1::*;
        let recovery_only = matches!(
            self.kind,
            PrepareMaRecoveryRequest | MaRecoveryReady | ConfirmRecoveryResult | FinalizeMaRecovery
        );
        let planned_only = matches!(
            self.kind,
            PrepareMaHandoffRequest | MaHandoffReady | ConfirmRebindResult | FinalizeMaHandoff
        );
        if self.binding.purpose != self.mode.purpose()
            || !matches!(self.role, SnpMaRoleV1::Outgoing | SnpMaRoleV1::Incoming)
            || (self.mode == LocalHandoffModeV1::Recovery && self.role != SnpMaRoleV1::Incoming)
            || (recovery_only && self.mode != LocalHandoffModeV1::Recovery)
            || (planned_only && self.mode != LocalHandoffModeV1::Planned)
            || (self.kind == MaRebindResult) != self.result.is_some()
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        let prepare = matches!(
            self.kind,
            PrepareMaHandoffRequest
                | MaHandoffReady
                | PrepareMaRecoveryRequest
                | MaRecoveryReady
                | RetryMaRebind
        );
        let confirmation = matches!(
            self.kind,
            MaRebindResult
                | ConfirmRebindResult
                | FinalizeMaHandoff
                | ConfirmRecoveryResult
                | FinalizeMaRecovery
        );
        if (prepare && self.binding.stage != SnpOperationStageV1::PrepareAuthorization)
            || (confirmation
                && self.binding.stage != SnpOperationStageV1::FirmwareResultConfirmation)
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        if let Some(result) = &self.result {
            validate_result(result, &self.binding)?;
        }
        self.binding.encode_exact()?;
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<Vec<u8>> {
        self.validate()?;
        let binding = self.binding.encode_exact()?;
        let length = 48 + binding.len() + self.result.as_ref().map_or(0, |_| 104);
        if length > Self::MAX_ENCODED_SIZE {
            return Err(SnpCodecError::RecordTooLarge);
        }
        let mut bytes = vec![0; length];
        let mut w = StrictWriter::new(&mut bytes);
        w.write_bytes(b"SNP-MA-L")?;
        w.write_u16(1)?;
        w.write_u16(self.kind as u16)?;
        w.write_u32(length as u32)?;
        w.write_u8(self.mode as u8)?;
        w.write_u8(self.role as u8)?;
        w.write_u8(self.phase as u8)?;
        w.write_u8(self.status as u8)?;
        w.write_u16(binding.len() as u16)?;
        w.write_zeroes(2)?;
        w.write_u64(self.previous_ma_handle)?;
        w.write_u64(self.new_ma_handle)?;
        w.write_u64(self.tenant_handle)?;
        w.write_bytes(&binding)?;
        if let Some(result) = &self.result {
            w.write_bytes(&result.encode_exact()?)?;
        }
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        if bytes.len() > Self::MAX_ENCODED_SIZE {
            return Err(SnpCodecError::RecordTooLarge);
        }
        let mut r = StrictReader::new(bytes);
        if r.read_array::<8>()? != *b"SNP-MA-L" {
            return Err(SnpCodecError::InvalidMagic);
        }
        if r.read_u16()? != 1 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        let kind = match r.read_u16()? {
            1 => LocalControlKindV1::PrepareMaHandoffRequest,
            2 => LocalControlKindV1::MaHandoffReady,
            3 => LocalControlKindV1::MaRebindResult,
            4 => LocalControlKindV1::ConfirmRebindResult,
            5 => LocalControlKindV1::FinalizeMaHandoff,
            6 => LocalControlKindV1::AbortMaHandoff,
            7 => LocalControlKindV1::QueryMaHandoffStatus,
            8 => LocalControlKindV1::RetryMaRebind,
            9 => LocalControlKindV1::PrepareMaRecoveryRequest,
            10 => LocalControlKindV1::MaRecoveryReady,
            11 => LocalControlKindV1::ConfirmRecoveryResult,
            12 => LocalControlKindV1::FinalizeMaRecovery,
            _ => return Err(SnpCodecError::UnknownRecordType),
        };
        if r.read_u32()? as usize != bytes.len() {
            return Err(SnpCodecError::InvalidLength);
        }
        let mode = match r.read_u8()? {
            1 => LocalHandoffModeV1::Planned,
            2 => LocalHandoffModeV1::Recovery,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let role = SnpMaRoleV1::decode(&mut r)?;
        let phase = match r.read_u8()? {
            0 => LocalHandoffPhaseV1::Unprepared,
            1 => LocalHandoffPhaseV1::Prepared,
            2 => LocalHandoffPhaseV1::Ready,
            3 => LocalHandoffPhaseV1::Partial,
            4 => LocalHandoffPhaseV1::Confirmed,
            5 => LocalHandoffPhaseV1::Complete,
            6 => LocalHandoffPhaseV1::Aborted,
            7 => LocalHandoffPhaseV1::ReconciliationRequired,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let status = match r.read_u8()? {
            0 => LocalControlStatusV1::Success,
            1 => LocalControlStatusV1::Pending,
            2 => LocalControlStatusV1::Retryable,
            3 => LocalControlStatusV1::Terminal,
            4 => LocalControlStatusV1::Indeterminate,
            5 => LocalControlStatusV1::Unavailable,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let binding_length = r.read_u16()? as usize;
        r.read_zeroes(2)?;
        let previous_ma_handle = r.read_u64()?;
        let new_ma_handle = r.read_u64()?;
        let tenant_handle = r.read_u64()?;
        let binding = LocalHandoffBindingV1::decode_exact(mode.purpose(), r.take(binding_length)?)?;
        let result = if kind == LocalControlKindV1::MaRebindResult {
            Some(FirmwareRebindResultV1::decode_exact(r.take(104)?)?)
        } else {
            None
        };
        r.finish()?;
        let value = Self {
            kind,
            mode,
            role,
            phase,
            status,
            previous_ma_handle,
            new_ma_handle,
            tenant_handle,
            binding,
            result,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Secret-free snapshot descriptor. Evidence and replay digests reference
/// authenticated retained packages/journals, not transferable live session keys.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalTenantMetadataV1 {
    pub tenant_report_id: [u8; 32],
    pub tenant_evidence_digest: [u8; 48],
    pub migration_data_valid: bool,
    pub migration_data: [u8; 64],
    pub replay_snapshot_digest: [u8; 48],
}

impl fmt::Debug for LocalTenantMetadataV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalTenantMetadataV1(<protected>)")
    }
}

impl LocalTenantMetadataV1 {
    fn validate(&self) -> SnpCodecResult<()> {
        if self.migration_data_valid {
            MigrationDataV1::decode_exact(&self.migration_data)?;
        } else if self.migration_data != [0; 64] {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMetadataSnapshotV1 {
    pub tenants: Vec<LocalTenantMetadataV1>,
}

impl LocalMetadataSnapshotV1 {
    pub const MAX_ENCODED_SIZE: usize = 20 + MAX_LOCAL_HANDOFF_TENANTS * 200;

    pub fn encode_exact(&self) -> SnpCodecResult<Vec<u8>> {
        if self.tenants.is_empty() || self.tenants.len() > MAX_LOCAL_HANDOFF_TENANTS {
            return Err(SnpCodecError::InvalidCount);
        }
        if self
            .tenants
            .windows(2)
            .any(|p| p[0].tenant_report_id >= p[1].tenant_report_id)
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        let length = 20 + 200 * self.tenants.len();
        let mut bytes = vec![0; length];
        let mut w = StrictWriter::new(&mut bytes);
        w.write_bytes(b"SNP-MA-M")?;
        w.write_u16(1)?;
        w.write_zeroes(2)?;
        w.write_u32(length as u32)?;
        w.write_u32(self.tenants.len() as u32)?;
        for tenant in &self.tenants {
            tenant.validate()?;
            w.write_bytes(&tenant.tenant_report_id)?;
            w.write_bytes(&tenant.tenant_evidence_digest)?;
            w.write_u8(u8::from(tenant.migration_data_valid))?;
            w.write_zeroes(7)?;
            w.write_bytes(&tenant.migration_data)?;
            w.write_bytes(&tenant.replay_snapshot_digest)?;
        }
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        if bytes.len() > Self::MAX_ENCODED_SIZE {
            return Err(SnpCodecError::RecordTooLarge);
        }
        let mut r = StrictReader::new(bytes);
        if r.read_array::<8>()? != *b"SNP-MA-M" {
            return Err(SnpCodecError::InvalidMagic);
        }
        if r.read_u16()? != 1 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        r.read_zeroes(2)?;
        if r.read_u32()? as usize != bytes.len() {
            return Err(SnpCodecError::InvalidLength);
        }
        let count = r.read_u32()? as usize;
        if count == 0 || count > MAX_LOCAL_HANDOFF_TENANTS || bytes.len() != 20 + count * 200 {
            return Err(SnpCodecError::InvalidCount);
        }
        let mut tenants = Vec::with_capacity(count);
        for _ in 0..count {
            let tenant_report_id = r.read_array()?;
            let tenant_evidence_digest = r.read_array()?;
            let migration_data_valid = match r.read_u8()? {
                0 => false,
                1 => true,
                _ => return Err(SnpCodecError::NonCanonicalEncoding),
            };
            r.read_zeroes(7)?;
            tenants.push(LocalTenantMetadataV1 {
                tenant_report_id,
                tenant_evidence_digest,
                migration_data_valid,
                migration_data: r.read_array()?,
                replay_snapshot_digest: r.read_array()?,
            });
        }
        r.finish()?;
        let value = Self { tenants };
        value.encode_exact()?;
        Ok(value)
    }

    pub fn digest(&self) -> SnpCodecResult<[u8; 48]> {
        let mut bytes = b"SNP-MA-METADATA-v1".to_vec();
        bytes.extend_from_slice(&self.encode_exact()?);
        Ok(sha384(&bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalTransitionV1 {
    Prepare = 1,
    Ready = 2,
    Results = 3,
    Retry = 4,
    Finalize = 5,
    Abort = 6,
}

pub struct LocalTransitionRequestV1<'a> {
    pub transition: LocalTransitionV1,
    pub binding: &'a LocalHandoffBindingV1,
    pub policy: &'a VerifiedLmPolicyV1,
    pub ma_approvals: &'a [&'a VerifiedMaPolicyCollateral],
    pub results: &'a [FirmwareRebindResultV1],
}

/// Trusted current-state output, not host-proposed observations.
pub struct CurrentLocalTenantStateV1 {
    pub tenant_report_id: [u8; 32],
    pub bound_ma_report_id: [u8; 32],
    pub migration_data_valid: bool,
    pub migration_data: [u8; 64],
}

/// Composition-selected authority, never peer supplied. Every call must check
/// current operation authority, trusted time/policy/PKI/revocation, exact metadata/
/// evidence/replay state and anchored operation/epoch/attempt idempotency.
/// Operation authority is independently appraised policy/binding/firmware scope,
/// never a host assertion. A coordinator credential is not assumed by this API;
/// deployment must supply any additional authority its platform requires.
/// Prepare/Retry/Results appraise fresh purpose-specific approvals. Planned Ready
/// requires LocalMaHandoff mutual SPDM authentication, verified metadata, both MA
/// readiness and matching installed secret slots; Recovery requires exact failed/
/// replacement firmware identity/launch equivalence, no old proof/session/secret.
///
/// Results authenticate actual firmware effects and current full tenant history.
/// Retry permits ONLY explicitly recognized retryable statuses after querying
/// unchanged failed bindings; successful bindings are never reissued/rolled back.
/// Finalize requires every incoming confirmation, actual acknowledged VALID=0
/// cleanup of both planned slots and a correlated BASE lifecycle request checked
/// against independent completion facts and deployment policy. Abort also
/// acknowledges cleanup and durable split-ownership reconciliation. Calls must
/// not shut down an MA or treat host messages/logs as authoritative evidence.
/// Reserve affected MA secret state as well as tenants; qualify effect scope and
/// remaining bindings before accepting a correlated lifecycle shutdown request.
pub trait LocalHandoffAuthorityV1 {
    fn verify_transition(
        &mut self,
        request: &LocalTransitionRequestV1<'_>,
        metadata: &LocalMetadataSnapshotV1,
    ) -> Result<Vec<CurrentLocalTenantStateV1>, LocalHandoffErrorV1>;
}

pub struct UnavailableLocalHandoffServicesV1;

impl LocalHandoffAuthorityV1 for UnavailableLocalHandoffServicesV1 {
    fn verify_transition(
        &mut self,
        _: &LocalTransitionRequestV1<'_>,
        _: &LocalMetadataSnapshotV1,
    ) -> Result<Vec<CurrentLocalTenantStateV1>, LocalHandoffErrorV1> {
        Err(LocalHandoffErrorV1::ProviderUnavailable)
    }
}

struct LocalContractV1 {
    mode: LocalHandoffModeV1,
    binding: LocalHandoffBindingV1,
    metadata: LocalMetadataSnapshotV1,
    tenants: Vec<VerifiedTenantReportIdV1>,
    policy_digest: [u8; 48],
    th1: Option<[u8; 48]>,
    phase: LocalHandoffPhaseV1,
    results: Vec<FirmwareRebindResultV1>,
    last_request: Option<[u8; 48]>,
}

impl LocalContractV1 {
    fn new(
        mode: LocalHandoffModeV1,
        binding: LocalHandoffBindingV1,
        metadata: LocalMetadataSnapshotV1,
        tenants: &[VerifiedTenantReportIdV1],
        policy: &VerifiedLmPolicyV1,
    ) -> Result<Self, LocalHandoffErrorV1> {
        metadata.encode_exact()?;
        let set = CanonicalTenantSetV1::new(tenants.len() as u32, tenants)?;
        binding.digest(&set, None)?;
        if binding.purpose != mode.purpose()
            || binding.attempt_number != 1
            || binding.previous_ma_report_id == binding.new_ma_report_id
            || tenants.len() != metadata.tenants.len()
            || tenants
                .iter()
                .zip(&metadata.tenants)
                .any(|(id, m)| id.as_bytes() != &m.tenant_report_id)
        {
            return Err(LocalHandoffErrorV1::ContextMismatch);
        }
        Ok(Self {
            mode,
            binding,
            metadata,
            tenants: tenants.to_vec(),
            policy_digest: *policy.digest(),
            th1: None,
            phase: LocalHandoffPhaseV1::Unprepared,
            results: Vec::new(),
            last_request: None,
        })
    }

    fn advance(
        &mut self,
        request: &LocalTransitionRequestV1<'_>,
        now: u64,
        authority: &mut dyn LocalHandoffAuthorityV1,
    ) -> Result<(), LocalHandoffErrorV1> {
        use LocalHandoffPhaseV1 as Phase;
        use LocalTransitionV1::*;
        if request.transition != Abort && now >= self.binding.deadline_unix_seconds {
            return Err(LocalHandoffErrorV1::Expired);
        }
        if request.policy.digest() != &self.policy_digest {
            return Err(LocalHandoffErrorV1::ContextMismatch);
        }
        if request.transition != Results && !request.results.is_empty() {
            return Err(LocalHandoffErrorV1::ContextMismatch);
        }
        if request.transition == Results && request.results.len() != self.tenants.len() {
            return Err(LocalHandoffErrorV1::Codec(SnpCodecError::InvalidCount));
        }
        let tenants = CanonicalTenantSetV1::new(self.tenants.len() as u32, &self.tenants)?;
        let mut expected = self.binding.clone();
        if request.transition == Retry {
            expected.stage = SnpOperationStageV1::PrepareAuthorization;
            expected.firmware_result_set_digest = [0; 48];
            // An identical retry command still needs provider/CAS acknowledgement.
            if self.phase != Phase::Prepared {
                expected.attempt_number = expected
                    .attempt_number
                    .checked_add(1)
                    .ok_or(LocalHandoffErrorV1::InvalidTransition)?;
            }
        }
        let mut fingerprint = vec![request.transition as u8];
        fingerprint.extend_from_slice(&request.binding.encode_exact()?);
        fingerprint.extend_from_slice(&self.metadata.digest()?);
        fingerprint.extend_from_slice(&self.policy_digest);
        for result in request.results {
            fingerprint.extend_from_slice(&result.encode_exact()?);
        }
        let fingerprint = sha384(&fingerprint);
        let duplicate = self.last_request == Some(fingerprint);
        let next = match request.transition {
            Prepare if self.phase == Phase::Unprepared => Phase::Prepared,
            Ready if self.phase == Phase::Prepared => Phase::Ready,
            Results if self.phase == Phase::Ready => {
                if request.results.iter().all(|r| r.raw_status == 0) {
                    Phase::Confirmed
                } else {
                    Phase::Partial
                }
            }
            Retry if self.phase == Phase::Partial => Phase::Prepared,
            Finalize if self.phase == Phase::Confirmed => Phase::Complete,
            Abort if !matches!(self.phase, Phase::Complete | Phase::Aborted) => Phase::Aborted,
            _ if duplicate => self.phase,
            _ => return Err(LocalHandoffErrorV1::InvalidTransition),
        };
        if request.transition == Results {
            let set = CanonicalFirmwareResultSetV1::new(
                self.tenants.len() as u32,
                request.results,
                &tenants,
                self.binding.previous_ma_report_id,
                self.binding.new_ma_report_id,
            )?;
            expected.stage = SnpOperationStageV1::FirmwareResultConfirmation;
            expected.firmware_result_set_digest = set.digest()?;
            if self
                .results
                .iter()
                .zip(request.results)
                .any(|(old, new)| old.raw_status == 0 && old != new)
            {
                return Err(LocalHandoffErrorV1::BindingMismatch);
            }
            self.verify_approvals(request, &tenants, Some(&set))?;
        } else if matches!(request.transition, Prepare | Retry) {
            self.verify_approvals(request, &tenants, None)?;
        } else if !request.results.is_empty() || !request.ma_approvals.is_empty() {
            return Err(LocalHandoffErrorV1::ContextMismatch);
        }
        if request.binding != &expected {
            return Err(LocalHandoffErrorV1::ContextMismatch);
        }
        let states = match authority.verify_transition(request, &self.metadata) {
            Ok(states) => states,
            Err(error) => {
                self.phase = Phase::ReconciliationRequired;
                return Err(error);
            }
        };
        let results = if request.transition == Results {
            request.results
        } else {
            &self.results
        };
        if states.len() != self.metadata.tenants.len() {
            self.phase = Phase::ReconciliationRequired;
            return Err(LocalHandoffErrorV1::BindingMismatch);
        }
        for (i, (state, metadata)) in states.iter().zip(&self.metadata.tenants).enumerate() {
            let moved = results.get(i).is_some_and(|r| r.raw_status == 0);
            let expected_ma = if moved {
                self.binding.new_ma_report_id
            } else {
                self.binding.previous_ma_report_id
            };
            if state.tenant_report_id != metadata.tenant_report_id
                || state.bound_ma_report_id != expected_ma
            {
                self.phase = Phase::ReconciliationRequired;
                return Err(LocalHandoffErrorV1::BindingMismatch);
            }
            if state.migration_data_valid != metadata.migration_data_valid
                || state.migration_data != metadata.migration_data
            {
                self.phase = Phase::ReconciliationRequired;
                return Err(LocalHandoffErrorV1::HistoryChanged);
            }
        }
        if matches!(request.transition, Prepare | Retry) {
            self.th1 = Some(
                request
                    .ma_approvals
                    .last()
                    .ok_or(LocalHandoffErrorV1::ContextMismatch)?
                    .context()
                    .th1,
            );
        }
        self.binding = expected;
        if request.transition == Results {
            self.results = request.results.to_vec();
        }
        self.phase = next;
        self.last_request = Some(fingerprint);
        Ok(())
    }

    fn verify_approvals(
        &self,
        request: &LocalTransitionRequestV1<'_>,
        tenants: &CanonicalTenantSetV1<'_>,
        results: Option<&CanonicalFirmwareResultSetV1<'_>>,
    ) -> Result<(), LocalHandoffErrorV1> {
        let roles: &[SnpMaRoleV1] = match self.mode {
            LocalHandoffModeV1::Planned => &[SnpMaRoleV1::Outgoing, SnpMaRoleV1::Incoming],
            LocalHandoffModeV1::Recovery => &[SnpMaRoleV1::Incoming],
        };
        if request.ma_approvals.len() != roles.len() {
            return Err(LocalHandoffErrorV1::ContextMismatch);
        }
        for (approval, role) in request.ma_approvals.iter().zip(roles) {
            if !matches!(approval, VerifiedMaPolicyCollateral::FixedReleaseV1(_))
                || approval.policy_digest() != &self.policy_digest
                || approval.identity_digest() != &self.binding.ma_policy_identity_digest
                || approval.context().role != *role
                || approval.report_id()
                    != if *role == SnpMaRoleV1::Outgoing {
                        &self.binding.previous_ma_report_id
                    } else {
                        &self.binding.new_ma_report_id
                    }
                || self.th1.is_some_and(|th1| approval.context().th1 != th1)
            {
                return Err(LocalHandoffErrorV1::ContextMismatch);
            }
            request
                .binding
                .verify_context(approval.context(), tenants, results)?;
        }
        if self.mode == LocalHandoffModeV1::Planned {
            admit_fixed_release_pair_v1(request.ma_approvals[0], request.ma_approvals[1])
                .map_err(LocalHandoffErrorV1::Policy)?;
        }
        Ok(())
    }
}

/// Logical planned-handoff state only. Dropping this model clears no firmware
/// slots: R4's runtime guard must acknowledge cleanup on every terminal/drop path.
pub struct PlannedHandoffContractV1(LocalContractV1);

/// Distinct recovery contract: no outgoing approval, old/new SPDM or secret.
///
/// ```compile_fail
/// use pal::snp::local_handoff::{HandoffSecretV1, HandoffRandomSourceV1, RecoveryContractV1};
/// fn forbidden(recovery: &RecoveryContractV1, random: &mut dyn HandoffRandomSourceV1) {
///     HandoffSecretV1::generate(recovery, random);
/// }
/// ```
pub struct RecoveryContractV1(LocalContractV1);

macro_rules! contract {
    ($name:ident, $mode:ident) => {
        impl $name {
            pub fn new(
                binding: LocalHandoffBindingV1,
                metadata: LocalMetadataSnapshotV1,
                tenants: &[VerifiedTenantReportIdV1],
                policy: &VerifiedLmPolicyV1,
            ) -> Result<Self, LocalHandoffErrorV1> {
                LocalContractV1::new(
                    LocalHandoffModeV1::$mode,
                    binding,
                    metadata,
                    tenants,
                    policy,
                )
                .map(Self)
            }

            pub fn phase(&self) -> LocalHandoffPhaseV1 {
                self.0.phase
            }

            pub fn binding(&self) -> &LocalHandoffBindingV1 {
                &self.0.binding
            }

            pub fn contains_tenant(&self, tenant: &VerifiedTenantReportIdV1) -> bool {
                self.0.tenants.iter().any(|entry| entry == tenant)
            }

            pub fn advance(
                &mut self,
                request: &LocalTransitionRequestV1<'_>,
                now: u64,
                authority: &mut dyn LocalHandoffAuthorityV1,
            ) -> Result<(), LocalHandoffErrorV1> {
                self.0.advance(request, now, authority)
            }
        }
    };
}
contract!(PlannedHandoffContractV1, Planned);
contract!(RecoveryContractV1, Recovery);

pub trait HandoffRandomSourceV1 {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), LocalHandoffErrorV1>;
}

impl<T: RandomSource + ?Sized> HandoffRandomSourceV1 for T {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), LocalHandoffErrorV1> {
        RandomSource::fill_random32(self, output)
            .map_err(|_| LocalHandoffErrorV1::RandomnessUnavailable)
    }
}

/// Trusted protected-memory/local encrypted-SPDM sink, never host control.
/// Installs both direction-specific slots and acknowledges matching operation,
/// identity and secret state. Recheck current policy, deadline, epoch, attempt,
/// Prepared phase and authenticated session at installation, even for an object
/// generated earlier. Reject conflicting slot replacement for one operation.
/// Failures require explicit two-slot cleanup.
/// Cleanup must not panic. Process abort/crash requires external reconciliation.
pub trait ProtectedHandoffSecretProviderV1 {
    fn install_and_transfer(
        &mut self,
        binding: &LocalHandoffBindingV1,
        secret: &[u8; 32],
    ) -> Result<(), LocalHandoffErrorV1>;
    fn clear_both(&mut self, binding: &LocalHandoffBindingV1) -> Result<(), LocalHandoffErrorV1>;
}

impl HandoffRandomSourceV1 for UnavailableLocalHandoffServicesV1 {
    fn fill_random32(&mut self, _: &mut [u8; 32]) -> Result<(), LocalHandoffErrorV1> {
        Err(LocalHandoffErrorV1::RandomnessUnavailable)
    }
}

impl ProtectedHandoffSecretProviderV1 for UnavailableLocalHandoffServicesV1 {
    fn install_and_transfer(
        &mut self,
        _: &LocalHandoffBindingV1,
        _: &[u8; 32],
    ) -> Result<(), LocalHandoffErrorV1> {
        Err(LocalHandoffErrorV1::SecretProviderUnavailable)
    }
    fn clear_both(&mut self, _: &LocalHandoffBindingV1) -> Result<(), LocalHandoffErrorV1> {
        Err(LocalHandoffErrorV1::SecretProviderUnavailable)
    }
}

/// Protected, non-cloneable plaintext. No host codec, persistence or byte getter.
pub struct HandoffSecretV1 {
    bytes: Secret32,
    binding: LocalHandoffBindingV1,
}

impl fmt::Debug for HandoffSecretV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandoffSecretV1(<redacted>)")
    }
}

impl HandoffSecretV1 {
    pub fn generate<R: HandoffRandomSourceV1 + ?Sized>(
        prepared: &PlannedHandoffContractV1,
        random: &mut R,
    ) -> Result<Self, LocalHandoffErrorV1> {
        if prepared.phase() != LocalHandoffPhaseV1::Prepared
            || prepared.0.binding.attempt_number != 1
            || !prepared.0.results.is_empty()
        {
            return Err(LocalHandoffErrorV1::InvalidTransition);
        }
        let binding = &prepared.0.binding;
        let mut bytes = Secret32::zeroed();
        random.fill_random32(bytes.as_mut()).inspect_err(|error| {
            log::error!("handoff random32 generation failed: {error:?}");
        })?;
        Ok(Self {
            bytes,
            binding: binding.clone(),
        })
    }

    /// Retires only this local owner; installed slots require provider cleanup.
    ///
    /// ```compile_fail
    /// use pal::snp::local_handoff::HandoffSecretV1;
    /// fn duplicate(secret: HandoffSecretV1) { secret.clone(); }
    /// ```
    ///
    /// ```compile_fail
    /// use pal::snp::local_handoff::{HandoffSecretV1, ProtectedHandoffSecretProviderV1};
    /// fn reuse(secret: HandoffSecretV1, sink: &mut dyn ProtectedHandoffSecretProviderV1) {
    ///     secret.clear();
    ///     secret.install(sink);
    /// }
    /// ```
    pub fn clear(self) {
        drop(self);
    }

    /// Consumes/zeroizes the local copy. The runtime still owns cleanup of both
    /// provider slots after success, abort, timeout, failure or session loss.
    pub fn install(
        self,
        provider: &mut dyn ProtectedHandoffSecretProviderV1,
    ) -> Result<(), LocalHandoffErrorV1> {
        let mut cleanup = HandoffSlotCleanup {
            provider,
            binding: &self.binding,
            armed: true,
        };
        let result = cleanup
            .provider
            .install_and_transfer(&self.binding, self.bytes.as_bytes());
        if let Err(error) = result {
            log::error!("handoff secret installation failed: {error:?}");
            cleanup.clear()?;
            return Err(error);
        }
        cleanup.armed = false;
        Ok(())
    }
}

struct HandoffSlotCleanup<'a> {
    provider: &'a mut dyn ProtectedHandoffSecretProviderV1,
    binding: &'a LocalHandoffBindingV1,
    armed: bool,
}

impl HandoffSlotCleanup<'_> {
    fn clear(&mut self) -> Result<(), LocalHandoffErrorV1> {
        self.armed = false;
        self.provider.clear_both(self.binding).inspect_err(|error| {
            log::error!("handoff slot cleanup failed; reconciliation required: {error:?}");
        })
    }
}

impl Drop for HandoffSlotCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Unwind cannot return an outcome; the runtime must reconcile.
            let _ = self.clear();
        }
    }
}

fn validate_result(
    result: &FirmwareRebindResultV1,
    binding: &LocalHandoffBindingV1,
) -> SnpCodecResult<()> {
    result.encode_exact()?;
    let success = result.raw_status == 0;
    if result.previous_ma_report_id != binding.previous_ma_report_id
        || result.binding_changed != u8::from(success)
        || result.resulting_ma_report_id
            != if success {
                binding.new_ma_report_id
            } else {
                binding.previous_ma_report_id
            }
    {
        return Err(SnpCodecError::NonCanonicalEncoding);
    }
    Ok(())
}

const _: () = {
    assert!(
        LocalMetadataSnapshotV1::MAX_ENCODED_SIZE + 10
            <= super::limits::MAX_SNP_APPLICATION_MESSAGE_SIZE
    );
    assert!(LocalMaControlV1::MAX_ENCODED_SIZE <= super::limits::MAX_SNP_APPLICATION_MESSAGE_SIZE);
};
