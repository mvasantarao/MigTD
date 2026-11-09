// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Logical P0.11 binding effects. Providers own current authority, slot
//! reservation, physical resolution and protected firmware invocation.

use super::{
    local_handoff::{
        LocalHandoffModeV1, LocalHandoffPhaseV1, PlannedHandoffContractV1, RecoveryContractV1,
    },
    migration_install::MigrationInstallEffectV1,
    purpose_binding::{LocalHandoffBindingV1, VerifiedTenantReportIdV1},
    report_data_context::{SnpEvidencePurposeV1, SnpMaRoleV1},
};
use crate::types::ManagedGuestHandle;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingOperationV1 {
    SetSecret,
    ClearSecret,
    PlannedRebind,
    RecoveryRebind,
    Query,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingCorrelationV1 {
    pub operation: BindingOperationV1,
    pub target: ManagedGuestHandle,
    pub binding: LocalHandoffBindingV1,
    pub tenant_report_id: Option<[u8; 32]>,
    pub slot_role: Option<SnpMaRoleV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingFailureV1 {
    InvalidRequest,
    Unavailable,
    FirmwareRejected { status: u32 },
    Transport,
    Partial,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingErrorV1 {
    pub correlation: Box<BindingCorrelationV1>,
    pub failure: BindingFailureV1,
    pub effect: MigrationInstallEffectV1,
    pub raw_firmware_status: Option<u32>,
}

impl BindingErrorV1 {
    pub fn unavailable(correlation: &BindingCorrelationV1) -> Self {
        Self {
            correlation: Box::new(correlation.clone()),
            failure: BindingFailureV1::Unavailable,
            effect: MigrationInstallEffectV1::NotApplied,
            raw_firmware_status: None,
        }
    }
}

/// Local provider observation only. Caller compares the entire correlation.
#[derive(Debug, PartialEq, Eq)]
pub struct BindingCompletionV1 {
    correlation: BindingCorrelationV1,
}
impl BindingCompletionV1 {
    pub fn from_firmware_status(
        correlation: &BindingCorrelationV1,
        status: u32,
    ) -> Result<Self, BindingErrorV1> {
        if status != 0 {
            return Err(BindingErrorV1 {
                correlation: Box::new(correlation.clone()),
                failure: BindingFailureV1::FirmwareRejected { status },
                effect: MigrationInstallEffectV1::Unknown,
                raw_firmware_status: Some(status),
            });
        }
        Ok(Self {
            correlation: correlation.clone(),
        })
    }
    pub const fn correlation(&self) -> &BindingCorrelationV1 {
        &self.correlation
    }
}

/// No codec, Clone or plaintext Debug. The caller retains zeroizing ownership.
pub struct BindingSecretRequestV1<'a> {
    correlation: BindingCorrelationV1,
    role: SnpMaRoleV1,
    secret: &'a [u8; 32],
}
impl fmt::Debug for BindingSecretRequestV1<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BindingSecretRequestV1(<redacted>)")
    }
}
impl<'a> BindingSecretRequestV1<'a> {
    pub fn new(
        binding: &LocalHandoffBindingV1,
        target: ManagedGuestHandle,
        role: SnpMaRoleV1,
        secret: &'a [u8; 32],
    ) -> Result<Self, BindingErrorV1> {
        let correlation = BindingCorrelationV1 {
            operation: BindingOperationV1::SetSecret,
            target,
            binding: binding.clone(),
            tenant_report_id: None,
            slot_role: Some(role),
        };
        if binding.purpose != SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization
            || binding.encode_exact().is_err()
            || !matches!(role, SnpMaRoleV1::Outgoing | SnpMaRoleV1::Incoming)
        {
            return Err(BindingErrorV1 {
                correlation: Box::new(correlation),
                failure: BindingFailureV1::InvalidRequest,
                effect: MigrationInstallEffectV1::NotApplied,
                raw_firmware_status: None,
            });
        }
        Ok(Self {
            correlation,
            role,
            secret,
        })
    }
    pub const fn role(&self) -> SnpMaRoleV1 {
        self.role
    }
    pub const fn correlation(&self) -> &BindingCorrelationV1 {
        &self.correlation
    }
    pub const fn secret(&self) -> &[u8; 32] {
        self.secret
    }
}

pub struct BindingRebindRequestV1<'a> {
    correlation: BindingCorrelationV1,
    mode: LocalHandoffModeV1,
    planned: Option<&'a PlannedHandoffContractV1>,
    recovery: Option<&'a RecoveryContractV1>,
}
impl<'a> BindingRebindRequestV1<'a> {
    pub fn planned(
        binding: &LocalHandoffBindingV1,
        target: ManagedGuestHandle,
        tenant: &VerifiedTenantReportIdV1,
        contract: &'a PlannedHandoffContractV1,
    ) -> Result<Self, BindingErrorV1> {
        Self::new(binding, target, tenant, Some(contract), None)
    }
    pub fn recovery(
        binding: &LocalHandoffBindingV1,
        target: ManagedGuestHandle,
        tenant: &VerifiedTenantReportIdV1,
        contract: &'a RecoveryContractV1,
    ) -> Result<Self, BindingErrorV1> {
        Self::new(binding, target, tenant, None, Some(contract))
    }
    fn new(
        binding: &LocalHandoffBindingV1,
        target: ManagedGuestHandle,
        tenant: &VerifiedTenantReportIdV1,
        planned: Option<&'a PlannedHandoffContractV1>,
        recovery: Option<&'a RecoveryContractV1>,
    ) -> Result<Self, BindingErrorV1> {
        let mode = if planned.is_some() {
            LocalHandoffModeV1::Planned
        } else {
            LocalHandoffModeV1::Recovery
        };
        let correlation = BindingCorrelationV1 {
            operation: if planned.is_some() {
                BindingOperationV1::PlannedRebind
            } else {
                BindingOperationV1::RecoveryRebind
            },
            target,
            binding: binding.clone(),
            tenant_report_id: Some(*tenant.as_bytes()),
            slot_role: None,
        };
        let valid = match (planned, recovery) {
            (Some(contract), None) => {
                contract.phase() == LocalHandoffPhaseV1::Ready
                    && contract.binding() == binding
                    && contract.contains_tenant(tenant)
            }
            (None, Some(contract)) => {
                contract.phase() == LocalHandoffPhaseV1::Ready
                    && contract.binding() == binding
                    && contract.contains_tenant(tenant)
            }
            _ => false,
        };
        if !valid {
            return Err(BindingErrorV1 {
                correlation: Box::new(correlation),
                failure: BindingFailureV1::InvalidRequest,
                effect: MigrationInstallEffectV1::NotApplied,
                raw_firmware_status: None,
            });
        }
        Ok(Self {
            correlation,
            mode,
            planned,
            recovery,
        })
    }
    pub const fn correlation(&self) -> &BindingCorrelationV1 {
        &self.correlation
    }
    pub const fn mode(&self) -> LocalHandoffModeV1 {
        self.mode
    }
    pub fn still_ready(&self) -> bool {
        self.planned
            .is_some_and(|c| c.phase() == LocalHandoffPhaseV1::Ready)
            || self
                .recovery
                .is_some_and(|c| c.phase() == LocalHandoffPhaseV1::Ready)
    }
}

#[derive(Debug)]
pub struct AuthoritativeBindingV1 {
    pub correlation: BindingCorrelationV1,
    pub current_ma_report_id: [u8; 32],
    pub migration_data_valid: bool,
    pub migration_data: [u8; 64],
}

/// Recheck current policy, purpose, binding, epoch/attempt, deadline, slot
/// ownership and effect scope on every effect. Cleanup uses VALID=0 with an
/// acknowledged response. Recovery is incoming-only and requires exact firmware
/// identity/launch equivalence, never an old-MA process or handoff secret.
/// Queries are authoritative platform observations, never host assertions.
/// No method retries or serializes a secret into host control.
pub trait MaBindingManagerV1 {
    fn set_handoff_secret(
        &mut self,
        request: &BindingSecretRequestV1<'_>,
    ) -> Result<BindingCompletionV1, BindingErrorV1>;
    fn clear_handoff_secret(
        &mut self,
        correlation: &BindingCorrelationV1,
    ) -> Result<BindingCompletionV1, BindingErrorV1>;
    fn rebind_handoff(
        &mut self,
        request: &BindingRebindRequestV1<'_>,
    ) -> Result<BindingCompletionV1, BindingErrorV1>;
    fn rebind_recovery(
        &mut self,
        request: &BindingRebindRequestV1<'_>,
    ) -> Result<BindingCompletionV1, BindingErrorV1>;
    fn query_binding(
        &mut self,
        correlation: &BindingCorrelationV1,
    ) -> Result<AuthoritativeBindingV1, BindingErrorV1>;
}
pub struct UnavailableMaBindingManagerV1;
impl MaBindingManagerV1 for UnavailableMaBindingManagerV1 {
    fn set_handoff_secret(
        &mut self,
        r: &BindingSecretRequestV1<'_>,
    ) -> Result<BindingCompletionV1, BindingErrorV1> {
        Err(BindingErrorV1::unavailable(&r.correlation))
    }
    fn clear_handoff_secret(
        &mut self,
        c: &BindingCorrelationV1,
    ) -> Result<BindingCompletionV1, BindingErrorV1> {
        Err(BindingErrorV1::unavailable(c))
    }
    fn rebind_handoff(
        &mut self,
        r: &BindingRebindRequestV1<'_>,
    ) -> Result<BindingCompletionV1, BindingErrorV1> {
        Err(BindingErrorV1::unavailable(r.correlation()))
    }
    fn rebind_recovery(
        &mut self,
        r: &BindingRebindRequestV1<'_>,
    ) -> Result<BindingCompletionV1, BindingErrorV1> {
        Err(BindingErrorV1::unavailable(r.correlation()))
    }
    fn query_binding(
        &mut self,
        c: &BindingCorrelationV1,
    ) -> Result<AuthoritativeBindingV1, BindingErrorV1> {
        Err(BindingErrorV1::unavailable(c))
    }
}
