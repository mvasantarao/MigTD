// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! T4.11 logical installation boundary, not a firmware ABI or authorization engine.

use core::fmt;

use super::{
    direct_key::SnpSessionReferenceV2, migration_data::MigrationDataV1,
    report_data_context::SnpMigrationAlgorithmV1, wire::SnpCodecError,
};
use crate::{
    tenant_identity::VerifiedTenantIdentity,
    tenant_replay::VerifiedTenantAuthorizationV1,
    types::{MigrationRole, SnpOperationContext},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationInstallInputErrorV1 {
    OperationMismatch,
    TenantMismatch,
    SessionRequestMismatch,
    UnsupportedAlgorithm,
    InvalidMigrationData(SnpCodecError),
}

/// Validated shape/correlation, not proof of policy, replay or key acceptance.
///
/// The caller must independently admit the exact history, reconstruct the
/// V2 nonsecret session reference, complete policy/replay admission and protected
/// key-delivery acceptance,
/// and retain/zeroize the secret owner and any transport copies. No key is owned
/// or cloned here. The provider must recheck current target/state authorization.
///
/// ```compile_fail
/// use pal::snp::migration_install::MigrationInstallRequestV1;
/// fn duplicate(request: MigrationInstallRequestV1<'_>) {
///     let _ = request.clone();
/// }
/// ```
///
/// ```compile_fail
/// use pal::{
///     snp::{direct_key::SnpSessionReferenceV2,
///         migration_install::MigrationInstallRequestV1,
///         report_data_context::SnpMigrationAlgorithmV1},
///     tenant_identity::VerifiedTenantIdentity,
///     tenant_replay::VerifiedTenantAuthorizationV1,
///     types::SnpOperationContext,
/// };
/// fn escape<'a>(operation: &'a SnpOperationContext, tenant: &'a VerifiedTenantIdentity,
///     authorization: &'a VerifiedTenantAuthorizationV1,
///     session: &'a SnpSessionReferenceV2, history: &'a [u8; 64])
///     -> MigrationInstallRequestV1<'a> {
///     let secret = [42; 32];
///     MigrationInstallRequestV1::new(operation, tenant, authorization, session,
///         &secret, history, SnpMigrationAlgorithmV1::Aes256GcmMigrationV1).unwrap()
/// }
/// ```
pub struct MigrationInstallRequestV1<'a> {
    operation: &'a SnpOperationContext,
    tenant: &'a VerifiedTenantIdentity,
    authorization: &'a VerifiedTenantAuthorizationV1,
    session: &'a SnpSessionReferenceV2,
    migration_key: &'a [u8; 32],
    migration_data: &'a [u8; 64],
}

impl<'a> MigrationInstallRequestV1<'a> {
    pub fn new(
        operation: &'a SnpOperationContext,
        tenant: &'a VerifiedTenantIdentity,
        authorization: &'a VerifiedTenantAuthorizationV1,
        session: &'a SnpSessionReferenceV2,
        migration_key: &'a [u8; 32],
        migration_data: &'a [u8; 64],
        algorithm: SnpMigrationAlgorithmV1,
    ) -> Result<Self, MigrationInstallInputErrorV1> {
        let binding = authorization.binding().as_stored();
        if binding.operation != *operation {
            return Err(MigrationInstallInputErrorV1::OperationMismatch);
        }
        if binding.tenant_report_id != *tenant.as_bytes() {
            return Err(MigrationInstallInputErrorV1::TenantMismatch);
        }
        if session.request_id != operation.request_id.value() {
            return Err(MigrationInstallInputErrorV1::SessionRequestMismatch);
        }
        if algorithm != SnpMigrationAlgorithmV1::Aes256GcmMigrationV1 {
            return Err(MigrationInstallInputErrorV1::UnsupportedAlgorithm);
        }
        MigrationDataV1::decode_exact(migration_data)
            .map_err(MigrationInstallInputErrorV1::InvalidMigrationData)?;
        Ok(Self {
            operation,
            tenant,
            authorization,
            session,
            migration_key,
            migration_data,
        })
    }

    pub const fn operation(&self) -> &SnpOperationContext {
        self.operation
    }

    pub const fn tenant(&self) -> &VerifiedTenantIdentity {
        self.tenant
    }

    pub const fn authorization(&self) -> &VerifiedTenantAuthorizationV1 {
        self.authorization
    }

    pub const fn session(&self) -> &SnpSessionReferenceV2 {
        self.session
    }

    pub const fn migration_key(&self) -> &[u8; 32] {
        self.migration_key
    }

    pub const fn migration_data(&self) -> &[u8; 64] {
        self.migration_data
    }

    pub const fn algorithm(&self) -> SnpMigrationAlgorithmV1 {
        SnpMigrationAlgorithmV1::Aes256GcmMigrationV1
    }

    /// Logical operand only; the lower layer owns firmware encoding/addresses.
    pub fn firmware_report_id(&self) -> [u8; 32] {
        match self.operation.role {
            MigrationRole::Source => *self.tenant.as_bytes(),
            MigrationRole::Destination => [0; 32],
        }
    }

    pub fn correlation(&self) -> MigrationInstallCorrelationV1 {
        MigrationInstallCorrelationV1 {
            operation: *self.operation,
            tenant_report_id: *self.tenant.as_bytes(),
            session: self.session.clone(),
        }
    }
}

impl fmt::Debug for MigrationInstallRequestV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationInstallRequestV1")
            .field("operation", self.operation)
            .field("material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationInstallCorrelationV1 {
    operation: SnpOperationContext,
    tenant_report_id: [u8; 32],
    session: SnpSessionReferenceV2,
}

impl MigrationInstallCorrelationV1 {
    pub const fn operation(&self) -> &SnpOperationContext {
        &self.operation
    }

    pub const fn tenant_report_id(&self) -> &[u8; 32] {
        &self.tenant_report_id
    }

    pub const fn session(&self) -> &SnpSessionReferenceV2 {
        &self.session
    }
}

/// A trusted provider's local status observation, not an attested persistence
/// receipt or P0.8 wire result. Callers must check correlation before advancing.
#[derive(Debug, PartialEq, Eq)]
pub struct MigrationInstallCompletionV1 {
    correlation: MigrationInstallCorrelationV1,
}

impl MigrationInstallCompletionV1 {
    pub fn from_firmware_status(
        request: &MigrationInstallRequestV1<'_>,
        status: u32,
    ) -> Result<Self, MigrationInstallErrorV1> {
        if status != 0 {
            return Err(MigrationInstallErrorV1 {
                correlation: Box::new(request.correlation()),
                failure: MigrationInstallFailureV1::FirmwareRejected { status },
            });
        }
        Ok(Self {
            correlation: request.correlation(),
        })
    }

    pub const fn correlation(&self) -> &MigrationInstallCorrelationV1 {
        &self.correlation
    }

    pub const fn firmware_status(&self) -> u32 {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationInstallEffectV1 {
    NotApplied,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationInstallFailureV1 {
    Unavailable,
    FirmwareRejected { status: u32 },
    Transport { effect: MigrationInstallEffectV1 },
    PartialInstallation { firmware_status: Option<u32> },
    Indeterminate { firmware_status: Option<u32> },
}

#[derive(Debug, PartialEq, Eq)]
pub struct MigrationInstallErrorV1 {
    correlation: Box<MigrationInstallCorrelationV1>,
    failure: MigrationInstallFailureV1,
}

impl MigrationInstallErrorV1 {
    pub fn unavailable(request: &MigrationInstallRequestV1<'_>) -> Self {
        Self {
            correlation: Box::new(request.correlation()),
            failure: MigrationInstallFailureV1::Unavailable,
        }
    }

    /// NotApplied is valid only when the provider knows no effect occurred.
    pub fn transport(
        request: &MigrationInstallRequestV1<'_>,
        effect: MigrationInstallEffectV1,
    ) -> Self {
        Self {
            correlation: Box::new(request.correlation()),
            failure: MigrationInstallFailureV1::Transport { effect },
        }
    }

    pub fn partial(request: &MigrationInstallRequestV1<'_>, firmware_status: Option<u32>) -> Self {
        Self {
            correlation: Box::new(request.correlation()),
            failure: MigrationInstallFailureV1::PartialInstallation { firmware_status },
        }
    }

    pub fn indeterminate(
        request: &MigrationInstallRequestV1<'_>,
        firmware_status: Option<u32>,
    ) -> Self {
        Self {
            correlation: Box::new(request.correlation()),
            failure: MigrationInstallFailureV1::Indeterminate { firmware_status },
        }
    }

    pub fn correlation(&self) -> &MigrationInstallCorrelationV1 {
        &self.correlation
    }

    pub const fn failure(&self) -> MigrationInstallFailureV1 {
        self.failure
    }

    pub const fn firmware_status(&self) -> Option<u32> {
        match self.failure {
            MigrationInstallFailureV1::FirmwareRejected { status } => Some(status),
            MigrationInstallFailureV1::PartialInstallation { firmware_status }
            | MigrationInstallFailureV1::Indeterminate { firmware_status } => firmware_status,
            _ => None,
        }
    }

    pub const fn effect(&self) -> MigrationInstallEffectV1 {
        match self.failure {
            MigrationInstallFailureV1::Unavailable => MigrationInstallEffectV1::NotApplied,
            MigrationInstallFailureV1::Transport { effect } => effect,
            MigrationInstallFailureV1::PartialInstallation { .. } => {
                MigrationInstallEffectV1::Partial
            }
            // No qualified mapping of raw rejection codes to effects is installed.
            MigrationInstallFailureV1::FirmwareRejected { .. }
            | MigrationInstallFailureV1::Indeterminate { .. } => MigrationInstallEffectV1::Unknown,
        }
    }

    pub fn requires_reconciliation(&self) -> bool {
        self.effect() != MigrationInstallEffectV1::NotApplied
    }
}

/// Future providers own target resolution, protected invocation, current bound-MA,
/// role/guest-state/active-session checks and secret-copy cleanup. Preserve raw
/// status: INVALID_GUEST and INVALID_GUEST_STATE cannot identify every root cause.
/// A timeout after submission must not be reported as known no-effect.
///
/// This boundary never retries. Errors stop advancement; partial/unknown effects
/// require reconciliation. No implementation here activates a runtime provider.
pub trait SnpMigrationKeyInstaller {
    fn install_migration_info(
        &self,
        request: &MigrationInstallRequestV1<'_>,
    ) -> Result<MigrationInstallCompletionV1, MigrationInstallErrorV1>;
}

pub struct UnavailableMigrationKeyInstallerV1;

impl SnpMigrationKeyInstaller for UnavailableMigrationKeyInstallerV1 {
    fn install_migration_info(
        &self,
        request: &MigrationInstallRequestV1<'_>,
    ) -> Result<MigrationInstallCompletionV1, MigrationInstallErrorV1> {
        Err(MigrationInstallErrorV1::unavailable(request))
    }
}

#[cfg(test)]
#[path = "migration_install_tests.rs"]
mod tests;
