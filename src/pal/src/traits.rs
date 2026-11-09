// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "snp-fixture")]
use crate::types::QvlResult;
use crate::types::{
    AttestationBundle, MaEvidence, MaEvidenceError, MaEvidenceRequest, SnpCollateralError,
    SnpCollateralRequest, SnpEvidenceVerificationRequest, SnpOperationContext,
    SnpVerificationCollateral, SnpVerificationError, VerifiedSnpEvidence,
};

#[derive(Debug)]
pub enum PalError {
    NotAvailable,
    InvalidInput,
    VerificationFailed(String),
}

/// Compatibility boundary for the current combined report/collateral blob.
/// Runtime callers acquire separate selected MA evidence and collateral.
/// This legacy adapter is not the common V6 evidence or verification contract.
pub trait AttestationProvider {
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationBundle, PalError>;
}

/// Acquires only the local migration agent's SNP attestation report.
pub trait MaEvidenceProvider {
    fn acquire_ma_evidence(
        &self,
        request: &MaEvidenceRequest,
    ) -> Result<MaEvidence, MaEvidenceError>;
}

/// Acquires the certificate collateral needed to verify local SNP evidence.
///
/// Implementations must not fall back across fixture and hardware trust
/// boundaries.
pub trait SnpCollateralProvider {
    fn acquire_snp_collateral(
        &self,
        request: &SnpCollateralRequest<'_>,
    ) -> Result<SnpVerificationCollateral, SnpCollateralError>;
}

pub trait SnpEvidenceVerifier {
    fn verify_evidence(
        &self,
        request: &SnpEvidenceVerificationRequest<'_>,
    ) -> Result<VerifiedSnpEvidence, SnpVerificationError>;
}

/// Disabled compatibility boundary; V1 has no approved platform-derived-key use.
///
/// This context-only method is not a purpose-scoped derived-key request. Any
/// future operation requires a separately approved typed contract.
pub trait PlatformKeyProvider {
    fn prepare_key(&self, context: &SnpOperationContext) -> Result<(), PalError>;
}

/// Rejects legacy preparation requests without deriving keys or invoking firmware.
pub struct UnavailablePlatformKeyProvider;

impl PlatformKeyProvider for UnavailablePlatformKeyProvider {
    fn prepare_key(&self, _context: &SnpOperationContext) -> Result<(), PalError> {
        Err(PalError::NotAvailable)
    }
}

/// Legacy key-only mock/runtime boundary; not the typed T4.11 installation API.
/// New SNP code uses `snp::migration_install::SnpMigrationKeyInstaller`.
/// Do not adapt this call by fabricating tenant, session or history inputs.
pub trait MigrationKeyInstaller {
    fn set_migration_info(
        &self,
        context: &SnpOperationContext,
        migration_key: &[u8],
    ) -> Result<(), PalError>;
}

#[cfg(feature = "snp-fixture")]
pub trait QvlLibrary {
    fn verify(
        &self,
        params: &crate::snp::qvl::validate::AttestationVerificationParams<'_>,
        cert_chain: &[Vec<u8>],
    ) -> Result<QvlResult, PalError>;
}

// Copyright (c) 2026 Microsoft Corporation

/// LogPlatform: abstraction over the structured attestation log output channel.
/// Phase 3a: SnpEmuLogPlatform (heap-backed Vec ring buffer).
/// Phase 3b: RealSnpLogPlatform (GHCB-backed shared page via GhcbVmgexitTransport).
pub trait LogPlatform: Send + Sync {
    /// Write a structured binary log entry (type tag + payload bytes).
    fn write_entry(&self, event_type: u32, payload: &[u8]) -> Result<(), PalError>;

    /// Allocate or return the shared log page address (Phase 3b: GHCB shared page).
    fn alloc_shared_page(&self) -> Result<usize, PalError>;

    /// Return the vCPU count (used by RealSnpLogPlatform for GHCB sizing).
    fn vcpu_count(&self) -> u32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole};

    #[test]
    fn platform_key_preparation_is_unavailable_for_both_roles_and_retries() {
        let provider = UnavailablePlatformKeyProvider;
        for role in [MigrationRole::Source, MigrationRole::Destination] {
            let context = SnpOperationContext::new(
                HostRequestId::new(7),
                MigrationId::new(8),
                role,
                ManagedGuestHandle::new(0x1234),
            );
            for _ in 0..2 {
                assert!(matches!(
                    provider.prepare_key(&context),
                    Err(PalError::NotAvailable)
                ));
            }
        }
    }
}
