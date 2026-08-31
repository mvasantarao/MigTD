// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::types::{AttestationBundle, QvlResult};

#[derive(Debug)]
pub enum PalError {
    NotAvailable,
    InvalidInput,
    VerificationFailed(String),
}

pub trait AttestationProvider {
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationBundle, PalError>;
}

#[cfg(feature = "snp-emu")]
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
