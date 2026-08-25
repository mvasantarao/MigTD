// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MigrationKeyOps: abstraction over SNP PSP key export/import lifecycle.
//!
//! Phase 3a: SnpEmuKeyOps returns NotAvailable (fixture phase, no PSP, A3).
//! Phase 3b: real impl via MSG_KEY_REQ + MSG_SET_MIGRATION_INFO through
//!   /dev/sev-guest GHCB VMGEXIT path (Venice hardware required).

use crate::traits::PalError;

pub trait MigrationKeyOps {
    fn export(&self, session: u64) -> Result<Vec<u8>, PalError>;
    fn import(&self, session: u64, material: &[u8]) -> Result<(), PalError>;
    fn abort(&self, session: u64) -> Result<(), PalError>;
    fn zeroize(&self, session: u64) -> Result<(), PalError>;
}

/// Phase 3a stub — returns NotAvailable (PSP not available in fixture mode, A3).
#[cfg(feature = "snp-emu")]
pub struct SnpEmuKeyOps;

#[cfg(feature = "snp-emu")]
impl MigrationKeyOps for SnpEmuKeyOps {
    fn export(&self, _session: u64) -> Result<Vec<u8>, PalError> {
        Err(PalError::NotAvailable)
    }
    fn import(&self, _session: u64, _material: &[u8]) -> Result<(), PalError> {
        Err(PalError::NotAvailable)
    }
    fn abort(&self, _session: u64) -> Result<(), PalError> {
        Err(PalError::NotAvailable)
    }
    fn zeroize(&self, _session: u64) -> Result<(), PalError> {
        Err(PalError::NotAvailable)
    }
}
