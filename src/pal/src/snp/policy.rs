// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SnpMigPolicy: SNP migration policy struct.
//! Phase 2: all-zero value. SHA384(zeroed) replaces SHA384(&[]) as MigPolicyMy wire hash.
//! Phase 3: populate MinLaunchTCB, MinLaunchETCB, MA policy bits from MIGRATION_DATA.

use zerocopy::{FromZeros, Immutable, IntoBytes};

/// SNP Migration Policy wire structure (Phase 2: zero-value, 64 bytes).
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, Immutable, FromZeros)]
pub struct SnpMigPolicy {
    /// Minimum launch TCB for accepted peers. Phase 2: zero (accept all).
    pub min_launch_tcb: [u8; 8],
    /// Minimum launch ETCB (ARG SVN floor). Phase 2: zero.
    pub min_launch_etcb: [u8; 8],
    /// Reserved / future policy bits. Phase 2: zero.
    pub reserved: [u8; 48],
}

use crate::traits::PalError;

/// Extracted SNP ATTESTATION_REPORT fields for policy evaluation.
/// Pure data adapter — no TAV calls, no cert validation.
/// Phase 4 will wire this into the full policy evaluation consumer.
#[derive(Debug, Clone)]
pub struct PolicyEvaluationInfo {
    pub chip_id: [u8; 64],
    pub vmpl: u32,
    pub launch_digest: [u8; 48],
    pub current_tcb: u64,
    pub policy_bits: u64,
    pub source_tag: &'static str, // "fixture" or "hardware"
}

impl PolicyEvaluationInfo {
    /// Build from raw SNP ATTESTATION_REPORT bytes (1184 bytes, AMD FW ABI Table 23).
    pub fn from_snp_report(report: &[u8]) -> Result<Self, PalError> {
        if report.len() < 1184 {
            return Err(PalError::InvalidInput);
        }
        Ok(Self {
            policy_bits: u64::from_le_bytes(report[0x08..0x10].try_into().unwrap()),
            vmpl: u32::from_le_bytes(report[0x30..0x34].try_into().unwrap()),
            current_tcb: u64::from_le_bytes(report[0x38..0x40].try_into().unwrap()),
            launch_digest: report[0x90..0xC0]
                .try_into()
                .map_err(|_| PalError::InvalidInput)?,
            chip_id: report[0x1A0..0x1E0]
                .try_into()
                .map_err(|_| PalError::InvalidInput)?,
            source_tag: if cfg!(feature = "snp-emu") {
                "fixture"
            } else {
                "hardware"
            },
        })
    }
}
