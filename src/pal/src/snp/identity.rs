// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SnpIdentityInfo: SNP platform identity struct sent as TdReportInit wire element.
//! Phase 2: zero-value (SNP has no TDX TDINFO_STRUCT equivalent on the wire).
//! Phase 3: populate VMPL, cpuid_fam_id/mod_id, current_tcb, platform_info from
//!          the MA's own ATTESTATION_REPORT fields.
//!
//! Wire compatibility note: VdmMessageElementType::TdReportInit name is RETAINED for
//! wire compatibility with TDX peers. Payload is SnpIdentityInfo (not TDREPORT).
//! Receiver accepts 0-length TdReportInit for SNP peers (no SERVTD_EXT equivalent).

use zerocopy::{FromZeros, Immutable, IntoBytes};

/// 512-byte identity blob (same wire size as TDX TDINFO_STRUCT for compatibility).
/// Phase 2: all-zero — signals "SNP peer, no SERVTD_EXT" to destination.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, Immutable, FromZeros)]
pub struct SnpIdentityInfo {
    /// VMPL level (0-3). Phase 2: 0.
    pub vmpl: u8,
    /// CPU family ID (cpuid_fam_id). Phase 2: 0.
    pub cpuid_fam_id: u8,
    /// CPU model ID (cpuid_mod_id). Phase 2: 0.
    pub cpuid_mod_id: u8,
    pub reserved0: u8,
    /// current_tcb from ATTESTATION_REPORT (8 bytes). Phase 2: zero.
    pub current_tcb: [u8; 8],
    /// platform_info from ATTESTATION_REPORT (8 bytes). Phase 2: zero.
    pub platform_info: [u8; 8],
    /// Padding to 512 bytes for wire compatibility with TDX TDINFO_STRUCT.
    pub reserved: [u8; 492],
}
