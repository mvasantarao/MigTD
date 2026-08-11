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
