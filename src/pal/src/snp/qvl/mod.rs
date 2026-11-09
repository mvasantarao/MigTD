// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Captured-fixture SDK compatibility and structural validation. Shared V6
//! callers use `composition::snp::SnpProviderSet::services().verifier`; this
//! module is not its fallback or a source of authenticated common claims.

#[cfg(all(feature = "snp-fixture", feature = "snp-aas-verify"))]
pub mod azure;
pub mod validate;
#[cfg(feature = "snp-fixture")]
pub mod verify;
