// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Platform contracts and selected provider ownership. SNP runtime roots use
//! `composition::snp`; legacy combined-blob adapters are compatibility only.

#[cfg(all(
    feature = "snp-linux-hardware",
    any(feature = "snp-fixture", feature = "snp_fixture_only", feature = "tdx")
))]
compile_error!("SNP hardware cannot include fixture evidence, synthetic roots or TDX providers");

pub mod composition;
pub mod random;
pub mod snp_report;
pub mod tenant_identity;
pub mod tenant_replay;
pub mod traits;
pub mod types;

#[cfg(feature = "snp-core")]
pub mod snp;
#[cfg(feature = "tdx")]
pub mod tdx;

#[cfg(feature = "snp-core")]
pub mod logging;
