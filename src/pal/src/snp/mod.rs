// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod certs;
pub mod identity;
pub mod key_ops;
pub mod policy;
pub mod qvl;
pub mod report;

#[cfg(not(feature = "snp-emu"))]
pub mod hardware;

pub mod fixture;

// CI guard: snp_fixture_only ensures SnpEmu is active — hardware paths are blocked in CI.
#[cfg(all(feature = "snp_fixture_only", not(feature = "snp-emu")))]
compile_error!(
    "snp_fixture_only requires the snp-emu feature. Hardware paths must not be enabled in CI builds."
);
