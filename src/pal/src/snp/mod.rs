// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod authorization_result;
pub mod certs;
pub mod collateral_set;
pub mod evidence_header;
pub mod identity;
pub mod key_ops;
pub mod limits;
pub mod ma_evidence;
pub mod policy;
pub mod policy_identity;
pub mod qvl;
pub mod report;
pub mod report_data_context;
pub mod tenant_evidence;
pub mod tenant_policy_context;
pub mod wire;

#[cfg(test)]
mod golden_vectors;

#[cfg(test)]
mod property_tests;

#[cfg(not(feature = "snp-emu"))]
pub mod hardware;

pub mod fixture;

// CI guard: snp_fixture_only ensures SnpEmu is active — hardware paths are blocked in CI.
#[cfg(all(feature = "snp_fixture_only", not(feature = "snp-emu")))]
compile_error!(
    "snp_fixture_only requires the snp-emu feature. Hardware paths must not be enabled in CI builds."
);
