// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod traits;
pub mod types;

#[cfg(feature = "snp-emu")]
pub mod snp;
#[cfg(feature = "tdx")]
pub mod tdx;

#[cfg(feature = "snp-emu")]
pub mod logging;
