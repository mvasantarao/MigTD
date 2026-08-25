// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SNP logging utilities for the Migration Agent.
//!
//! TDX logging (TDCALL-backed log area) lives in migtd/src/migration/logging.rs
//! gated on feature "vmcall-raw". This module provides the SNP/SnpEmu-side
//! utilities and LogPlatform implementations (added in Phase 3a sprint 3a-23).

use log::LevelFilter;

/// Convert a u8 log level value to a log::LevelFilter.
/// Shared between TDX and SNP paths — identical semantics.
pub fn u8_to_levelfilter(value: u8) -> LevelFilter {
    match value {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

// Phase 3a: SnpEmuLogPlatform and TdxLogPlatform added in sprint 3a-23.
