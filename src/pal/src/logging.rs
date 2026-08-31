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

/// Phase 3a: heap-backed ring buffer LogPlatform impl for SnpEmu (userspace testing).
/// Phase 3b: replaced by GHCB-backed shared page implementation (RealSnpLogPlatform).
#[cfg(feature = "snp-emu")]
pub struct SnpEmuLogPlatform {
    entries: std::sync::Mutex<std::collections::VecDeque<(u32, Vec<u8>)>>,
    capacity: usize,
}

#[cfg(feature = "snp-emu")]
impl SnpEmuLogPlatform {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
            capacity,
        }
    }
}

#[cfg(feature = "snp-emu")]
impl crate::traits::LogPlatform for SnpEmuLogPlatform {
    fn write_entry(&self, event_type: u32, payload: &[u8]) -> Result<(), crate::traits::PalError> {
        let mut q = self
            .entries
            .lock()
            .map_err(|_| crate::traits::PalError::NotAvailable)?;
        if q.len() >= self.capacity {
            q.pop_front();
        }
        q.push_back((event_type, payload.to_vec()));
        Ok(())
    }

    fn alloc_shared_page(&self) -> Result<usize, crate::traits::PalError> {
        Ok(0) // heap-only in Phase 3a; Phase 3b uses GHCB shared page
    }
}
