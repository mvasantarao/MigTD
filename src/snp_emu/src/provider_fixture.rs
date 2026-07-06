// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SnpFixtureProvider: AttestationProvider backed by pre-captured fixture files.
//!
//! Phase 1: returns ma_report_blob (real AMD fixture report + cert chain),
//!          tenant_report is None (no tenant CVM in emulator test).
//! Phase 3: SnpHardwareProvider replaces this with live GHCB SNP_GET_REPORT.

use pal::traits::{AttestationProvider, PalError};
use pal::types::AttestationBundle;

use crate::report_emu::build_fixture_blob;

pub struct SnpFixtureProvider;

impl AttestationProvider for SnpFixtureProvider {
    fn get_report(&self, _report_data: &[u8; 64]) -> Result<AttestationBundle, PalError> {
        // _report_data accepted but NOT injected into the fixture.
        // The fixture report carries the report_data from its original capture time.
        // TH1 binding failure is an accepted Phase 1 limitation (resolved in Phase 3
        // when real AMD hardware generates a fresh report per session).
        Ok(AttestationBundle {
            ma_report_blob: build_fixture_blob()?,
            tenant_report: None, // Phase 3: Some(tenant_cvm_report)
        })
    }
}
