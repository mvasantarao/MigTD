// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::traits::{AttestationProvider, PalError};
use crate::types::AttestationBundle;

pub struct TdxAttestationProvider;

impl AttestationProvider for TdxAttestationProvider {
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationBundle, PalError> {
        let _ = report_data;
        Err(PalError::NotAvailable)
    }
}
