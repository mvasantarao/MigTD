// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Phase 1 stub -- full cert chain + report signature verification in Phase 2.
// Will use sev::certs::snp for ARK->ASK->VCEK chain verification.

use crate::traits::{PalError, QvlLibrary};
use crate::types::QvlResult;

pub struct SnpQvl;

impl QvlLibrary for SnpQvl {
    fn verify(&self, _report: &[u8], _cert_chain: &[Vec<u8>]) -> Result<QvlResult, PalError> {
        Err(PalError::NotAvailable)
    }
}
