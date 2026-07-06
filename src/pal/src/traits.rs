// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::types::{AttestationBundle, QvlResult};

#[derive(Debug)]
pub enum PalError { NotAvailable, InvalidInput, VerificationFailed(String) }

pub trait AttestationProvider {
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationBundle, PalError>;
}

#[cfg(feature = "snp-emu")]
pub trait QvlLibrary {
    fn verify(
        &self,
        params: &crate::snp::qvl::validate::AttestationVerificationParams<'_>,
        cert_chain: &[Vec<u8>],
    ) -> Result<QvlResult, PalError>;
}
