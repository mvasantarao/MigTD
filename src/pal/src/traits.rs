// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::types::QvlResult;

#[derive(Debug)]
pub enum PalError { NotAvailable, InvalidInput, VerificationFailed(String) }

pub trait AttestationProvider {
    fn get_report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, PalError>;
    fn get_cert_chain(&self) -> Result<Vec<Vec<u8>>, PalError>;
}

pub trait QvlLibrary {
    fn verify(&self, report: &[u8], cert_chain: &[Vec<u8>]) -> Result<QvlResult, PalError>;
}
