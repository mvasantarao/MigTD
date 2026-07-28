// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SNP attestation report validation parameters.
//!
//! Phase 1: struct skeleton only — validate() is a stub returning Ok(()).
//! Phase 2 (P2-07): implement tcb_ge() + full validate() logic.
//! Phase 3: populate Option<> fields for forwardPolicy / MIGRATION_DATA / maReportID.

use tee_attestation_verification_lib::snp::report::TcbVersionMilanGenoa as TcbVersion;

use crate::traits::PalError;

/// Parameters governing what validate() checks.
///
/// Phase 2: use crypto_only() constructor — all Option fields are None.
/// Phase 3: populate source_tcb, migration_data, ma_report_id as needed.
pub struct AttestationVerificationParams<'a> {
    /// Raw bytes of the SNP attestation report (1184 bytes).
    pub report: &'a [u8],
    /// Expected SHA384 digest (48 bytes): SHA384("MigTDReq" || TH1) or ("MigTDRsp" || TH1).
    pub expected_report_data: &'a [u8; 48],
    /// Minimum acceptable TCB. Phase 1: None (all-zero = accept anything).
    pub min_tcb: Option<TcbVersion>,
    /// Minimum acceptable guest SVN. Phase 1: None.
    pub min_guest_svn: Option<u32>,
    /// Phase 3 forwardPolicy: source MA's own TCB ("reference: self").
    pub source_tcb: Option<TcbVersion>,
    /// Phase 3 forwardPolicy: source MA's own guest SVN.
    pub source_guest_svn: Option<u32>,
    /// Phase 3 MIGRATION_DATA blob for MinLaunchMITVector / MinLaunchTCB checks.
    pub migration_data: Option<&'a [u8]>,
    /// Phase 3 maReportID binding: SHA256(source_MA_report)[0..32].
    pub ma_report_id: Option<&'a [u8; 32]>,
}

impl<'a> AttestationVerificationParams<'a> {
    /// Creates params for cryptographic verification only — cert chain (ARK→ASK→VCEK),
    /// report ECDSA signature, and report_data binding are checked;
    /// all policy fields (min_tcb, source_tcb, ma_report_id, migration_data) are None.
    pub fn crypto_only(report: &'a [u8], expected_report_data: &'a [u8; 48]) -> Self {
        Self {
            report,
            expected_report_data,
            min_tcb: None,
            min_guest_svn: None,
            source_tcb: None,
            source_guest_svn: None,
            migration_data: None,
            ma_report_id: None,
        }
    }
}

/// Validate an SNP attestation report against the given parameters.
///
/// Phase 1: stub — returns Ok(()) unconditionally.
/// Phase 2 (P2-07): implement tcb_ge() and full policy checks.
pub fn validate(_params: &AttestationVerificationParams<'_>) -> Result<(), PalError> {
    Ok(())
}
