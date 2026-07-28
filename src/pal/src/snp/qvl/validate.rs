// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SNP attestation report validation parameters.
//!
//! Phase 1: struct skeleton only — validate() is a stub returning Ok(()).
//! Phase 2 (P2-07): implement tcb_ge() + full validate() logic.
//! Phase 3: populate Option<> fields for forwardPolicy / MIGRATION_DATA / maReportID.

use tee_attestation_verification_lib::snp::report::{
    AttestationReport, TryFromBytes, TcbVersionMilanGenoa as TcbVersion,
};

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

/// Field-by-field TCB floor check using TcbVersionMilanGenoa's PartialOrd.
/// Confirmed from tav-1.0.2: PartialOrd is implemented comparing boot_loader, tee,
/// snp, microcode — reserved bytes are excluded (correct for semantics).
fn tcb_ge(a: &TcbVersion, b: &TcbVersion) -> bool {
    a >= b  // uses TcbVersionMilanGenoa::partial_cmp (field-by-field, not byte-level)
}

/// Validate an SNP attestation report against the given parameters.
///
/// Checks (all optional — skipped if None):
///   1. report.reported_tcb >= params.min_tcb  (field-by-field via PartialOrd)
///   2. report.guest_svn    >= params.min_guest_svn (u32, report offset 0x004)
///
/// Note: TAV's verify_attestation() has already confirmed:
///   - report.reported_tcb == VCEK OID extensions (verify_tcb_values)
///   - VCEK → ASK → ARK chain is valid
///   - report ECDSA P-384 signature is valid
/// So reported_tcb here is cryptographically trusted.
pub fn validate(params: &AttestationVerificationParams<'_>) -> Result<(), PalError> {
    // Short-circuit: skip parse cost for crypto_only() path (all None)
    if params.min_tcb.is_none() && params.min_guest_svn.is_none() {
        return Ok(());
    }

    let report = AttestationReport::try_read_from_bytes(params.report)
        .map_err(|_| PalError::VerificationFailed("SNP report parse in validate".into()))?;

    // Check 1: platform TCB floor (boot_loader, tee, snp, microcode)
    if let Some(ref min_tcb) = params.min_tcb {
        // reported_tcb is a PUBLIC FIELD of type TcbVersionRaw (not TcbVersionMilanGenoa).
        // Must call .as_milan_genoa() to convert before comparison.
        if !tcb_ge(&report.reported_tcb.as_milan_genoa(), min_tcb) {
            return Err(PalError::VerificationFailed(
                "reported_tcb below minimum_tcb".into(),
            ));
        }
    }

    // Check 2: guest SVN floor (report offset 0x004, le::U32 byteorder field — call .get())
    if let Some(min_svn) = params.min_guest_svn {
        if report.guest_svn.get() < min_svn {
            return Err(PalError::VerificationFailed(
                "guest_svn below min_guest_svn".into(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_no_constraints_passes() {
        // crypto_only() = all None — short-circuits before parse
        let dummy = vec![0u8; 1184];
        let params = AttestationVerificationParams::crypto_only(&dummy, &[0u8; 48]);
        assert!(validate(&params).is_ok());
    }
}
