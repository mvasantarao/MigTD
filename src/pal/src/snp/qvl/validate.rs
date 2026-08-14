// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SNP attestation report validation parameters.
//!
//! Phase 2: tcb_ge() + expected_report_data binding check implemented.
//! Phase 3: populate Option<> fields for forwardPolicy / MIGRATION_DATA / maReportID.

use tee_attestation_verification_lib::snp::report::{
    AttestationReport, TcbVersionMilanGenoa as TcbVersion, TryFromBytes,
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
    a >= b // uses TcbVersionMilanGenoa::partial_cmp (field-by-field, not byte-level)
}

/// Validate an SNP attestation report against the given parameters.
///
/// Checks performed (in order):
///   0. report_data binding — MANDATORY: report.report_data[0..48] == SHA384(prefix || TH1)
///   1. report.reported_tcb >= params.min_tcb  (field-by-field via PartialOrd) — if Some
///   2. report.guest_svn    >= params.min_guest_svn (u32, report offset 0x004) — if Some
///
/// Note: TAV's verify_attestation() has already confirmed:
///   - report.reported_tcb == VCEK OID extensions (verify_tcb_values)
///   - VCEK → ASK → ARK chain is valid
///   - report ECDSA P-384 signature is valid
/// So reported_tcb here is cryptographically trusted.
pub fn validate(params: &AttestationVerificationParams<'_>) -> Result<(), PalError> {
    let report = AttestationReport::try_read_from_bytes(params.report)
        .map_err(|_| PalError::VerificationFailed("SNP report parse in validate".into()))?;

    // Check 0: report_data binding — MANDATORY.
    // report.report_data is [u8; 64] at raw offset 0x050; expected is SHA384(prefix||TH1) = 48 bytes.
    // Bytes [48..64] are zero padding and are not compared.
    if report.report_data[..48] != *params.expected_report_data {
        return Err(PalError::VerificationFailed(
            "report_data binding mismatch: SHA384(prefix || TH1) does not match".into(),
        ));
    }

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
    fn validate_zeroed_report_matches_zeroed_expected() {
        // All-zero 1184-byte report: report_data[0..48] = [0;48] matches expected [0;48].
        let dummy = vec![0u8; 1184];
        let params = AttestationVerificationParams::crypto_only(&dummy, &[0u8; 48]);
        assert!(validate(&params).is_ok());
    }

    #[test]
    fn validate_report_data_mismatch_fails() {
        // All-zero report: report_data[0..48] = [0;48]. Expected = [1;48] -> mismatch.
        let dummy = vec![0u8; 1184];
        let expected = [1u8; 48];
        let params = AttestationVerificationParams::crypto_only(&dummy, &expected);
        assert!(validate(&params).is_err());
    }
}
