// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SNP attestation report validation parameters.
//!
//! Phase 2: tcb_ge() + expected_report_data binding check implemented.
//! Phase 3: populate Option<> fields for forwardPolicy / MIGRATION_DATA / maReportID.

use crate::traits::PalError;
use crate::types::SnpReportRequestKind;

/// Legacy Milan/Genoa floor for frozen conformance; not a production layout resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcbVersion {
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

/// Parameters governing what validate() checks.
///
/// Phase 2: use crypto_only() constructor — all Option fields are None.
/// Phase 3: populate source_tcb, migration_data, ma_report_id as needed.
pub struct AttestationVerificationParams<'a> {
    /// Raw bytes of the SNP attestation report (1184 bytes).
    pub report: &'a [u8],
    /// Expected SHA384 context digest; the remaining 16 REPORT_DATA bytes must be zero.
    pub expected_report_data: &'a [u8; 48],
    /// Live guest/host semantics are separate from captured legacy-fixture compatibility.
    pub report_request: SnpReportRequestKind,
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
    /// Compatibility constructor for captured legacy fixtures. Live Version 1
    /// evidence must use `for_request` with its guest- or host-request classification.
    pub fn crypto_only(report: &'a [u8], expected_report_data: &'a [u8; 48]) -> Self {
        Self::for_request(
            report,
            expected_report_data,
            SnpReportRequestKind::LegacyCapturedFixture,
        )
    }

    pub fn for_request(
        report: &'a [u8],
        expected_report_data: &'a [u8; 48],
        report_request: SnpReportRequestKind,
    ) -> Self {
        Self {
            report,
            expected_report_data,
            report_request,
            min_tcb: None,
            min_guest_svn: None,
            source_tcb: None,
            source_guest_svn: None,
            migration_data: None,
            ma_report_id: None,
        }
    }
}

/// Reserved bytes are not SVN operands.
fn tcb_ge(a: &TcbVersion, b: &TcbVersion) -> bool {
    a.boot_loader >= b.boot_loader && a.tee >= b.tee && a.snp >= b.snp && a.microcode >= b.microcode
}

/// Validate an SNP attestation report against the given parameters.
///
/// Checks performed (in order):
///   0. report_data binding — MANDATORY: expected SHA384 digest followed by 16 zero bytes
///   1. report.reported_tcb >= params.min_tcb (componentwise) — if Some
///   2. report.guest_svn    >= params.min_guest_svn (u32, report offset 0x004) — if Some
///
/// This checks fields only. Authentication belongs to the selected verifier.
pub fn validate(params: &AttestationVerificationParams<'_>) -> Result<(), PalError> {
    let report: &[u8; 1184] = params
        .report
        .try_into()
        .map_err(|_| PalError::VerificationFailed("SNP report parse in validate".into()))?;
    let version = u32::from_le_bytes(report[0..4].try_into().unwrap());
    let vmpl = u32::from_le_bytes(report[0x30..0x34].try_into().unwrap());
    let report_data = &report[0x50..0x90];

    if params.report_request != SnpReportRequestKind::LegacyCapturedFixture && version != 6 {
        return Err(PalError::VerificationFailed(
            "Version 1 MA/tenant evidence requires report Version 6".into(),
        ));
    }

    match params.report_request {
        SnpReportRequestKind::GuestRequestedMa { expected_vmpl } => {
            if expected_vmpl > 3 || vmpl != expected_vmpl {
                return Err(PalError::VerificationFailed(
                    "MA report VMPL mismatch".into(),
                ));
            }
        }
        SnpReportRequestKind::HostRequestedTenant => {
            if vmpl != u32::MAX || params.expected_report_data != &[0; 48] || report_data != [0; 64]
            {
                return Err(PalError::VerificationFailed(
                    "host-requested tenant report requires VMPL 0xffffffff and zero REPORT_DATA"
                        .into(),
                ));
            }
        }
        SnpReportRequestKind::LegacyCapturedFixture => {}
    }

    if report_data[..48] != *params.expected_report_data {
        return Err(PalError::VerificationFailed(
            "report_data binding mismatch: expected SHA384 context digest does not match".into(),
        ));
    }
    if report_data[48..].iter().any(|&byte| byte != 0) {
        return Err(PalError::VerificationFailed(
            "report_data binding mismatch: nonzero padding in bytes 48..64".into(),
        ));
    }

    // Check 1: platform TCB floor (boot_loader, tee, snp, microcode)
    if let Some(ref min_tcb) = params.min_tcb {
        let reported = TcbVersion {
            boot_loader: report[0x180],
            tee: report[0x181],
            snp: report[0x186],
            microcode: report[0x187],
        };
        if !tcb_ge(&reported, min_tcb) {
            return Err(PalError::VerificationFailed(
                "reported_tcb below minimum_tcb".into(),
            ));
        }
    }

    // Check 2: guest SVN floor.
    if let Some(min_svn) = params.min_guest_svn {
        if u32::from_le_bytes(report[4..8].try_into().unwrap()) < min_svn {
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
    fn legacy_tcb_floor_checks_every_component_and_ignores_reserved_bytes() {
        let mut report = [0u8; 1184];
        let offsets = [0x180, 0x181, 0x186, 0x187];
        for offset in offsets {
            report[offset] = 7;
        }
        let check = |report: &[u8]| {
            let mut params = AttestationVerificationParams::crypto_only(report, &[0; 48]);
            params.min_tcb = Some(TcbVersion {
                boot_loader: 7,
                tee: 7,
                snp: 7,
                microcode: 7,
            });
            validate(&params)
        };
        assert!(check(&report).is_ok());
        for offset in offsets {
            report[offset] = 6;
            assert!(check(&report).is_err(), "TCB component at {offset:#x}");
            report[offset] = 8;
            assert!(check(&report).is_ok());
        }
        report[0x182..0x186].fill(0xff);
        assert!(check(&report).is_ok());
    }

    #[test]
    fn legacy_guest_svn_floor_is_little_endian_and_requires_an_exact_report() {
        let mut report = [0u8; 1184];
        report[4..8].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        let mut params = AttestationVerificationParams::crypto_only(&report, &[0; 48]);
        params.min_guest_svn = Some(0x0102_0304);
        assert!(validate(&params).is_ok());
        params.min_guest_svn = Some(0x0102_0305);
        assert!(validate(&params).is_err());
        assert!(validate(&AttestationVerificationParams::crypto_only(
            &report[..1183],
            &[0; 48],
        ))
        .is_err());
        assert!(validate(&AttestationVerificationParams::crypto_only(
            &[0; 1185], &[0; 48],
        ))
        .is_err());
    }

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

    #[test]
    fn validate_report_data_digest_with_zero_padding_passes() {
        let mut report = [0u8; 1184];
        let expected = [0xA5; 48];
        report[0x50..0x80].copy_from_slice(&expected);
        let params = AttestationVerificationParams::crypto_only(&report, &expected);
        assert!(validate(&params).is_ok());
    }

    #[test]
    fn validate_report_data_rejects_each_nonzero_padding_byte() {
        let expected = [0xA5; 48];
        for padding_index in 48..64 {
            let mut report = [0u8; 1184];
            report[0x50..0x80].copy_from_slice(&expected);
            report[0x50 + padding_index] = 1;
            let params = AttestationVerificationParams::crypto_only(&report, &expected);
            assert!(
                matches!(validate(&params), Err(PalError::VerificationFailed(_))),
                "nonzero REPORT_DATA byte {padding_index} must be rejected"
            );
        }
    }

    #[test]
    fn host_requested_tenant_requires_host_vmpl_and_all_64_zero_report_data_bytes() {
        let mut report = [0u8; 1184];
        report[..4].copy_from_slice(&6u32.to_le_bytes());
        report[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
        let check = |report: &[u8], expected: &[u8; 48]| {
            validate(&AttestationVerificationParams::for_request(
                report,
                expected,
                SnpReportRequestKind::HostRequestedTenant,
            ))
        };
        assert!(check(&report, &[0; 48]).is_ok());
        assert!(check(&report, &[1; 48]).is_err());
        for offset in 0x50..0x90 {
            let mut changed = report;
            changed[offset] = 1;
            assert!(check(&changed, &[0; 48]).is_err(), "byte {offset}");
        }
        for vmpl in [0u32, 1, 2, 3, 4, u32::MAX - 1] {
            let mut changed = report;
            changed[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes());
            assert!(check(&changed, &[0; 48]).is_err());
        }
    }

    #[test]
    fn live_report_kinds_do_not_accept_legacy_report_versions() {
        for report_request in [
            SnpReportRequestKind::GuestRequestedMa { expected_vmpl: 0 },
            SnpReportRequestKind::HostRequestedTenant,
        ] {
            for version in [0u32, 1, 2, 3, 4, 5, 7, u32::MAX] {
                let mut report = [0u8; 1184];
                report[..4].copy_from_slice(&version.to_le_bytes());
                if report_request == SnpReportRequestKind::HostRequestedTenant {
                    report[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
                }
                assert!(validate(&AttestationVerificationParams::for_request(
                    &report,
                    &[0; 48],
                    report_request,
                ))
                .is_err());
            }
        }
    }

    #[test]
    fn guest_requested_ma_requires_the_selected_guest_vmpl() {
        for vmpl in 0u32..4 {
            let mut report = [0u8; 1184];
            report[..4].copy_from_slice(&6u32.to_le_bytes());
            report[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes());
            report[0x50..0x80].fill(0xA5);
            for expected_vmpl in [0, 1, 2, 3, 4, u32::MAX] {
                let params = AttestationVerificationParams::for_request(
                    &report,
                    &[0xA5; 48],
                    SnpReportRequestKind::GuestRequestedMa { expected_vmpl },
                );
                assert_eq!(validate(&params).is_ok(), vmpl == expected_vmpl);
            }
        }
    }
}
