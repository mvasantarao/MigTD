// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Hardware-backed MA evidence provider using the /dev/sev-guest ioctl.
//!
//! Issues SNP_GET_REPORT (ioctl 'S'/0x0) to obtain a fresh 1184-byte
//! ATTESTATION_REPORT from the PSP.  vmpl=1 is embedded in the report so
//! verifiers can confirm the MA runs at VMPL1.
//!
//! Compiled through the independent `snp-linux-hardware` capability.
//! Real hardware qualification and production runtime integration remain open.
//!
//! Kernel interface: OHCL-Linux-Kernel include/uapi/linux/sev-guest.h
//!   SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)
//!   snp_guest_request_ioctl { msg_version:u8, req_data:u64, resp_data:u64, exitinfo2:u64 }
//!   snp_report_req  { user_data:[u8;64], vmpl:u32, rsvd:[u8;28] }
//!   snp_report_resp { data:[u8;4000] }  — ATTESTATION_REPORT in data[0..1184]

#![cfg(feature = "snp-linux-hardware")]

use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

use crate::traits::{AttestationProvider, MaEvidenceProvider, PalError, SnpCollateralProvider};
use crate::types::{
    AttestationBundle, MaEvidence, MaEvidenceBinding, MaEvidenceError, MaEvidenceRequest,
    SnpCollateralError, SnpCollateralRequest, SnpVerificationCollateral,
    SNP_ATTESTATION_REPORT_SIZE,
};

// ── Kernel struct layouts (must match sev-guest.h exactly) ──────────────────

const SNP_REPORT_USER_DATA_SIZE: usize = 64;
const SNP_REPORT_RESP_DATA_SIZE: usize = 4000;
/// vmpl level embedded in the report.  MA runs at VMPL1 in OHCL architecture.
const MA_VMPL: u32 = 1;

/// /dev/sev-guest device path.
const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

/// SNP_GUEST_MSG_VERSION_1 — required by kernel; must be non-zero.
const SNP_GUEST_MSG_VERSION_1: u8 = 1;

/// Compute _IOWR(type, nr, size):
///   bits[31:30] = IOC_READ | IOC_WRITE = 3
///   bits[29:16] = size
///   bits[15:8]  = type
///   bits[7:0]   = nr
const fn iowr_const(io_type: u8, nr: u8, size: usize) -> usize {
    (3usize << 30) | (size << 16) | ((io_type as usize) << 8) | (nr as usize)
}

/// snp_guest_request_ioctl layout (32 bytes):
///   offset  0: msg_version u8   + 7 bytes padding
///   offset  8: req_data    u64
///   offset 16: resp_data   u64
///   offset 24: exitinfo2   u64
#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

const _: () = assert!(
    std::mem::size_of::<SnpGuestRequestIoctl>() == 32,
    "SnpGuestRequestIoctl size must be 32 bytes"
);

/// SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)
const SNP_GET_REPORT: usize = iowr_const(b'S', 0x0, std::mem::size_of::<SnpGuestRequestIoctl>());

/// snp_report_req: request payload for SNP_GET_REPORT.
#[repr(C)]
struct SnpReportReq {
    /// 64-byte challenge / nonce to embed in the report.
    user_data: [u8; SNP_REPORT_USER_DATA_SIZE],
    /// VMPL level to embed in the ATTESTATION_REPORT.  Must be >= caller VMPL.
    vmpl: u32,
    /// Must be zero.
    rsvd: [u8; 28],
}

/// snp_report_resp: response buffer for SNP_GET_REPORT.
#[repr(C)]
struct SnpReportResp {
    /// ATTESTATION_REPORT occupies data[0..1184]; remainder is padding.
    data: [u8; SNP_REPORT_RESP_DATA_SIZE],
}

// ── Extern ioctl declaration ─────────────────────────────────────────────────

unsafe extern "C" {
    fn ioctl(fd: i32, request: usize, ...) -> i32;
}

// ── SnpHardwareProvider ──────────────────────────────────────────────────────

/// Phase 3b hardware attestation provider — issues SNP_GET_REPORT on /dev/sev-guest.
///
/// Available through `snp-linux-hardware`, independently of the emulator gate.
/// Requires: running inside an SNP CVM with /dev/sev-guest present.
pub struct SnpHardwareProvider;

impl MaEvidenceProvider for SnpHardwareProvider {
    /// Get a fresh SNP ATTESTATION_REPORT with `report_data` embedded as user_data.
    ///
    /// Steps:
    ///   1. Open /dev/sev-guest
    ///   2. Fill snp_report_req { user_data=report_data, vmpl=1, rsvd=0 }
    ///   3. Issue SNP_GET_REPORT ioctl
    ///   4. Extract snp_report_resp.data[0..1184] as typed MA evidence
    fn acquire_ma_evidence(
        &self,
        request: &MaEvidenceRequest,
    ) -> Result<MaEvidence, MaEvidenceError> {
        // Step 1: Open /dev/sev-guest (requires root or sev-guest group membership)
        let sev_fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(SEV_GUEST_DEVICE)
            .map_err(|e| {
                log::error!(
                    "[MA] SnpHardwareProvider: failed to open {}: {}",
                    SEV_GUEST_DEVICE,
                    e
                );
                MaEvidenceError::ProviderUnavailable
            })?;

        // Step 2: Fill request — user_data = challenge, vmpl = 1, rsvd = 0
        let mut req = SnpReportReq {
            user_data: *request.report_data(),
            vmpl: MA_VMPL,
            rsvd: [0u8; 28],
        };

        // Step 3: Issue ioctl
        let mut resp = SnpReportResp {
            data: [0u8; SNP_REPORT_RESP_DATA_SIZE],
        };
        let mut arg = SnpGuestRequestIoctl {
            msg_version: SNP_GUEST_MSG_VERSION_1,
            _pad: [0u8; 7],
            req_data: (&mut req as *mut SnpReportReq) as u64,
            resp_data: (&mut resp as *mut SnpReportResp) as u64,
            exitinfo2: 0,
        };

        let ret = unsafe { ioctl(sev_fd.as_raw_fd(), SNP_GET_REPORT, &mut arg) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error();
            log::error!(
                "[MA] SnpHardwareProvider: SNP_GET_REPORT ioctl failed: {} (exitinfo2={:#018x})",
                errno,
                arg.exitinfo2
            );
            return Err(MaEvidenceError::DeviceIo);
        }

        // Check firmware error in exitinfo2[31:0]
        let fw_err = (arg.exitinfo2 & 0xFFFF_FFFF) as u32;
        if fw_err != 0 {
            log::error!(
                "[MA] SnpHardwareProvider: PSP firmware error: fw_err={:#010x} exitinfo2={:#018x}",
                fw_err,
                arg.exitinfo2
            );
            return Err(MaEvidenceError::FirmwareRejected { status: fw_err });
        }

        // Step 4: Extract 1184-byte ATTESTATION_REPORT from response
        let mut report = [0u8; SNP_ATTESTATION_REPORT_SIZE];
        report.copy_from_slice(&resp.data[..SNP_ATTESTATION_REPORT_SIZE]);
        log::info!(
            "[MA] SnpHardwareProvider: SNP_GET_REPORT OK — {} bytes, vmpl={}",
            report.len(),
            MA_VMPL
        );

        Ok(MaEvidence::new(
            report,
            MaEvidenceBinding::RequestedReportData,
        ))
    }
}

impl SnpCollateralProvider for SnpHardwareProvider {
    fn acquire_snp_collateral(
        &self,
        _request: &SnpCollateralRequest<'_>,
    ) -> Result<SnpVerificationCollateral, SnpCollateralError> {
        // SNP_GET_REPORT returns only the attestation report. A production
        // certificate-table or platform-service provider is not wired yet.
        // Hardware mode must not fall back to emulator fixture collateral.
        log::error!("selected Linux SNP collateral provider unavailable; no fixture fallback");
        Err(SnpCollateralError::ProviderUnavailable)
    }
}

impl AttestationProvider for SnpHardwareProvider {
    fn get_report(
        &self,
        report_data: &[u8; SNP_REPORT_USER_DATA_SIZE],
    ) -> Result<AttestationBundle, PalError> {
        let evidence = self
            .acquire_ma_evidence(&MaEvidenceRequest::new(*report_data))
            .map_err(|error| match error {
                MaEvidenceError::InvalidReportLength { .. } => PalError::InvalidInput,
                MaEvidenceError::ProviderUnavailable | MaEvidenceError::DeviceIo => {
                    PalError::NotAvailable
                }
                MaEvidenceError::FirmwareRejected { status } => {
                    PalError::VerificationFailed(format!("PSP fw_error={status:#010x}"))
                }
            })?;

        Ok(AttestationBundle {
            ma_report_blob: evidence.into_report().to_vec(),
            tenant_report: None,
        })
    }
}
