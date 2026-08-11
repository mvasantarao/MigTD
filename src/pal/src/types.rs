// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformType {
    Tdx,
    AmdSnp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct QvlResult {
    pub platform: PlatformType,
    pub tcb_status: TcbStatus,
    /// Phase 2 (P2-07): platform TCB from VCEK OID extensions (1.3.6.1.4.1.3704.1.x).
    /// Raw 8 bytes matching the TcbVersionMilanGenoa wire layout.
    /// None if cert does not carry AMD OID extensions (test/mock certs).
    pub platform_tcb: Option<[u8; 8]>,
}

/// Bundle returned by AttestationProvider::get_report().
/// Phase 1: only ma_report_blob is populated (tenant_report = None).
/// Phase 3: tenant_report also populated (real tenant CVM SNP report).
#[derive(Debug, Clone)]
pub struct AttestationBundle {
    /// MA's own SNP REPORT (1184 bytes) + cert chain DERs concatenated:
    /// report[1184] || vcek_len[4LE] || vcek || ask_len[4LE] || ask
    pub ma_report_blob: Vec<u8>,
    /// Phase 3: tenant CVM's SNP REPORT fetched via MSG_VERIFY_REPORT.
    pub tenant_report: Option<Vec<u8>>,
}
