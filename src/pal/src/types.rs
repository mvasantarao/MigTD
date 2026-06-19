// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformType { Tdx, AmdSnp }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcbStatus { UpToDate, OutOfDate, Revoked, Unknown }

#[derive(Debug, Clone)]
pub struct QvlResult {
    pub platform: PlatformType,
    pub tcb_status: TcbStatus,
}
