// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! HostControlTransport: abstraction over the Host->MA WFR command channel.
//!
//! Phase 3a impl: TcpTransport (TCP loopback, integer opcodes per A1/A2).
//! Phase 3b impl: GhcbVmgexitTransport via WABO (Root Partition/AHOS component).
//! Same integer opcode contract in both phases (A1).
//!
//! Defined in migtd (not pal) to avoid circular dependency:
//!   migtd -> pal; pal must not import migtd types.

use super::data::WaitForRequestResponse;
use super::MigrationResult;
use async_trait::async_trait;

#[async_trait]
pub trait HostControlTransport: Send + Sync {
    /// Block until the host delivers a WFR request (integer opcode + payload, per A1).
    async fn wait_for_request(
        &self,
    ) -> core::result::Result<WaitForRequestResponse, MigrationResult>;

    /// Notify the host of completion status for the given request.
    async fn report_status(
        &self,
        status: u8,
        request_id: u64,
        data: &[u8],
    ) -> core::result::Result<(), MigrationResult>;
}
