// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Adapter for the Phase 3A synthetic WFR queue and status path.

use crate::migration::data::WaitForRequestResponse;
use crate::migration::host_transport::HostControlTransport;
use crate::migration::session::{report_status, wait_for_request};
use crate::migration::MigrationResult;
use async_trait::async_trait;

pub struct EmulatedHostControlTransport;

#[async_trait]
impl HostControlTransport for EmulatedHostControlTransport {
    async fn wait_for_request(
        &self,
    ) -> core::result::Result<WaitForRequestResponse, MigrationResult> {
        wait_for_request().await
    }

    async fn report_status(
        &self,
        status: u8,
        request_id: u64,
        data: &[u8],
    ) -> core::result::Result<(), MigrationResult> {
        let data = data.to_vec();
        report_status(status, request_id, &data).await
    }
}
