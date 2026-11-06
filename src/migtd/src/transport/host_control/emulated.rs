// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Local testing requests use the same SNP handler, without a TDX emulation queue.

use super::HostControlTransport;
use crate::runtime::snp::requests::HostRequest;
use crate::status::MigrationResult;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct EmulatedHostControlTransport {
    requests: Mutex<VecDeque<HostRequest>>,
}

impl EmulatedHostControlTransport {
    pub fn new(request: HostRequest) -> Self {
        Self {
            requests: Mutex::new(VecDeque::from([request])),
        }
    }
}

#[async_trait]
impl HostControlTransport for EmulatedHostControlTransport {
    async fn wait_for_request(&self) -> Result<HostRequest, MigrationResult> {
        self.requests
            .lock()
            .expect("local request queue poisoned")
            .pop_front()
            .ok_or_else(|| {
                eprintln!("[MA] local testing request queue exhausted");
                MigrationResult::NetworkError
            })
    }

    async fn report_status(
        &self,
        status: u8,
        request_id: u64,
        data: &[u8],
    ) -> Result<(), MigrationResult> {
        eprintln!(
            "[MA] LOCAL_REQUEST_STATUS: status={status} request_id={request_id} data_len={}",
            data.len()
        );
        Ok(())
    }
}
