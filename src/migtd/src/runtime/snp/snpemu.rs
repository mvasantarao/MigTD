// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! WFR dispatcher for SNP Migration Agent (ring-3 userspace process in OHCL).
//! All WFR code lives in MigTD repo (not vm_enclave).
//! Generic over HostControlTransport — TCP in Phase 3a, WABO in Phase 3b.
//!
//! Opcode handling per DataStatusOperation enum (A1 — integer wire contract):
//!   EnableLogArea  (4) -> enable_logarea() + set_max_level() + report_status()
//!   GetTDReport    (3) -> SNP_GET_REPORT; return 1184-byte ATTESTATION_REPORT in ACK
//!                         (IGVMAgent MA health check — NOT peer-to-peer SPDM attestation)
//!   StartMigration (1) -> exchange_msk() + report_status(); exit loop
//!
//! GetMigrationReadiness opcode: REMOVED (A6).
//! GetTDReport is required on both SnpEmu and real HW (see ASSUMPTION A5).

use crate::migration::host_transport::HostControlTransport;
use crate::migration::data::WaitForRequestResponse;
use crate::migration::logging::enable_logarea;
use crate::migration::session::{exchange_msk, report_status};
use crate::migration::MigrationResult;
use pal::traits::AttestationProvider;

pub async fn runtime_main_snp<T: HostControlTransport>(transport: &T) -> i32 {
    log::info!("[MA] WFR dispatcher started (Phase 3a SnpEmu)");

    loop {
        let req = match transport.wait_for_request().await {
            Err(e) => {
                log::error!("[MA] wait_for_request failed: {}", e as u8);
                return 1;
            }
            Ok(r) => r,
        };

        match req {
            WaitForRequestResponse::EnableLogArea(info) => {
                log::info!("[MA] opcode 4: EnableLogArea (request_id={})", info.mig_request_id);
                let mut data = Vec::new();
                let status = enable_logarea(info.log_max_level, info.mig_request_id, &mut data)
                    .await
                    .map(|_| MigrationResult::Success)
                    .unwrap_or_else(|e| e);
                log::set_max_level(pal::logging::u8_to_levelfilter(info.log_max_level));
                let _ = report_status(status as u8, info.mig_request_id, &data).await;
            }

            WaitForRequestResponse::GetTdReport(info) => {
                // IGVMAgent MA health check — must return real 1184-byte ATTESTATION_REPORT.
                // SnpEmu path: SnpFixtureProvider returns pre-captured fixture blob.
                // Phase 3b (SnpHardwareProvider): added in 3a-09.
                log::info!("[MA] opcode 3: GetTDReport (request_id={})", info.mig_request_id);
                let report_result = snp_emu::provider_fixture::SnpFixtureProvider
                    .get_report(&info.reportdata);
                let (status, data) = match report_result {
                    Ok(bundle) => (MigrationResult::Success, bundle.ma_report_blob),
                    Err(e) => {
                        log::error!("[MA] GetTDReport: SNP_GET_REPORT failed: {:?}", e);
                        (MigrationResult::MutualAttestationError, Vec::new())
                    }
                };
                let _ = report_status(status as u8, info.mig_request_id, &data).await;
            }

            WaitForRequestResponse::StartMigration(req) => {
                let request_id = req.mig_info.mig_request_id;
                log::info!("[MA] opcode 1: StartMigration -> exchange_msk() (request_id={})", request_id);
                let res = exchange_msk(&req).await;
                let status = res.map(|_| MigrationResult::Success).unwrap_or_else(|e| e);
                let status_code = status as u8;
                let _ = report_status(status_code, request_id, &Vec::new()).await;
                if status_code == MigrationResult::Success as u8 {
                    log::info!("[MA] migration complete (request_id={}) — exiting WFR loop", request_id);
                    return 0;
                } else {
                    log::error!("[MA] migration failed: status={} (request_id={})", status_code, request_id);
                    return status_code as i32;
                }
            }

            _ => {
                log::warn!("[MA] unhandled WFR opcode — ignoring");
            }
        }
    }
}
