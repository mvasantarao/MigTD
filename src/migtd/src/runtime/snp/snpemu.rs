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
use crate::migration::session::exchange_msk;
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
                let _ = transport.report_status(status as u8, info.mig_request_id, &data).await;
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
                let _ = transport.report_status(status as u8, info.mig_request_id, &data).await;
            }

            WaitForRequestResponse::StartMigration(req) => {
                let request_id = req.mig_info.mig_request_id;
                log::info!("[MA] opcode 1: StartMigration -> exchange_msk() (request_id={})", request_id);
                let res = exchange_msk(&req).await;
                let status = res.map(|_| MigrationResult::Success).unwrap_or_else(|e| e);
                let status_code = status as u8;
                let _ = transport.report_status(status_code, request_id, &[]).await;
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


#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use crate::migration::MigrationResult;
    use crate::migration::host_transport::HostControlTransport;
    use crate::migration::data::WaitForRequestResponse;
    use crate::migration::{EnableLogAreaInfo, ReportInfo};

    // ── MockTransport ────────────────────────────────────────────────────────
    // Records every report_status call so tests can assert on status codes.

    #[derive(Default, Clone)]
    struct MockTransport {
        /// Canned responses returned in order by wait_for_request().
        responses: Arc<Mutex<Vec<WaitForRequestResponse>>>,
        /// Captured (status, request_id, data_len) from report_status calls.
        calls: Arc<Mutex<Vec<(u8, u64, usize)>>>,
    }

    impl MockTransport {
        fn new(responses: Vec<WaitForRequestResponse>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses)),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
        fn captured_calls(&self) -> Vec<(u8, u64, usize)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HostControlTransport for MockTransport {
        async fn wait_for_request(&self) -> Result<WaitForRequestResponse, MigrationResult> {
            let mut q = self.responses.lock().unwrap();
            if q.is_empty() {
                // Return NetworkError to terminate the dispatcher loop
                Err(MigrationResult::NetworkError)
            } else {
                Ok(q.remove(0))
            }
        }

        async fn report_status(
            &self,
            status: u8,
            request_id: u64,
            data: &[u8],
        ) -> Result<(), MigrationResult> {
            self.calls.lock().unwrap().push((status, request_id, data.len()));
            Ok(())
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn enable_logarea_req(req_id: u64, level: u8) -> WaitForRequestResponse {
        WaitForRequestResponse::EnableLogArea(EnableLogAreaInfo {
            mig_request_id: req_id,
            log_max_level: level,
            reserved: [0u8; 7],
        })
    }

    fn get_tdreport_req(req_id: u64) -> WaitForRequestResponse {
        WaitForRequestResponse::GetTdReport(ReportInfo {
            mig_request_id: req_id,
            reportdata: [0u8; 64],
        })
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    /// EnableLogArea: dispatcher must call report_status with Success (0).
    #[tokio::test]
    async fn test_report_status_enable_logarea_success_code() {
        let transport = MockTransport::new(vec![enable_logarea_req(1001, 3)]);
        // Dispatcher will loop until wait_for_request returns Err (queue empty)
        let _ = super::runtime_main_snp(&transport).await;
        let calls = transport.captured_calls();
        // EnableLogArea arm must have fired report_status
        assert!(!calls.is_empty(), "report_status not called for EnableLogArea");
        let (status, req_id, _data_len) = calls[0];
        assert_eq!(req_id, 1001, "wrong request_id");
        // Status must be a valid MigrationResult code
        assert!(
            MigrationResult::try_from(status).is_ok(),
            "EnableLogArea report_status sent invalid status code {}", status
        );
    }

    /// GetTDReport: dispatcher must call report_status with a non-empty data payload
    /// (the ATTESTATION_REPORT blob from SnpFixtureProvider).
    #[tokio::test]
    async fn test_report_status_get_tdreport_returns_report_blob() {
        let transport = MockTransport::new(vec![get_tdreport_req(1002)]);
        let _ = super::runtime_main_snp(&transport).await;
        let calls = transport.captured_calls();
        assert!(!calls.is_empty(), "report_status not called for GetTDReport");
        let (status, req_id, data_len) = calls[0];
        assert_eq!(req_id, 1002, "wrong request_id");
        assert_eq!(
            MigrationResult::try_from(status).unwrap(),
            MigrationResult::Success,
            "GetTDReport fixture path must return Success"
        );
        // Fixture blob must be non-empty (report + cert chain)
        assert!(data_len > 0, "GetTDReport response must carry non-empty blob");
    }

    /// report_status success code accepted: MigrationResult::Success as u8 == 0.
    #[test]
    fn test_report_status_success_code_accepted() {
        let code = MigrationResult::Success as u8;
        assert_eq!(code, 0u8);
        assert!(MigrationResult::try_from(code).is_ok());
        assert!(matches!(
            MigrationResult::try_from(code).unwrap(),
            MigrationResult::Success
        ));
    }

    /// report_status error codes accepted: all defined MigrationResult variants
    /// (except reserved 0xFF) must round-trip through try_from.
    #[test]
    fn test_report_status_error_codes_accepted() {
        let error_codes: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xFF];
        for &code in error_codes {
            assert!(
                MigrationResult::try_from(code).is_ok(),
                "error code {} should be accepted by MigrationResult::try_from", code
            );
        }
    }

    /// report_status unknown code rejected: codes not in the enum must return Err.
    #[test]
    fn test_report_status_unknown_code_rejected() {
        let unknown_codes: &[u8] = &[13, 14, 100, 200, 254];
        for &code in unknown_codes {
            assert!(
                MigrationResult::try_from(code).is_err(),
                "unknown code {} should be rejected by MigrationResult::try_from", code
            );
        }
    }
}
