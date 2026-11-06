// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! WFR dispatcher for SNP Migration Agent (ring-3 userspace process in OHCL).
//! All WFR code lives in MigTD repo (not snp-ma-vm-harness).
//! Generic over HostControlTransport — TCP in Phase 3a, WABO in Phase 3b.
//!
//! Opcode handling per DataStatusOperation enum (A1 — integer wire contract):
//!   EnableLogArea  (4) -> enable_logarea() + set_max_level() + report_status()
//!   GetTDReport    (3) -> selected MA evidence plus legacy certificate-blob ACK
//!                         (IGVMAgent MA health check — NOT peer-to-peer SPDM attestation)
//!   StartMigration (1) -> SNP legacy workflow + report_status(); exit loop
//!
//! GetMigrationReadiness opcode: REMOVED (A6).
//! GetTDReport is required on both SnpEmu and real HW (see ASSUMPTION A5).

use super::legacy::exchange_legacy;
use super::requests::{
    HostRequest as WaitForRequestResponse, LegacyOperation as MigrationInformation,
};
use crate::snp_composition::SnpRuntimeProviders;
use crate::status::MigrationResult;
use crate::transport::{host_control::HostControlTransport, peer::TcpPeerStream};
use pal::types::MigrationRole;

fn configure_log_level(log_max_level: u8) -> MigrationResult {
    if log_max_level > 5 {
        return MigrationResult::InvalidParameter;
    }

    log::set_max_level(pal::logging::u8_to_levelfilter(log_max_level));
    MigrationResult::Success
}

pub async fn execute_start_migration<T: HostControlTransport>(
    transport: &T,
    request: &MigrationInformation,
    providers: &SnpRuntimeProviders,
    peer: &TcpPeerStream,
    role: MigrationRole,
) -> i32 {
    let request_id = request.mig_request_id;
    eprintln!(
        "[MA] START_MIGRATION_WORKFLOW_BEGIN: role={} request_id={}",
        if request.is_src() {
            "source"
        } else {
            "destination"
        },
        request_id
    );

    let result = if request.operation.role != role {
        eprintln!("[MA] host request role does not match the configured SNP peer role");
        Err(MigrationResult::InvalidParameter)
    } else {
        exchange_legacy(request, providers, peer).await
    };
    complete_start_migration(transport, request_id, result).await
}

async fn complete_start_migration<T: HostControlTransport>(
    transport: &T,
    request_id: u64,
    result: Result<(), MigrationResult>,
) -> i32 {
    let status = result
        .map(|_| MigrationResult::Success)
        .unwrap_or_else(|error| error);
    let status_code = status as u8;

    if let Err(error) = transport.report_status(status_code, request_id, &[]).await {
        eprintln!(
            "[MA] ERROR: StartMigration report_status failed: status={} request_id={}",
            error as u8, request_id
        );
        return error as u8 as i32;
    }

    if status == MigrationResult::Success {
        eprintln!(
            "[MA] START_MIGRATION_WORKFLOW_END: result=success request_id={}",
            request_id
        );
        0
    } else {
        eprintln!(
            "[MA] START_MIGRATION_WORKFLOW_END: result=failure status={} request_id={}",
            status_code, request_id
        );
        status_code as i32
    }
}

pub async fn runtime_main_snp<T: HostControlTransport>(
    transport: &T,
    providers: &SnpRuntimeProviders,
    peer: &TcpPeerStream,
    role: MigrationRole,
) -> i32 {
    eprintln!("[MA] WFR dispatcher started (Phase 3a SnpEmu)");

    loop {
        let req = match transport.wait_for_request().await {
            Err(e) => {
                eprintln!(
                    "[MA] FATAL: wait_for_request failed: opcode_err={}",
                    e as u8
                );
                return e as u8 as i32;
            }
            Ok(r) => r,
        };

        match req {
            WaitForRequestResponse::EnableLogArea(info) => {
                eprintln!(
                    "[MA] opcode 4: EnableLogArea (request_id={})",
                    info.mig_request_id
                );
                // Phase 3a uses serial logging and has no VMM-readable shared log area.
                // Validate and apply the requested level; Phase 3b will return WABO/GHCB
                // log-area metadata through the same report_status response.
                let status = configure_log_level(info.log_max_level);
                if status == MigrationResult::Success {
                    eprintln!(
                        "[MA] EnableLogArea: level {} accepted (serial logging)",
                        info.log_max_level
                    );
                } else {
                    eprintln!("[MA] EnableLogArea: invalid level {}", info.log_max_level);
                }
                if let Err(e) = transport
                    .report_status(status as u8, info.mig_request_id, &[])
                    .await
                {
                    eprintln!(
                        "[MA] FATAL: EnableLogArea report_status failed: {}",
                        e as u8
                    );
                    return 1;
                }
            }

            WaitForRequestResponse::GetTdReport(info) => {
                // Legacy health-check blob, not live peer or tenant attestation.
                eprintln!(
                    "[MA] opcode 3: GetTDReport (request_id={})",
                    info.mig_request_id
                );
                let report_result = providers.legacy_report_blob(&info.reportdata);
                let (status, data) = match report_result {
                    Ok(blob) => (MigrationResult::Success, blob),
                    Err(e) => {
                        eprintln!("[MA] ERROR: GetTDReport: SNP_GET_REPORT failed: {:?}", e);
                        (MigrationResult::MutualAttestationError, Vec::new())
                    }
                };
                if let Err(error) = transport
                    .report_status(status as u8, info.mig_request_id, &data)
                    .await
                {
                    eprintln!(
                        "[MA] FATAL: GetTDReport report_status failed: {}",
                        error as u8
                    );
                    return error as u8 as i32;
                }
            }

            WaitForRequestResponse::StartMigration(req) => {
                let request_id = req.mig_request_id;
                eprintln!(
                    "[MA] opcode 1: StartMigration -> SNP legacy workflow (request_id={})",
                    request_id
                );
                return execute_start_migration(transport, &req, providers, peer, role).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::snp::requests::{
        HealthRequest as ReportInfo, LogRequest as EnableLogAreaInfo,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    // ── MockTransport ────────────────────────────────────────────────────────
    // Records every report_status call so tests can assert on status codes.

    #[derive(Default, Clone)]
    struct MockTransport {
        /// Canned responses returned in order by wait_for_request().
        responses: Arc<Mutex<Vec<WaitForRequestResponse>>>,
        /// Captured (status, request_id, data_len) from report_status calls.
        calls: Arc<Mutex<Vec<(u8, u64, usize)>>>,
        report_error: Option<MigrationResult>,
    }

    impl MockTransport {
        fn new(responses: Vec<WaitForRequestResponse>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses)),
                calls: Arc::new(Mutex::new(Vec::new())),
                report_error: None,
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
            self.calls
                .lock()
                .unwrap()
                .push((status, request_id, data.len()));
            self.report_error.map_or(Ok(()), Err)
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    async fn run(transport: &MockTransport, providers: &SnpRuntimeProviders) -> i32 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let _server = listener.accept().await.unwrap();
        let peer = TcpPeerStream::new(stream);
        super::runtime_main_snp(transport, providers, &peer, MigrationRole::Source).await
    }

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
        let providers = crate::snp_composition::selected_runtime_provider_set();
        let _ = run(&transport, &providers).await;
        let calls = transport.captured_calls();
        // EnableLogArea arm must have fired report_status
        assert!(
            !calls.is_empty(),
            "report_status not called for EnableLogArea"
        );
        let (status, req_id, _data_len) = calls[0];
        assert_eq!(req_id, 1001, "wrong request_id");
        assert_eq!(
            MigrationResult::try_from(status).unwrap(),
            MigrationResult::Success,
            "valid Phase 3a log level must be accepted"
        );
    }

    #[tokio::test]
    async fn test_report_status_enable_logarea_rejects_invalid_level() {
        let transport = MockTransport::new(vec![enable_logarea_req(1001, 6)]);
        let providers = crate::snp_composition::selected_runtime_provider_set();
        let _ = run(&transport, &providers).await;
        let calls = transport.captured_calls();
        assert!(
            !calls.is_empty(),
            "report_status not called for EnableLogArea"
        );
        let (status, req_id, data_len) = calls[0];
        assert_eq!(req_id, 1001, "wrong request_id");
        assert_eq!(
            data_len, 0,
            "Phase 3a does not return shared log-area metadata"
        );
        assert_eq!(
            MigrationResult::try_from(status).unwrap(),
            MigrationResult::InvalidParameter,
            "invalid Phase 3a log level must be rejected"
        );
    }

    /// GetTDReport: dispatcher must call report_status with a non-empty data payload
    /// (the ATTESTATION_REPORT blob from SnpFixtureProvider).
    #[tokio::test]
    async fn test_report_status_get_tdreport_returns_report_blob() {
        let transport = MockTransport::new(vec![get_tdreport_req(1002)]);
        let providers = crate::snp_composition::selected_runtime_provider_set();
        let _ = run(&transport, &providers).await;
        let calls = transport.captured_calls();
        assert!(
            !calls.is_empty(),
            "report_status not called for GetTDReport"
        );
        let (status, req_id, data_len) = calls[0];
        assert_eq!(req_id, 1002, "wrong request_id");
        assert_eq!(
            MigrationResult::try_from(status).unwrap(),
            MigrationResult::Success,
            "GetTDReport fixture path must return Success"
        );
        assert_eq!(
            data_len,
            1184 + 8
                + snp_emu::report_emu::fixture_vcek_der().len()
                + snp_emu::report_emu::fixture_ask_der().len(),
            "GetTDReport must retain the exact legacy report/certificate blob"
        );
    }

    #[tokio::test]
    async fn get_tdreport_report_failure_is_terminal_and_retains_transport_status() {
        let transport = MockTransport {
            report_error: Some(MigrationResult::NetworkError),
            ..MockTransport::new(vec![get_tdreport_req(1002), enable_logarea_req(1003, 3)])
        };
        let providers = crate::snp_composition::selected_runtime_provider_set();
        let exit = run(&transport, &providers).await;
        assert_eq!(exit, MigrationResult::NetworkError as u8 as i32);
        let calls = transport.captured_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, MigrationResult::Success as u8);
        assert_eq!(calls[0].1, 1002);
        assert_eq!(
            calls[0].2,
            providers.legacy_report_blob(&[0; 64]).unwrap().len()
        );
        assert_eq!(transport.responses.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_shared_start_migration_success_reports_success() {
        let transport = MockTransport::default();
        let exit_code = super::complete_start_migration(&transport, 2001, Ok(())).await;
        assert_eq!(exit_code, 0);
        assert_eq!(
            transport.captured_calls(),
            vec![(MigrationResult::Success as u8, 2001, 0)]
        );
    }

    #[tokio::test]
    async fn test_shared_start_migration_failure_reports_same_status() {
        let transport = MockTransport::default();
        let exit_code = super::complete_start_migration(
            &transport,
            2002,
            Err(MigrationResult::MutualAttestationError),
        )
        .await;
        assert_eq!(
            exit_code,
            MigrationResult::MutualAttestationError as u8 as i32
        );
        assert_eq!(
            transport.captured_calls(),
            vec![(MigrationResult::MutualAttestationError as u8, 2002, 0)]
        );
    }

    #[tokio::test]
    async fn mismatched_role_fails_before_peer_exchange() {
        let request = MigrationInformation::new(2003, MigrationRole::Destination, 9);
        let transport = MockTransport::new(vec![WaitForRequestResponse::StartMigration(request)]);
        let providers = crate::snp_composition::selected_runtime_provider_set();
        assert_eq!(
            run(&transport, &providers).await,
            MigrationResult::InvalidParameter as u8 as i32
        );
        assert_eq!(
            transport.captured_calls(),
            vec![(MigrationResult::InvalidParameter as u8, 2003, 0)]
        );
    }

    #[tokio::test]
    async fn start_migration_report_failure_is_terminal() {
        let transport = MockTransport {
            report_error: Some(MigrationResult::NetworkError),
            ..MockTransport::default()
        };
        assert_eq!(
            super::complete_start_migration(&transport, 2004, Ok(())).await,
            MigrationResult::NetworkError as u8 as i32
        );
        assert_eq!(transport.captured_calls().len(), 1);
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
                "error code {} should be accepted by MigrationResult::try_from",
                code
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
                "unknown code {} should be rejected by MigrationResult::try_from",
                code
            );
        }
    }
}
