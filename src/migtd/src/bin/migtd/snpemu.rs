// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Unified SNP Migration Agent entry point for standalone and PID1 execution.

#![cfg(feature = "SnpEmu")]

use std::net::SocketAddr;
use std::process;

use alloc::vec::Vec;
use migtd::driver::vmcall_raw::panic_with_guest_crash_reg_report;
use migtd::migration::event;
use migtd::migration::logging::{
    create_logarea, enable_logarea, init_vmm_logger, u8_to_levelfilter,
};
use migtd::migration::session::report_status;
use migtd::migration::MigrationResult;
use migtd::runtime::snp::config::{
    usage, HostControlMode, MigrationRole, ParseOutcome, PeerTransportMode, ProcessMode,
    RuntimeConfig, StartMode,
};
use migtd::runtime::snp::snpemu::execute_start_migration;
use migtd::transport::host_control::emulated::EmulatedHostControlTransport;
use tdx_tdcall_emu::tdx_emu::{connect_tcp_client, set_emulated_start_migration};
use tdx_tdcall_emu::{init_tcp_emulation_with_mode, start_tcp_server_sync, TcpEmulationMode};

pub fn main() {
    let config = match RuntimeConfig::parse(std::env::args()) {
        Ok(ParseOutcome::Run(config)) => config,
        Ok(ParseOutcome::Help) => {
            println!("{}", usage());
            return;
        }
        Err(error) => {
            eprintln!("[MA] invalid runtime configuration: {error}");
            eprintln!("{}", usage());
            process::exit(2);
        }
    };

    if let Err(error) = prepare_process(&config) {
        eprintln!("[MA] FATAL: {error}");
        process::exit(2);
    }

    eprintln!(
        "[MA] RUNTIME_PROFILE: process={} start={} role={} host_control={} \
         peer_transport={} platform_services={}",
        config.process_mode,
        config.start_mode,
        config.role,
        config.host_control,
        config.peer_transport,
        config.platform_services
    );

    if let Err(error) = initialize_peer_channel(config.role, &config.peer_address) {
        eprintln!("[MA] FATAL: {error}");
        process::exit(1);
    }

    let exit_code = match config.start_mode {
        StartMode::Autostart => {
            queue_autostart_request(&config);
            runtime_main_autostart()
        }
        StartMode::Wfr => {
            if config.process_mode == ProcessMode::Pid1 {
                eprintln!("[MA] MA_BOOT_STAGE_2: entering WFR service loop");
            }
            runtime_main_wfr(&config)
        }
    };
    process::exit(exit_code);
}

fn prepare_process(config: &RuntimeConfig) -> Result<(), String> {
    if config.platform_services == migtd::runtime::snp::config::PlatformServicesMode::Hardware {
        return Err(
            "hardware platform services are not implemented; refusing fixture fallback".to_string(),
        );
    }
    if config.peer_transport == PeerTransportMode::Underhill {
        return Err(
            "the Underhill peer backend is not implemented; refusing TCP fallback".to_string(),
        );
    }

    match config.process_mode {
        ProcessMode::Standalone => {
            let result = init_vmm_logger();
            if result.is_err() {
                panic_with_guest_crash_reg_report(
                    MigrationResult::InitializationError as u64,
                    b"Failed to initialize VMM logger",
                );
            }

            #[cfg(not(any(
                feature = "test_disable_ra_and_accept_all",
                feature = "SnpUnderhill"
            )))]
            attestation::attest_init_heap();

            td_shim_emu::event_log::init_event_log();
            Ok(())
        }
        ProcessMode::Pid1 => {
            #[cfg(feature = "SnpUnderhill")]
            {
                super::main_snp_underhill::prepare_pid1(config.role);
                Ok(())
            }
            #[cfg(not(feature = "SnpUnderhill"))]
            {
                Err(
                    "PID1 process mode requires a binary built with the SnpUnderhill feature"
                        .to_string(),
                )
            }
        }
    }
}

fn initialize_peer_channel(role: MigrationRole, peer_address: &str) -> Result<(), String> {
    let socket_address: SocketAddr = peer_address
        .parse()
        .map_err(|error| format!("invalid peer address {peer_address}: {error}"))?;
    let mode = if role.is_source() {
        TcpEmulationMode::Client
    } else {
        TcpEmulationMode::Server
    };

    eprintln!(
        "[MA] PEER_CHANNEL_SETUP: role={} address={}",
        role, peer_address
    );
    init_tcp_emulation_with_mode(
        &socket_address.ip().to_string(),
        socket_address.port(),
        mode,
    )
    .map_err(|error| format!("peer TCP emulation initialization failed: {error}"))?;

    if role.is_source() {
        connect_tcp_client().map_err(|error| format!("peer TCP connect failed: {error:?}"))?;
    } else {
        eprintln!("[MA] PEER_CHANNEL_LISTENING: {}", peer_address);
        start_tcp_server_sync(peer_address)
            .map_err(|error| format!("peer TCP accept failed: {error:?}"))?;
    }

    eprintln!(
        "[MA] PEER_CHANNEL_READY: role={} address={}",
        role, peer_address
    );
    Ok(())
}

fn queue_autostart_request(config: &RuntimeConfig) {
    let target_uuid = [
        config.target_uuid[0] as u64,
        config.target_uuid[1] as u64,
        config.target_uuid[2] as u64,
        config.target_uuid[3] as u64,
    ];
    let migration_source = u8::from(config.role.is_source());

    eprintln!(
        "[MA] AUTOSTART_REQUEST_CREATED: request_id={} role={}",
        config.request_id, config.role
    );
    set_emulated_start_migration(
        config.request_id,
        migration_source,
        target_uuid,
        config.binding_handle,
    );
}

fn runtime_main_autostart() -> i32 {
    match create_logarea() {
        Ok(_) => log::info!("LogArea created successfully\n"),
        Err(error) => log::error!("Failed to create logarea: {}\n", error as u8),
    }

    event::register_callback();

    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    runtime.block_on(async move {
        loop {
            match migtd::migration::session::wait_for_request().await {
                Ok(response) => {
                    use migtd::migration::data::WaitForRequestResponse;
                    match response {
                        WaitForRequestResponse::EnableLogArea(wfr_info) => {
                            log::info!(migration_request_id = wfr_info.mig_request_id; "Processing EnableLogArea request\n");
                            let mut data = Vec::new();
                            let status = enable_logarea(
                                wfr_info.log_max_level,
                                wfr_info.mig_request_id,
                                &mut data,
                            )
                            .await
                            .map(|_| MigrationResult::Success)
                            .unwrap_or_else(|error| error);

                            log::set_max_level(u8_to_levelfilter(wfr_info.log_max_level));
                            let _ =
                                report_status(status as u8, wfr_info.mig_request_id, &data).await;
                        }
                        WaitForRequestResponse::GetTdReport(report_info) => {
                            log::info!(migration_request_id = report_info.mig_request_id; "SnpEmu: GetTdReport is a no-op (SNP report generated in SPDM layer)\n");
                            let _ = report_status(
                                MigrationResult::Success as u8,
                                report_info.mig_request_id,
                                &Vec::new(),
                            )
                            .await;
                        }
                        WaitForRequestResponse::StartMigration(request) => {
                            let request_id = request.mig_info.mig_request_id;
                            log::info!(migration_request_id = request_id; "Processing StartMigration through shared workflow\n");
                            return execute_start_migration(
                                &EmulatedHostControlTransport,
                                &request,
                            )
                            .await;
                        }
                        #[cfg(feature = "policy_v2")]
                        WaitForRequestResponse::StartRebinding(_)
                        | WaitForRequestResponse::GetMigtdData(_) => {
                            log::warn!("SnpEmu: unsupported request type (rebinding)\n");
                        }
                    }
                }
                Err(error) => {
                    log::error!("wait_for_request failed: {}\n", error as u8 as i32);
                    return error as u8 as i32;
                }
            }
        }
    })
}

fn runtime_main_wfr(config: &RuntimeConfig) -> i32 {
    if config.host_control != HostControlMode::Tcp {
        eprintln!(
            "[MA] FATAL: WFR requires TCP host control, configured={}",
            config.host_control
        );
        return 2;
    }
    if config.peer_transport != PeerTransportMode::TcpEmulation {
        eprintln!(
            "[MA] FATAL: unsupported M1 peer transport: {}",
            config.peer_transport
        );
        return 2;
    }

    let host_control_address = config
        .host_control_address
        .as_deref()
        .expect("WFR configuration must include a host-control address")
        .to_string();
    let role = config.role;
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    runtime.block_on(async move {
        use migtd::runtime::snp::snpemu::runtime_main_snp;
        use migtd::transport::host_control::tcp::TcpTransport;

        let transport = if role.is_source() {
            eprintln!(
                "[MA] Source MA: connecting to IGVMAgent/host at {}",
                host_control_address
            );
            TcpTransport::connect(&host_control_address).await
        } else {
            eprintln!(
                "[MA] Destination MA: binding host-control TCP on {}",
                host_control_address
            );
            TcpTransport::accept(&host_control_address).await
        };

        match transport {
            Ok(transport) => runtime_main_snp(&transport).await,
            Err(error) => {
                eprintln!("[MA] FATAL: TCP host-control setup failed: {error}");
                1
            }
        }
    })
}
