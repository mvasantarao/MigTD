// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SnpEmu-specific code for running MigTD SNP emulator in a standard Rust environment.
//! Simplified version of cvmemu.rs: no policy files, no igvm-attest, migration only.

#![cfg(feature = "SnpEmu")]

use std::env;
use std::process;

use alloc::vec::Vec;
use migtd::driver::vmcall_raw::panic_with_guest_crash_reg_report;
use migtd::migration::event;
use migtd::migration::logging::{
    create_logarea, enable_logarea, init_vmm_logger, u8_to_levelfilter,
};
use migtd::migration::session::{exchange_msk, report_status};
use migtd::migration::MigrationResult;

use tdx_tdcall_emu::tdx_emu::{connect_tcp_client, set_emulated_start_migration};
use tdx_tdcall_emu::{init_tcp_emulation_with_mode, start_tcp_server_sync, TcpEmulationMode};

/// SnpEmu entry point
pub fn main() {
    let result = init_vmm_logger();
    if result.is_err() {
        panic_with_guest_crash_reg_report(
            MigrationResult::InitializationError as u64,
            b"Failed to initialize VMM logger",
        );
    }

    // Init internal heap (only when NOT bypassing attestation)
    #[cfg(not(feature = "test_disable_ra_and_accept_all"))]
    attestation::attest_init_heap();

    // Initialize event log emulation
    td_shim_emu::event_log::init_event_log();

    // Parse CLI args and set up TCP
    parse_commandline_args();

    let exit_code = runtime_main_snp();
    process::exit(exit_code);
}

/// Main event loop for SnpEmu
fn runtime_main_snp() -> i32 {
    match create_logarea() {
        Ok(_) => log::info!("LogArea created successfully\n"),
        Err(e) => log::error!("Failed to create logarea: {}\n", e as u8),
    }

    event::register_callback();

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    rt.block_on(async move {
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
                            .unwrap_or_else(|e| e);

                            log::set_max_level(u8_to_levelfilter(wfr_info.log_max_level));
                            let _ = report_status(status as u8, wfr_info.mig_request_id, &data).await;
                        }
                        WaitForRequestResponse::GetTdReport(report_info) => {
                            // SnpEmu: SNP report is generated inline during SPDM handshake.
                            // Return success with empty bytes to satisfy the event loop.
                            log::info!(migration_request_id = report_info.mig_request_id; "SnpEmu: GetTdReport is a no-op (SNP report generated in SPDM layer)\n");
                            let _ = report_status(
                                MigrationResult::Success as u8,
                                report_info.mig_request_id,
                                &Vec::new(),
                            )
                            .await;
                        }
                        WaitForRequestResponse::StartMigration(req) => {
                            log::info!(migration_request_id = req.mig_info.mig_request_id; "Processing StartMigration request\n");

                            let res = exchange_msk(&req).await;
                            match &res {
                                Ok(_) => log::info!(migration_request_id = req.mig_info.mig_request_id; "exchange_msk() returned Ok\n"),
                                Err(e) => log::error!(migration_request_id = req.mig_info.mig_request_id; "exchange_msk() error {}\n", *e as u8),
                            }
                            let status = res.map(|_| MigrationResult::Success).unwrap_or_else(|e| e);
                            let status_code_u8 = status as u8;

                            let _ = report_status(status_code_u8, req.mig_info.mig_request_id, &Vec::new()).await;

                            if status_code_u8 == MigrationResult::Success as u8 {
                                log::info!(migration_request_id = req.mig_info.mig_request_id; "SNP migration key exchange successful!\n");
                                return 0;
                            } else {
                                log::error!(migration_request_id = req.mig_info.mig_request_id; "SNP migration key exchange failed: {}\n", status_code_u8);
                                return status_code_u8 as i32;
                            }
                        }
                        // SnpEmu does not support rebinding operations
                        #[cfg(feature = "policy_v2")]
                        WaitForRequestResponse::StartRebinding(_) |
                        WaitForRequestResponse::GetMigtdData(_) => {
                            log::warn!("SnpEmu: unsupported request type (rebinding)\n");
                        }
                    }
                }
                Err(e) => {
                    log::error!("wait_for_request failed: {}\n", e as u8 as i32);
                    return e as u8 as i32;
                }
            }
        }
    })
}

fn parse_commandline_args() {
    let args: Vec<String> = env::args().collect();
    let mut mig_request_id = 1u64;
    let mut is_source = true;
    let mut target_td_uuid = [1u32, 2, 3, 4];
    let mut binding_handle = 0x1234u64;
    let mut destination_ip: Option<String> = None;
    let mut destination_port: Option<u16> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--request-id" | "-r" if i + 1 < args.len() => {
                mig_request_id = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("Invalid request ID: {}", args[i + 1]);
                    process::exit(1);
                });
                i += 2;
            }
            "--role" | "-m" if i + 1 < args.len() => {
                match args[i + 1].to_lowercase().as_str() {
                    "source" | "src" => { is_source = true; i += 2; }
                    "destination" | "dst" | "target" => { is_source = false; i += 2; }
                    _ => { eprintln!("Invalid role: {}", args[i + 1]); process::exit(1); }
                }
            }
            "--uuid" | "-u" if i + 4 < args.len() => {
                target_td_uuid = [
                    args[i+1].parse().unwrap_or(1),
                    args[i+2].parse().unwrap_or(2),
                    args[i+3].parse().unwrap_or(3),
                    args[i+4].parse().unwrap_or(4),
                ];
                i += 5;
            }
            "--binding" | "-b" if i + 1 < args.len() => {
                let s = &args[i + 1];
                binding_handle = if s.starts_with("0x") || s.starts_with("0X") {
                    u64::from_str_radix(&s[2..], 16).unwrap_or(0x1234)
                } else {
                    s.parse().unwrap_or(0x1234)
                };
                i += 2;
            }
            "--dest-ip" | "-d" if i + 1 < args.len() => {
                destination_ip = Some(args[i + 1].clone());
                i += 2;
            }
            "--dest-port" | "-t" if i + 1 < args.len() => {
                destination_port = Some(args[i + 1].parse().unwrap_or(8001));
                i += 2;
            }
            "--help" | "-h" => { print_snpemu_usage(); process::exit(0); }
            _ => { eprintln!("Unknown argument: {}", args[i]); i += 1; }
        }
    }

    log::info!("SnpEmu Migration: id={}, role={}, uuid={:?}, binding={:#x}\n",
        mig_request_id, if is_source { "source" } else { "destination" },
        target_td_uuid, binding_handle);

    let tcp_ip = destination_ip.as_deref().unwrap_or("127.0.0.1");
    let tcp_port = destination_port.unwrap_or(8001);
    let mode = if is_source { TcpEmulationMode::Client } else { TcpEmulationMode::Server };

    if let Err(e) = init_tcp_emulation_with_mode(tcp_ip, tcp_port, mode) {
        log::error!("Failed to initialize TCP emulation: {}\n", e);
        process::exit(1);
    }

    if !is_source {
        let addr = format!("{}:{}", tcp_ip, tcp_port);
        match start_tcp_server_sync(&addr) {
            Ok(_) => log::info!("TCP server started on: {}\n", addr),
            Err(e) => { log::error!("Failed to start TCP server: {:?}\n", e); process::exit(1); }
        }
    } else {
        match connect_tcp_client() {
            Ok(_) => log::info!("Connected to destination TCP server\n"),
            Err(e) => { log::error!("Failed to connect to destination: {:?}\n", e); process::exit(1); }
        }
    }

    let td_uuid = [
        target_td_uuid[0] as u64, target_td_uuid[1] as u64,
        target_td_uuid[2] as u64, target_td_uuid[3] as u64,
    ];
    let rebinding_src = if is_source { 1u8 } else { 0u8 };
    set_emulated_start_migration(mig_request_id, rebinding_src, td_uuid, binding_handle);
}

fn print_snpemu_usage() {
    println!("MigTD SnpEmu Mode Usage:");
    println!();
    println!("  --request-id, -r ID        Migration request ID (default: 1)");
    println!("  --role, -m ROLE            'source' or 'destination' (default: source)");
    println!("  --uuid, -u U1 U2 U3 U4     Target TD UUID as four integers");
    println!("  --binding, -b HANDLE       Binding handle (hex or decimal, default: 0x1234)");
    println!("  --dest-ip, -d IP           Destination IP (default: 127.0.0.1)");
    println!("  --dest-port, -t PORT       Destination port (default: 8001)");
    println!();
    println!("Examples:");
    println!("  # Source:");
    println!("  ./migtd --role source --request-id 1 --dest-ip 127.0.0.1 --dest-port 8001");
    println!("  # Destination:");
    println!("  ./migtd --role destination --request-id 1");
}
