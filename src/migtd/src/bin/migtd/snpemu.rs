// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! SNP-owned WFR and local testing entry point; no synthetic TDX services.

#![cfg(feature = "SnpEmu")]

use migtd::runtime::snp::{
    config::{
        usage, HostControlMode, MigrationRole, ParseOutcome, PeerTransportMode, ProcessMode,
        RuntimeConfig, StartMode,
    },
    requests::{HostRequest, LegacyOperation},
    snpemu::runtime_main_snp,
};
use migtd::snp_composition::{selected_runtime_provider_set, SnpRuntimeProviders};
use migtd::transport::{
    host_control::{emulated::EmulatedHostControlTransport, tcp::TcpTransport},
    peer::TcpPeerStream,
};
use pal::types::MigrationRole as SnpRole;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process;

struct SerialLogger;
impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[MA] {}: {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}
static LOGGER: SerialLogger = SerialLogger;

pub fn main() {
    let config = match RuntimeConfig::parse(std::env::args()) {
        Ok(ParseOutcome::Run(config)) => config,
        Ok(ParseOutcome::Help) => {
            println!("{}", usage());
            return;
        }
        Err(error) => {
            eprintln!("[MA] invalid runtime configuration: {error}\n{}", usage());
            process::exit(2);
        }
    };
    if let Err(error) = prepare_process(&config) {
        eprintln!("[MA] FATAL: {error}");
        process::exit(2);
    }
    let providers = selected_runtime_provider_set();
    eprintln!("[MA] FIXTURE_PLATFORM_DATA_READY");
    eprintln!(
        "[MA] RUNTIME_PROFILE: process={} start={} role={} host_control={} peer_transport={} platform_services={}",
        config.process_mode, config.start_mode, config.role, config.host_control,
        config.peer_transport, config.platform_services,
    );
    eprintln!("[MA] LEGACY_CLI_LIMITATION: --uuid is ignored compatibility metadata; --binding is an untrusted legacy guest handle");
    let peer = match initialize_peer_channel(config.role, &config.peer_address) {
        Ok(peer) => peer,
        Err(error) => {
            eprintln!("[MA] FATAL: {error}");
            process::exit(1);
        }
    };
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    let exit = runtime.block_on(run(&config, &providers, peer));
    if config.process_mode == ProcessMode::Pid1 && exit == 0 {
        eprintln!("[MA] PID1_SERVICE_COMPLETE: migration finished; remaining resident");
        loop {
            std::thread::park();
        }
    }
    process::exit(exit);
}

fn prepare_process(config: &RuntimeConfig) -> Result<(), String> {
    if config.platform_services == migtd::runtime::snp::config::PlatformServicesMode::Hardware {
        return Err(
            "hardware platform services are not implemented; refusing fixture fallback".into(),
        );
    }
    if config.peer_transport != PeerTransportMode::TcpEmulation {
        return Err("the Underhill peer backend is not implemented; refusing TCP fallback".into());
    }
    log::set_logger(&LOGGER)
        .map_err(|error| format!("SNP serial logger initialization failed: {error}"))?;
    log::set_max_level(log::LevelFilter::Info);
    if config.process_mode == ProcessMode::Pid1 {
        #[cfg(feature = "SnpUnderhillRuntime")]
        migtd::runtime::snp::pid1::prepare_pid1(config.role);
        #[cfg(not(feature = "SnpUnderhillRuntime"))]
        return Err("PID1 process mode requires the SnpUnderhillRuntime feature".into());
    }
    Ok(())
}

fn initialize_peer_channel(role: MigrationRole, address: &str) -> Result<TcpStream, String> {
    let socket: SocketAddr = address
        .parse()
        .map_err(|error| format!("invalid peer address {address}: {error}"))?;
    eprintln!("[MA] PEER_CHANNEL_SETUP: role={role} address={address}");
    let stream = if role.is_source() {
        TcpStream::connect(socket).map_err(|error| format!("peer TCP connect failed: {error}"))?
    } else {
        let listener =
            TcpListener::bind(socket).map_err(|error| format!("peer TCP bind failed: {error}"))?;
        eprintln!("[MA] PEER_CHANNEL_LISTENING: {address}");
        listener
            .accept()
            .map_err(|error| format!("peer TCP accept failed: {error}"))?
            .0
    };
    stream
        .set_nonblocking(true)
        .map_err(|error| format!("peer TCP nonblocking setup failed: {error}"))?;
    eprintln!("[MA] PEER_CHANNEL_READY: role={role} address={address}");
    Ok(stream)
}

async fn run(config: &RuntimeConfig, providers: &SnpRuntimeProviders, peer: TcpStream) -> i32 {
    let peer = match tokio::net::TcpStream::from_std(peer) {
        Ok(peer) => TcpPeerStream::new(peer),
        Err(error) => {
            eprintln!("[MA] peer TCP runtime attachment failed: {error}");
            return 1;
        }
    };
    let role = if config.role.is_source() {
        SnpRole::Source
    } else {
        SnpRole::Destination
    };
    match config.start_mode {
        StartMode::Autostart => {
            eprintln!(
                "[MA] AUTOSTART_REQUEST_CREATED: request_id={} role={}",
                config.request_id, config.role
            );
            let request = HostRequest::StartMigration(LegacyOperation::new(
                config.request_id,
                role,
                config.binding_handle,
            ));
            runtime_main_snp(
                &EmulatedHostControlTransport::new(request),
                providers,
                &peer,
                role,
            )
            .await
        }
        StartMode::Wfr => {
            if config.host_control != HostControlMode::Tcp {
                eprintln!("[MA] FATAL: WFR requires TCP host control");
                return 2;
            }
            let Some(address) = config.host_control_address.as_deref() else {
                eprintln!("[MA] FATAL: WFR requires a host-control address");
                return 2;
            };
            if config.process_mode == ProcessMode::Pid1 {
                eprintln!("[MA] MA_BOOT_STAGE_2: entering WFR service loop");
            }
            let transport = if config.role.is_source() {
                TcpTransport::connect(address).await
            } else {
                TcpTransport::accept(address).await
            };
            match transport {
                Ok(transport) => runtime_main_snp(&transport, providers, &peer, role).await,
                Err(error) => {
                    eprintln!("[MA] FATAL: TCP host-control setup failed: {error}");
                    1
                }
            }
        }
    }
}
