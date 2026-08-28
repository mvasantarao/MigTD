// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MA as PID 1 entrypoint for OHCL VTL2 VM (Phase 3a SnpUnderhill).
//! Mounts proc/sysfs/devtmpfs, initializes logging, then enters WFR service loop.
//!
//! Phase 3a: TcpTransport (A2). TODO(Phase-3b): select GhcbVmgexitTransport.
//!
//! PID1 arguments:
//!   source <WFR-host-address> <peer-address>
//!   dest <peer-listen-address>
//!
//! 2-node test topology:
//!   Node A:  run `host_wfr_test --server 0.0.0.0:8001`   <- Source MA client connects here
//!            run source MA binary (connects to Node A host_wfr_test)
//!   Node B:  run dest MA binary (listens on 0.0.0.0:8002)
//!            run `host_wfr_test --client <NodeB_IP>:8002`  <- host connects to Dest MA
//!   Peer TCP is the SnpEmu backing for Service.MigTD.Send/Receive. It is
//!   established before either MA accepts WFR StartMigration.

use std::fs;
use std::net::SocketAddr;

use tdx_tdcall_emu::{
    connect_tcp_client, init_tcp_emulation_with_mode, start_tcp_server_sync, TcpEmulationMode,
};

/// Default: IGVMAgent co-located on the same node (production).
/// Override with env var MA_HOST_ADDR=<ip>:<port> for 2-node testing.
const MA_SOURCE_HOST_ADDR_DEFAULT: &str = "127.0.0.1:8001";
/// Dest MA always binds all interfaces so host can connect from any node.
const MA_DEST_LISTEN_ADDR: &str = "0.0.0.0:8002";
const MA_SOURCE_PEER_ADDR_DEFAULT: &str = "10.0.2.2:9001";
const MA_DEST_PEER_ADDR_DEFAULT: &str = "0.0.0.0:9001";

fn initialize_peer_channel(is_source: bool, peer_addr: &str) -> Result<(), String> {
    let socket_addr: SocketAddr = peer_addr
        .parse()
        .map_err(|e| format!("invalid peer address {peer_addr}: {e}"))?;
    let mode = if is_source {
        TcpEmulationMode::Client
    } else {
        TcpEmulationMode::Server
    };

    eprintln!(
        "[MA] PEER_CHANNEL_SETUP: role={} address={}",
        if is_source { "source" } else { "dest" },
        peer_addr
    );
    init_tcp_emulation_with_mode(&socket_addr.ip().to_string(), socket_addr.port(), mode)
        .map_err(|e| format!("peer TCP emulation initialization failed: {e}"))?;

    if is_source {
        connect_tcp_client().map_err(|e| format!("peer TCP connect failed: {e:?}"))?;
    } else {
        eprintln!("[MA] PEER_CHANNEL_LISTENING: {}", peer_addr);
        start_tcp_server_sync(peer_addr).map_err(|e| format!("peer TCP accept failed: {e:?}"))?;
    }

    eprintln!(
        "[MA] PEER_CHANNEL_READY: role={} address={}",
        if is_source { "source" } else { "dest" },
        peer_addr
    );
    Ok(())
}

pub fn ma_pid1_main(is_source: bool) -> i32 {
    // Mount essential filesystems for userspace tools
    for (fstype, target) in &[("proc", "/proc"), ("sysfs", "/sys"), ("devtmpfs", "/dev")] {
        let _ = fs::create_dir_all(target);
        if let Err(e) = nix::mount::mount(
            Some(*fstype),
            *target,
            Some(*fstype),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        ) {
            eprintln!("[MA] mount {} failed: {:?}", target, e);
        }
    }

    // MA_BOOT_STAGE_1: must appear in AHOS console stream for boot verification (3a-05 AC5)
    eprintln!(
        "[MA] MA_BOOT_STAGE_1: pid1 init started, role={}",
        if is_source { "source" } else { "dest" }
    );

    // TODO(3a-05): load static policy blobs from initramfs embedded path

    let args: Vec<String> = std::env::args().collect();
    let peer_addr = if is_source {
        args.get(3)
            .cloned()
            .or_else(|| std::env::var("MA_PEER_ADDR").ok())
            .unwrap_or_else(|| MA_SOURCE_PEER_ADDR_DEFAULT.to_string())
    } else {
        args.get(2)
            .cloned()
            .or_else(|| std::env::var("MA_PEER_ADDR").ok())
            .unwrap_or_else(|| MA_DEST_PEER_ADDR_DEFAULT.to_string())
    };
    if let Err(e) = initialize_peer_channel(is_source, &peer_addr) {
        eprintln!("[MA] FATAL: peer channel setup failed: {}", e);
        return 1;
    }

    eprintln!("[MA] MA_BOOT_STAGE_2: entering WFR service loop");

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        use migtd::runtime::snp::snpemu::runtime_main_snp;
        use migtd::transport::host_control::tcp::TcpTransport;

        let transport = if is_source {
            let addr = args
                .get(2)
                .cloned()
                .or_else(|| std::env::var("MA_HOST_ADDR").ok())
                .unwrap_or_else(|| MA_SOURCE_HOST_ADDR_DEFAULT.to_string());
            eprintln!("[MA] Source MA: connecting to IGVMAgent/host at {}", addr);
            TcpTransport::connect(&addr).await
        } else {
            eprintln!("[MA] Dest MA: binding TCP on {}", MA_DEST_LISTEN_ADDR);
            TcpTransport::accept(MA_DEST_LISTEN_ADDR).await
        };
        match transport {
            Ok(t) => runtime_main_snp(&t).await,
            Err(e) => {
                eprintln!("[MA] FATAL: TCP transport setup failed: {}", e);
                1
            }
        }
    })
}
