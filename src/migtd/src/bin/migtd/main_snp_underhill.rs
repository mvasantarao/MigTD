// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MA as PID 1 entrypoint for OHCL VTL2 VM (Phase 3a SnpUnderhill).
//! Mounts proc/sysfs/devtmpfs, initializes logging, then enters WFR service loop.
//!
//! Phase 3a: TcpTransport (A2). TODO(Phase-3b): select GhcbVmgexitTransport.
//!
//! TCP address selection (Source MA only -- Dest MA always binds 0.0.0.0):
//!   In production:  IGVMAgent runs on the same node, so 127.0.0.1:8001 is correct.
//!   In SNP guest (PID 1): pass as kernel cmdline: init=/init source 10.0.2.2:8001
//!   In test/2-node: env var MA_HOST_ADDR=<host_ip>:8001 also accepted (fallback).
//!
//! 2-node test topology:
//!   Node A:  run `host_wfr_test --server 0.0.0.0:8001`   <- Source MA client connects here
//!            run source MA binary (connects to Node A host_wfr_test)
//!   Node B:  run dest MA binary (listens on 0.0.0.0:8002)
//!            run `host_wfr_test --client <NodeB_IP>:8002`  <- host connects to Dest MA
//!   Both host_wfr_test instances must reach StartMigration roughly simultaneously
//!   for SPDM peer-to-peer handshake (exchange_msk) to succeed.

use std::fs;

/// Default: IGVMAgent co-located on the same node (production).
/// Override with env var MA_HOST_ADDR=<ip>:<port> for 2-node testing.
const MA_SOURCE_HOST_ADDR_DEFAULT: &str = "127.0.0.1:8001";
/// Dest MA always binds all interfaces so host can connect from any node.
const MA_DEST_LISTEN_ADDR: &str = "0.0.0.0:8002";

pub fn ma_pid1_main(is_source: bool) -> i32 {
    // Mount essential filesystems for userspace tools
    for (fstype, target) in &[
        ("proc",     "/proc"),
        ("sysfs",    "/sys"),
        ("devtmpfs", "/dev"),
    ] {
        let _ = fs::create_dir_all(target);
        if let Err(e) = nix::mount::mount(
            Some(*fstype), *target, Some(*fstype),
            nix::mount::MsFlags::empty(), None::<&str>,
        ) {
            eprintln!("[MA] mount {} failed: {:?}", target, e);
        }
    }

    // MA_BOOT_STAGE_1: must appear in AHOS console stream for boot verification (3a-05 AC5)
    log::info!("[MA] MA_BOOT_STAGE_1: pid1 init started, role={}", if is_source { "source" } else { "dest" });

    // TODO(3a-05): load static policy blobs from initramfs embedded path

    log::info!("[MA] MA_BOOT_STAGE_2: entering WFR service loop");

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        use migtd::transport::host_control::tcp::TcpTransport;
        use migtd::runtime::snp::snpemu::runtime_main_snp;

        let transport = if is_source {
            // argv[2] = host addr when running as PID 1; env var fallback; then default (10.0.2.2 = QEMU user-net gateway)
            let addr = std::env::args().nth(2)
                .or_else(|| std::env::var("MA_HOST_ADDR").ok())
                .unwrap_or_else(|| MA_SOURCE_HOST_ADDR_DEFAULT.to_string());
            log::info!("[MA] Source MA: connecting to IGVMAgent/host at {}", addr);
            TcpTransport::connect(&addr).await
        } else {
            log::info!("[MA] Dest MA: listening for IGVMAgent/host on {}", MA_DEST_LISTEN_ADDR);
            TcpTransport::accept(MA_DEST_LISTEN_ADDR).await
        };
        match transport {
            Ok(t) => runtime_main_snp(&t).await,
            Err(e) => {
                log::error!("[MA] TCP transport setup failed: {}", e);
                1
            }
        }
    })
}
