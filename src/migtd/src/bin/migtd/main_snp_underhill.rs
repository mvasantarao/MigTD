// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MA as PID 1 entrypoint for OHCL VTL2 VM (Phase 3a SnpUnderhill).
//! Mounts proc/sysfs/devtmpfs, initializes logging, then enters WFR service loop.
//!
//! Phase 3a: TcpTransport (A2). TODO(Phase-3b): select GhcbVmgexitTransport.

use std::fs;

/// Source MA TCP port: MA is client, connects to IGVMAgent (host) server.
const MA_SOURCE_HOST_ADDR: &str = "127.0.0.1:8001";
/// Dest MA TCP port: MA is server, IGVMAgent (host) client connects in.
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
        use crate::transport::host_control::tcp::TcpTransport;
        use crate::runtime::snp::snpemu::runtime_main_snp;

        let transport = if is_source {
            TcpTransport::connect(MA_SOURCE_HOST_ADDR).await
        } else {
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
