// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MA as PID 1 entrypoint for OHCL VTL2 VM (Phase 3a SnpUnderhill).
//! Mounts proc/sysfs/devtmpfs, initializes logging, then enters WFR service loop.
//!
//! Phase 3a: TcpTransport (A2). TODO(Phase-3b): select GhcbVmgexitTransport.
//! WFR loop stubbed here; wired to dispatcher in 3a-08 (US02).

use std::fs;

pub fn ma_pid1_main() -> i32 {
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
    log::info!("[MA] MA_BOOT_STAGE_1: pid1 init started");

    // TODO(3a-05): load static policy blobs from initramfs embedded path

    log::info!("[MA] MA_BOOT_STAGE_2: entering WFR service loop");

    // TODO(3a-08/US02): Replace with dispatcher call once runtime/snp/snpemu.rs is implemented:
    //   use crate::transport::host_control::tcp::TcpTransport;
    //   crate::runtime::snp::snpemu::runtime_main_snp(&TcpTransport::new())
    todo!("WFR dispatcher wired in 3a-08 (US02)")
}
