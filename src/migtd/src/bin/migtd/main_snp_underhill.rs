// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! PID 1 preparation for the unified SNP Migration Agent.

use std::fs;

use migtd::runtime::snp::config::MigrationRole;

pub fn prepare_pid1(role: MigrationRole) {
    for (fstype, target) in &[("proc", "/proc"), ("sysfs", "/sys"), ("devtmpfs", "/dev")] {
        let _ = fs::create_dir_all(target);
        if let Err(error) = nix::mount::mount(
            Some(*fstype),
            *target,
            Some(*fstype),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        ) {
            eprintln!("[MA] mount {} failed: {:?}", target, error);
        }
    }

    eprintln!(
        "[MA] MA_BOOT_STAGE_1: pid1 init started, role={}",
        role.as_str()
    );
}
