// Copyright (c) 2020-2025 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(feature = "no-std", no_std)]

//! Azure CVM Emulation layer for TDX TDCALL interface
//!
//! This crate provides a drop-in replacement for the original tdx-tdcall crate
//! that emulates TDX VMCALL operations using TCP transport for development and
//! testing in non-TDX environments.

extern crate alloc;

// Import the original tdx-tdcall as a dependency
pub use original_tdx_tdcall;

// Re-export all the standard tdx-tdcall types and constants
// Re-export error types and constants that are needed
pub use original_tdx_tdcall::{TdCallError, TdVmcallError, TdcallArgs};

// Export constants that we need from the original library
pub const TDCALL_STATUS_SUCCESS: u64 = 0;

// Our TDX emulation module
pub mod tdx_emu;

// Our emulated tdreport module
pub mod tdreport_emu;

// VMM-side logging emulation
pub mod logging_emu;

// Hardcoded collateral data for AzCVMEmu mode
mod collateral_data;

// Re-export TDX emulation functions
pub use tdx_emu::{
    connect_tcp_client, init_tcp_emulation_with_mode, set_emulated_start_rebinding,
    start_tcp_server_sync, tcp_receive_data, tcp_send_data, TcpEmulationMode,
};

// Re-export the emulated functions
pub mod tdx {
    // Re-export all non-MigTD functions from original
    pub use original_tdx_tdcall::tdx::{
        tdcall_accept_page,
        tdcall_get_td_info,
        tdcall_get_ve_info,
        tdcall_vp_read,
        tdvmcall_cpuid,
        // Standard VMCALL functions
        tdvmcall_halt,
        tdvmcall_io_read_16,
        tdvmcall_io_read_32,
        tdvmcall_io_read_8,
        tdvmcall_io_write_16,
        tdvmcall_io_write_32,
        tdvmcall_io_write_8,
        tdvmcall_mapgpa,
        tdvmcall_mmio_read,
        tdvmcall_mmio_write,
        tdvmcall_rdmsr,
        tdvmcall_service,
        // tdvmcall_setup_event_notify is emulated, not re-exported
        tdvmcall_sti_halt,
        tdvmcall_wrmsr,
        // Re-export types
        TdxDigest,
        TargetTdUuid,
    };

    // Export emulated functions
    pub use crate::tdx_emu::{
        tdcall_extend_rtmr, tdcall_servtd_rd, tdcall_servtd_wr, tdcall_sys_rd, tdcall_sys_wr,
        tdvmcall_get_quote, tdvmcall_migtd_receive_sync as tdvmcall_migtd_receive,
        tdvmcall_migtd_reportstatus, tdvmcall_migtd_send_sync as tdvmcall_migtd_send,
        tdvmcall_migtd_waitforrequest, tdvmcall_setup_event_notify, tdcall_vm_write, tdcall_servtd_rebind_approve,
    };
}

// Emulated tdreport module for AzCVMEmu compatibility
pub mod tdreport {
    use crate::tdreport_emu::tdcall_report_emulated;
    #[cfg(feature = "vtpm")]
    use az_tdx_vtpm::tdx::TdReport as AzTdReport;
    use original_tdx_tdcall::TdCallError;

    // Re-export some useful constants and types from original
    pub use original_tdx_tdcall::tdreport::{
        TdxReport, TD_REPORT_ADDITIONAL_DATA_SIZE, TD_REPORT_SIZE, TdInfo,
    };

    // Size guard: ensure az-tdx-vtpm TdReport stays 1024 bytes (only needed with vtpm feature).
    #[cfg(feature = "vtpm")]
    const _: () = assert!(core::mem::size_of::<AzTdReport>() == TD_REPORT_SIZE);

    /// Emulated tdcall_report function.
    /// With vtpm: fetches from hardware vTPM → TdxReport.
    /// Without vtpm (SnpEmu/mock): returns mock TdxReport directly.
    pub fn tdcall_report(additional_data: &[u8; 64]) -> Result<TdxReport, TdCallError> {
        // tdcall_report_emulated now returns TdxReport directly in all code paths.
        tdcall_report_emulated(additional_data)
    }

    /// Emulated TD Report Verification
    pub fn tdcall_verify_report(report_mac: &[u8]) -> Result<(), TdCallError> {
        log::warn!("Emulated TD report verification");
        Ok(())
    }
}

// Add td_call emulation support
pub fn td_call(args: &mut TdcallArgs) -> u64 {
    const TDVMCALL_SYS_RD: u64 = 0x0000b;

    match args.rax {
        0x00001 => {
            // TDINFO - return TD information
            // Detect actual number of CPUs available to the process
            let num_cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1); // Default to 1 if detection fails

            log::info!("TDINFO emulation: detected {} CPUs", num_cpus);

            args.r8 = num_cpus as u64; // num_vcpus
            args.r9 = num_cpus as u64; // max_vcpus
            args.r10 = 0; // vcpu_index - not used in emulation
            args.r11 = 0; // reserved
            0 // Success
        }
        TDVMCALL_SYS_RD => {
            match crate::tdx_emu::tdcall_sys_rd(args.rcx) {
                Ok((rdx, r8)) => {
                    args.rdx = rdx;
                    args.r8 = r8;
                    TDCALL_STATUS_SUCCESS
                }
                Err(_) => 0xFFFFFFFFFFFFFFFF, // Error code
            }
        }
        _ => {
            // Return error for unsupported rax values
            0xFFFFFFFFFFFFFFFF // Generic error code
        }
    }
}
