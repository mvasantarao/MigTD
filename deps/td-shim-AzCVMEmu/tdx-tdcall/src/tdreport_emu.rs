// Copyright (c) 2021 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TD Report generation emulation for AzCVMEmu mode
//!
//! This module provides emulation for TD report generation using vTPM interface
//! and IMDS for quote generation in Azure CVM environments.

#[cfg(any(feature = "test_mock_report", feature = "mock_report_tools"))]
use tdx_mock_data::QUOTE;
use alloc::vec::Vec;
#[cfg(feature = "vtpm")]
use az_tdx_vtpm::tdx;
#[cfg(all(feature = "vtpm", not(feature = "test_mock_report")))]
use az_tdx_vtpm::{hcl, imds, vtpm};
use log::{debug, error, info};
use original_tdx_tdcall::TdCallError;
use original_tdx_tdcall::tdreport::TdxReport;

/// Simple error type for internal emulation errors that are not TdCallError
/// Used only for get_quote_emulated which doesn't need TdCallError compatibility
#[derive(Debug)]
pub enum QuoteError {
    VtpmError,
    ImdsError,
    ConversionError,
}

/// Emulated TD Report Verification
#[cfg(feature = "test_mock_report")]
pub fn tdcall_verify_report(report_mac: &[u8]) -> Result<(), TdCallError> {
    info!("Using mock TD report verification for test_mock_report feature");
    Ok(())
}

/// Emulated TD report generation using mock report
#[cfg(feature = "test_mock_report")]
pub fn tdcall_report_emulated(_additional_data: &[u8; 64]) -> Result<TdxReport, TdCallError> {
    info!("Using mock TD report for test_mock_report feature");
    Ok(create_mock_td_report())
}

/// Emulated TD report generation using vTPM interface
#[cfg(all(feature = "vtpm", not(feature = "test_mock_report")))]
pub fn tdcall_report_emulated(additional_data: &[u8; 64]) -> Result<TdxReport, TdCallError> {
    info!("Using AzCVMEmu vTPM interface for report generation");

    // Get the vTPM report with our additional data as user data
    debug!("Getting vTPM report with retry mechanism");

    // Retry logic for vTPM report generation
    let mut vtpm_report = None;
    let max_retries = 3;


    for attempt in 1..=max_retries {
        debug!("vTPM report attempt {} of {}", attempt, max_retries);

        match vtpm::get_report_with_report_data(additional_data) {
            Ok(report) => {
                debug!("vTPM report obtained successfully on attempt {}", attempt);
                vtpm_report = Some(report);
                break;
            }
            Err(e) => {
                error!("vTPM report attempt {} failed: {:?}", attempt, e);

                if attempt < max_retries {
                    debug!("Waiting 5 seconds before retry...");
                    // Wait 5 seconds using std::time in AzCVMEmu mode
                    let start = std::time::Instant::now();
                    while start.elapsed() < std::time::Duration::from_secs(5) {
                        // Busy wait
                    }
                } else {
                    error!("All vTPM report attempts failed");
                    // Map to TdCallError::TdxExitInvalidParameters for compatibility
                    return Err(TdCallError::TdxExitInvalidParameters);
                }
            }
        }
    }

    let vtpm_report = vtpm_report.ok_or(TdCallError::TdxExitInvalidParameters)?;

    // Create an HCL report from the vTPM report
    debug!("Creating HCL report from vTPM report");
    let hcl_report = match hcl::HclReport::new(vtpm_report) {
        Ok(report) => {
            debug!("HCL report created successfully");
            report
        }
        Err(_) => {
            error!("Failed to create HCL report");
            return Err(TdCallError::TdxExitInvalidParameters);
        }
    };

    // Convert the HCL report to a TD report
    debug!("Converting HCL report to TD report");
    match tdx::TdReport::try_from(hcl_report) {
        Ok(az_report) => {
            debug!("TD report conversion successful");

            // transmute az_tdx_vtpm::tdx::TdReport -> TdxReport (both 1024-byte repr(C))
            let report: TdxReport = unsafe { core::mem::transmute(az_report) };
            let report_bytes = unsafe {
                core::slice::from_raw_parts(
                    &report as *const _ as *const u8,
                    core::mem::size_of::<TdxReport>()
                )
            };
            debug!("REPORT_BYTES=[");
            for (i, chunk) in report_bytes.chunks(64).enumerate() {
                let byte_str = chunk
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<String>>()
                    .join(", ");
                if i == report_bytes.chunks(64).len() - 1 {
                    debug!("    {}", byte_str);
                } else {
                    debug!("    {},", byte_str);
                }
            }
            debug!("];");

            Ok(report)
        }
        Err(_) => {
            error!("Failed to convert HCL report to TD report");
            Err(TdCallError::TdxExitInvalidParameters)
        }
    }
}

/// Emulated quote generation using mock quote
#[cfg(feature = "test_mock_report")]
pub fn get_quote_emulated(td_report_data: &[u8]) -> Result<Vec<u8>, QuoteError> {
    // When mock_quote_retry is enabled, fail the first N calls to exercise retry logic
    #[cfg(feature = "mock_quote_retry")]
    {
        use core::sync::atomic::{AtomicU32, Ordering};

        /// Number of times get_quote should fail before succeeding.
        /// Must not exceed MAXRETRIES in quote.rs (currently 5) so
        /// the last retry attempt succeeds.
        const FAIL_COUNT: u32 = 5;

        static CALL_COUNT: AtomicU32 = AtomicU32::new(0);

        let count = CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        if count < FAIL_COUNT {
            log::warn!(
                "mock_quote_retry: Simulating quote failure ({}/{})",
                count + 1,
                FAIL_COUNT
            );
            return Err(QuoteError::ImdsError);
        }
        log::info!(
            "mock_quote_retry: Returning mock quote on attempt {}",
            count + 1
        );
    }

    debug!("Using mock quote for test_mock_report feature");
    Ok(create_mock_quote(td_report_data))
}

/// Emulated quote generation using IMDS interface
#[cfg(all(feature = "vtpm", not(feature = "test_mock_report")))]
pub fn get_quote_emulated(td_report_data: &[u8]) -> Result<Vec<u8>, QuoteError> {

    debug!(
        "Getting quote from TD report data (size: {})",
        td_report_data.len()
    );

    // Check if we have a full TD report or just report data
    let td_report_struct = if td_report_data.len() >= core::mem::size_of::<TdxReport>() {
        // We have a full TD report - use it directly
        unsafe { core::ptr::read_unaligned(td_report_data.as_ptr() as *const TdxReport) }
    } else {
        // We only have report data (48 bytes) - need to generate a full TD report first
        debug!("Generating TD report from report data");

        // Pad or truncate the report data to 64 bytes for tdcall_report_emulated
        let mut report_data_64 = [0u8; 64];
        let copy_len = core::cmp::min(64, td_report_data.len());
        report_data_64[..copy_len].copy_from_slice(&td_report_data[..copy_len]);

        // Generate a full TD report using our emulated function
        match tdcall_report_emulated(&report_data_64) {
            Ok(report) => report,
            Err(e) => {
                error!("Failed to generate TD report from report data: {:?}", e);
                return Err(QuoteError::ConversionError);
            }
        }
    };

    let az_td_report: az_tdx_vtpm::tdx::TdReport = unsafe { core::mem::transmute(td_report_struct) };
    match imds::get_td_quote(&az_td_report) {
        Ok(quote) => {
            info!("Successfully got TD quote from IMDS");

            // Log quote as byte array format for direct code copying into mock_quote_data.rs
            debug!("QUOTE_BYTES=[");
            for (i, chunk) in quote.chunks(64).enumerate() {
                let byte_str = chunk
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<String>>()
                    .join(", ");
                if i == quote.chunks(64).len() - 1 {
                    debug!("    {}", byte_str);
                } else {
                    debug!("    {},", byte_str);
                }
            }
            debug!("];");

            Ok(quote)
        }
        Err(e) => {
            error!("IMDS call failed (expected outside Azure): {:?}", e);
            error!("Failed to get TD quote from IMDS: {:?}", e);
            Err(QuoteError::ImdsError)
        }
    }
}

/// Create a mock TD report for testing purposes
#[cfg(any(feature = "test_mock_report", feature = "mock_report_tools"))]
pub fn create_mock_td_report() -> TdxReport {
    // Check if a custom quote file is specified
    if let Ok(quote_file_path) = std::env::var("MOCK_QUOTE_FILE") {
        return create_td_report_from_file(quote_file_path);
    }
    // No custom quote file - use hardcoded quote data
    debug!("Creating mock TD report with hardcoded data");
    // tdx_mock_data::create_mock_td_report returns TdxReport directly - no conversion needed
    tdx_mock_data::create_mock_td_report(QUOTE.as_ref())
}

#[cfg(any(feature = "test_mock_report", feature = "mock_report_tools"))]
fn create_td_report_from_file(quote_file_path: String) -> TdxReport {
    debug!(
        "Creating mock TD report from custom quote file: {}",
        quote_file_path
    );

    let quote_data = match std::fs::read(&quote_file_path) {
        Ok(data) => {
            debug!("Successfully loaded quote file ({} bytes)", data.len());
            data
        }
        Err(e) => {
            error!("Failed to load quote from {}: {:?}", quote_file_path, e);
            if let Ok(cwd) = std::env::current_dir() {
                error!("Current working directory: {:?}", cwd);
                error!(
                    "Hint: Use absolute path or ensure the path is relative to: {:?}",
                    cwd
                );
            }
            panic!("Cannot create mock TD report without valid quote file");
        }
    };

    // tdx_mock_data::create_mock_td_report returns TdxReport directly
    tdx_mock_data::create_mock_td_report(&quote_data)
}

#[cfg(any(feature = "test_mock_report", feature = "mock_report_tools"))]
pub fn create_mock_quote(_td_report_data: &[u8]) -> Vec<u8> {
    // Check if a custom quote file is specified
    if let Ok(quote_file_path) = std::env::var("MOCK_QUOTE_FILE") {
        return create_td_quote_from_file(quote_file_path);
    }

    debug!("Creating mock quote with hardcoded data");
    QUOTE.to_vec()
}

#[cfg(any(feature = "test_mock_report", feature = "mock_report_tools"))]
fn create_td_quote_from_file(quote_file_path: String) -> Vec<u8> {
    debug!("Creating TD quote from file: {}", quote_file_path);

    match std::fs::read(&quote_file_path) {
        Ok(quote) => {
            debug!(
                "Successfully loaded mock quote from {} ({} bytes)",
                quote_file_path,
                quote.len()
            );

            quote
        }
        Err(e) => {
            error!(
                "Failed to load mock quote from {}: {:?}",
                quote_file_path, e
            );
            if let Ok(cwd) = std::env::current_dir() {
                error!("Current working directory: {:?}", cwd);
                error!(
                    "Hint: Use absolute path or ensure the path is relative to: {:?}",
                    cwd
                );
            }
            Vec::new()
        }
    }
}

// Stub implementations for builds where neither vtpm nor test_mock_report is enabled
// (e.g., SnpEmu without mock). These paths are unreachable at runtime because SnpEmu
// uses the SNP hardware report path, not the TDX vTPM path.
#[cfg(not(any(feature = "vtpm", feature = "test_mock_report", feature = "mock_report_tools")))]
pub fn tdcall_report_emulated(_additional_data: &[u8; 64]) -> Result<TdxReport, TdCallError> {
    panic!("tdcall_report_emulated: unreachable in SnpEmu — SNP report path must be used instead")
}

#[cfg(not(any(feature = "vtpm", feature = "test_mock_report")))]
pub fn get_quote_emulated(_td_report_data: &[u8]) -> Result<Vec<u8>, QuoteError> {
    panic!("get_quote_emulated: unreachable in SnpEmu — SNP attestation path must be used instead")
}
