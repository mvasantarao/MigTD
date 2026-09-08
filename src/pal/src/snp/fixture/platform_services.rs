// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Typed fixture implementations of the logical SNP platform services.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::traits::{MigrationKeyInstaller, PalError, PlatformKeyProvider, PlatformReportVerifier};
use crate::types::PlatformOperationContext;

const SNP_REPORT_SIZE: usize = 1184;
const MIGRATION_KEY_SIZE: usize = 32;
static TRACE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn trace(
    context: &PlatformOperationContext,
    phase: &str,
    operation: &str,
    interface: &str,
    provider: &str,
    execution: &str,
    hardware_invoked: bool,
    event: &str,
    result: &str,
) {
    let sequence = TRACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "SNP_API_CALL sequence={} role={} request_id={} phase={} operation={} \
         interface={} provider={} execution={} hardware_invoked={} event={} result={}",
        sequence,
        context.role.as_str(),
        context.request_id,
        phase,
        operation,
        interface,
        provider,
        execution,
        hardware_invoked,
        event,
        result
    );
}

pub fn trace_tav_verification(context: &PlatformOperationContext, event: &str, result: &str) {
    trace(
        context,
        "attestation-verification",
        "TAV_VERIFY_ATTESTATION",
        "QvlLibrary::verify",
        "SnpQvl",
        "software",
        false,
        event,
        result,
    );
}

pub struct MockPlatformReportVerifier;

impl PlatformReportVerifier for MockPlatformReportVerifier {
    fn verify_report(
        &self,
        context: &PlatformOperationContext,
        report: &[u8],
    ) -> Result<(), PalError> {
        trace(
            context,
            "platform-report-verification",
            "MSG_VERIFY_REPORT",
            "PlatformReportVerifier::verify_report",
            "MockPlatformReportVerifier",
            "mock",
            false,
            "begin",
            "pending",
        );
        if report.len() != SNP_REPORT_SIZE {
            trace(
                context,
                "platform-report-verification",
                "MSG_VERIFY_REPORT",
                "PlatformReportVerifier::verify_report",
                "MockPlatformReportVerifier",
                "mock",
                false,
                "end",
                "invalid-input",
            );
            return Err(PalError::InvalidInput);
        }
        trace(
            context,
            "platform-report-verification",
            "MSG_VERIFY_REPORT",
            "PlatformReportVerifier::verify_report",
            "MockPlatformReportVerifier",
            "mock",
            false,
            "end",
            "success",
        );
        Ok(())
    }
}

pub struct MockPlatformKeyProvider;

impl PlatformKeyProvider for MockPlatformKeyProvider {
    fn prepare_key(&self, context: &PlatformOperationContext) -> Result<(), PalError> {
        trace(
            context,
            "platform-key",
            "MSG_KEY_REQ",
            "PlatformKeyProvider::prepare_key",
            "MockPlatformKeyProvider",
            "mock",
            false,
            "begin",
            "pending",
        );
        trace(
            context,
            "platform-key",
            "MSG_KEY_REQ",
            "PlatformKeyProvider::prepare_key",
            "MockPlatformKeyProvider",
            "mock",
            false,
            "end",
            "success",
        );
        Ok(())
    }
}

pub struct MockMigrationKeyInstaller;

impl MigrationKeyInstaller for MockMigrationKeyInstaller {
    fn set_migration_info(
        &self,
        context: &PlatformOperationContext,
        migration_key: &[u8],
    ) -> Result<(), PalError> {
        trace(
            context,
            "msk-install",
            "MSG_SET_MIGRATION_INFO",
            "MigrationKeyInstaller::set_migration_info",
            "MockMigrationKeyInstaller",
            "mock",
            false,
            "begin",
            "pending",
        );
        if migration_key.len() != MIGRATION_KEY_SIZE {
            trace(
                context,
                "msk-install",
                "MSG_SET_MIGRATION_INFO",
                "MigrationKeyInstaller::set_migration_info",
                "MockMigrationKeyInstaller",
                "mock",
                false,
                "end",
                "invalid-input",
            );
            return Err(PalError::InvalidInput);
        }
        trace(
            context,
            "msk-install",
            "MSG_SET_MIGRATION_INFO",
            "MigrationKeyInstaller::set_migration_info",
            "MockMigrationKeyInstaller",
            "mock",
            false,
            "end",
            "success",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MigrationRole;

    fn context() -> PlatformOperationContext {
        PlatformOperationContext {
            request_id: 7,
            role: MigrationRole::Source,
            binding_handle: 0x1234,
            target_uuid: [1, 2, 3, 4],
        }
    }

    #[test]
    fn fixture_services_accept_valid_logical_inputs() {
        MockPlatformReportVerifier
            .verify_report(&context(), &[0u8; SNP_REPORT_SIZE])
            .unwrap();
        MockPlatformKeyProvider.prepare_key(&context()).unwrap();
        MockMigrationKeyInstaller
            .set_migration_info(&context(), &[0u8; MIGRATION_KEY_SIZE])
            .unwrap();
    }

    #[test]
    fn installer_rejects_wrong_key_size() {
        assert!(matches!(
            MockMigrationKeyInstaller.set_migration_info(&context(), &[0u8; 31]),
            Err(PalError::InvalidInput)
        ));
    }
}
