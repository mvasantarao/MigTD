// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Typed fixture implementations of the logical SNP platform services.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::traits::{MigrationKeyInstaller, PalError};
use crate::types::SnpOperationContext;

const MIGRATION_KEY_SIZE: usize = 32;
static TRACE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TraceSite<'a> {
    phase: &'a str,
    operation: &'a str,
    interface: &'a str,
    provider: &'a str,
    execution: &'a str,
    hardware_invoked: bool,
}

fn trace(context: &SnpOperationContext, site: &TraceSite<'_>, event: &str, result: &str) {
    let sequence = TRACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "SNP_API_CALL sequence={} role={} request_id={} phase={} operation={} \
         interface={} provider={} execution={} hardware_invoked={} event={} result={}",
        sequence,
        context.role.as_str(),
        context.request_id.value(),
        site.phase,
        site.operation,
        site.interface,
        site.provider,
        site.execution,
        site.hardware_invoked,
        event,
        result
    );
}

pub fn trace_qvl_verification(context: &SnpOperationContext, event: &str, result: &str) {
    let operation = "AZURE_VERIFY_ATTESTATION";
    let provider = "AzureSnpQvl";
    trace(
        context,
        &TraceSite {
            phase: "attestation-verification",
            operation,
            interface: "QvlLibrary::verify",
            provider,
            execution: "software",
            hardware_invoked: false,
        },
        event,
        result,
    );
}

pub struct MockMigrationKeyInstaller;

impl MigrationKeyInstaller for MockMigrationKeyInstaller {
    fn set_migration_info(
        &self,
        context: &SnpOperationContext,
        migration_key: &[u8],
    ) -> Result<(), PalError> {
        let site = TraceSite {
            phase: "msk-install",
            operation: "MSG_SET_MIGRATION_INFO",
            interface: "MigrationKeyInstaller::set_migration_info",
            provider: "MockMigrationKeyInstaller",
            execution: "mock",
            hardware_invoked: false,
        };
        trace(context, &site, "begin", "pending");
        if migration_key.len() != MIGRATION_KEY_SIZE {
            trace(context, &site, "end", "invalid-input");
            return Err(PalError::InvalidInput);
        }
        trace(context, &site, "end", "success");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, SnpOperationContext,
    };

    fn context() -> SnpOperationContext {
        SnpOperationContext::new(
            HostRequestId::new(7),
            MigrationId::new(8),
            MigrationRole::Source,
            ManagedGuestHandle::new(0x1234),
        )
    }

    #[test]
    fn installer_accepts_valid_logical_inputs() {
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
