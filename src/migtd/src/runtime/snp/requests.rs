// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Legacy host framing ends here; these handles confer no tenant authorization.

use crate::status::MigrationResult;
use codec::{Codec, Reader, Writer};
use pal::types::{
    HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, SnpOperationContext,
};

#[derive(Debug, Clone)]
pub struct LegacyOperation {
    pub mig_request_id: u64,
    pub operation: SnpOperationContext,
}

impl LegacyOperation {
    pub fn new(request_id: u64, role: MigrationRole, guest: u64) -> Self {
        Self {
            mig_request_id: request_id,
            operation: SnpOperationContext::new(
                HostRequestId::new(request_id),
                MigrationId::new(request_id),
                role,
                ManagedGuestHandle::new(guest),
            ),
        }
    }

    pub fn is_src(&self) -> bool {
        self.operation.role == MigrationRole::Source
    }
}

impl Default for LegacyOperation {
    fn default() -> Self {
        Self::new(0, MigrationRole::Source, 0)
    }
}

impl Codec for LegacyOperation {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut used = self.mig_request_id.encode(writer)?;
        used += u8::from(self.is_src()).encode(writer)?;
        used += self.operation.managed_guest.value().encode(writer)?;
        Ok(used)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let id = u64::read(reader)?;
        let role = MigrationRole::try_from(u8::read(reader)?).ok()?;
        Some(Self::new(id, role, u64::read(reader)?))
    }
}

#[derive(Debug)]
pub struct LogRequest {
    pub mig_request_id: u64,
    pub log_max_level: u8,
    pub reserved: [u8; 7],
}

#[derive(Debug)]
pub struct HealthRequest {
    pub mig_request_id: u64,
    pub reportdata: [u8; 64],
}

#[derive(Debug)]
pub enum HostRequest {
    EnableLogArea(LogRequest),
    GetTdReport(HealthRequest),
    StartMigration(LegacyOperation),
}

pub fn decode_legacy_start(id: u64, data: &[u8]) -> Result<LegacyOperation, MigrationResult> {
    if data.len() != 48 || data[1..8].iter().any(|byte| *byte != 0) {
        eprintln!("[MA] legacy StartMigration has invalid length, init-data or reserved fields");
        return Err(MigrationResult::InvalidParameter);
    }
    let role = MigrationRole::try_from(data[0]).map_err(|_| {
        eprintln!("[MA] legacy StartMigration has invalid role");
        MigrationResult::InvalidParameter
    })?;
    let guest = u64::from_le_bytes(data[40..48].try_into().unwrap());
    eprintln!("[MA] LEGACY_HOST_LIMITATION: TD identifier bytes are compatibility-only; no tenant authorization");
    Ok(LegacyOperation::new(id, role, guest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_frame_maps_only_untrusted_snp_handles() {
        let mut bytes = [0u8; 48];
        bytes[0] = 1;
        bytes[40..48].copy_from_slice(&0x1234u64.to_le_bytes());
        let operation = decode_legacy_start(71, &bytes).unwrap();
        assert_eq!(operation.operation.request_id.value(), 71);
        assert_eq!(operation.operation.migration_id.value(), 71);
        assert_eq!(operation.operation.role, MigrationRole::Source);
        assert_eq!(operation.operation.managed_guest.value(), 0x1234);
        assert_eq!(operation.operation.policy, None);
        bytes[8..40].fill(0xa5);
        assert_eq!(
            decode_legacy_start(71, &bytes).unwrap().operation,
            operation.operation
        );
    }

    #[test]
    fn invalid_legacy_start_never_becomes_an_operation() {
        for size in [0, 1, 47, 49, 560] {
            assert!(decode_legacy_start(7, &vec![0; size]).is_err());
        }
        for index in 0..8 {
            let mut bytes = [0u8; 48];
            bytes[index] = if index == 0 { 2 } else { 1 };
            assert!(decode_legacy_start(7, &bytes).is_err());
        }
    }
}
