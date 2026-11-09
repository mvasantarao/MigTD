// Copyright (c) 2022-2026 Intel Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Frozen host status codes shared without selecting a platform implementation.

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MigrationResult {
    Success = 0,
    InvalidParameter = 1,
    Unsupported = 2,
    OutOfResource = 3,
    TdxModuleError = 4,
    NetworkError = 5,
    SecureSessionError = 6,
    MutualAttestationError = 7,
    PolicyUnsatisfiedError = 8,
    InvalidPolicyError = 9,
    VmmCanceled = 10,
    VmmInternalError = 11,
    UnsupportedOperationError = 12,
    InitializationError = 0xFF,
}

impl TryFrom<u8> for MigrationResult {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MigrationResult::Success),
            1 => Ok(MigrationResult::InvalidParameter),
            2 => Ok(MigrationResult::Unsupported),
            3 => Ok(MigrationResult::OutOfResource),
            4 => Ok(MigrationResult::TdxModuleError),
            5 => Ok(MigrationResult::NetworkError),
            6 => Ok(MigrationResult::SecureSessionError),
            7 => Ok(MigrationResult::MutualAttestationError),
            8 => Ok(MigrationResult::PolicyUnsatisfiedError),
            9 => Ok(MigrationResult::InvalidPolicyError),
            10 => Ok(MigrationResult::VmmCanceled),
            11 => Ok(MigrationResult::VmmInternalError),
            12 => Ok(MigrationResult::UnsupportedOperationError),
            0xFF => Ok(MigrationResult::InitializationError),
            _ => Err(()),
        }
    }
}
