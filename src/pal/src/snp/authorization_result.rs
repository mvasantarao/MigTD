// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Canonical SNP tenant-migration authorization result.

use super::{
    evidence_header::{SnpEvidenceProfileV1, SnpRecordTypeV1, SnpTcbProfileV1},
    report_data_context::{SnpMaRoleV1, SnpMigrationAlgorithmV1, SHA384_DIGEST_SIZE},
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpAuthorizationDecisionV1 {
    Accepted = 0x01,
    Rejected = 0x02,
}

impl SnpAuthorizationDecisionV1 {
    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x01 => Ok(Self::Accepted),
            0x02 => Ok(Self::Rejected),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u8(self as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SnpAuthorizationFailureV1 {
    None = 0x0000,
    MalformedMessage = 0x0001,
    UnsupportedVersion = 0x0002,
    UnexpectedMessage = 0x0003,
    ResourceLimitExceeded = 0x0004,
    TrustProfileNotAllowed = 0x0005,
    UnsupportedAlgorithm = 0x0006,
    EvidenceInvalid = 0x0007,
    CollateralInvalid = 0x0008,
    ReportVerificationFailed = 0x0009,
    ReportDataBindingFailed = 0x000A,
    IdentityBindingFailed = 0x000B,
    PolicyDenied = 0x000C,
    TcbPolicyDenied = 0x000D,
    MigrationHistoryDenied = 0x000E,
    ReplayDetected = 0x000F,
    ProtocolStateViolation = 0x0010,
    InternalError = 0x0011,
}

impl SnpAuthorizationFailureV1 {
    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u16()? {
            0x0000 => Ok(Self::None),
            0x0001 => Ok(Self::MalformedMessage),
            0x0002 => Ok(Self::UnsupportedVersion),
            0x0003 => Ok(Self::UnexpectedMessage),
            0x0004 => Ok(Self::ResourceLimitExceeded),
            0x0005 => Ok(Self::TrustProfileNotAllowed),
            0x0006 => Ok(Self::UnsupportedAlgorithm),
            0x0007 => Ok(Self::EvidenceInvalid),
            0x0008 => Ok(Self::CollateralInvalid),
            0x0009 => Ok(Self::ReportVerificationFailed),
            0x000A => Ok(Self::ReportDataBindingFailed),
            0x000B => Ok(Self::IdentityBindingFailed),
            0x000C => Ok(Self::PolicyDenied),
            0x000D => Ok(Self::TcbPolicyDenied),
            0x000E => Ok(Self::MigrationHistoryDenied),
            0x000F => Ok(Self::ReplayDetected),
            0x0010 => Ok(Self::ProtocolStateViolation),
            0x0011 => Ok(Self::InternalError),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u16(self as u16)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpAuthorizationResultV1 {
    pub request_id: u64,
    pub decision: SnpAuthorizationDecisionV1,
    pub evidence_profile: SnpEvidenceProfileV1,
    pub tcb_profile: SnpTcbProfileV1,
    pub failure: SnpAuthorizationFailureV1,
    pub algorithm: SnpMigrationAlgorithmV1,
    pub negotiated_migration_version: u16,
    pub authorization_context_digest: [u8; SHA384_DIGEST_SIZE],
}

impl SnpAuthorizationResultV1 {
    pub const MAGIC: [u8; 8] = *b"SNP-LM-A";
    pub const MAJOR_VERSION: u8 = 1;
    pub const MINOR_VERSION: u8 = 0;
    pub const ENCODED_SIZE: usize = 88;

    fn validate_decision(&self) -> SnpCodecResult<()> {
        if self.algorithm != SnpMigrationAlgorithmV1::Aes256GcmMigrationV1 {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        match (self.decision, self.failure) {
            (SnpAuthorizationDecisionV1::Accepted, SnpAuthorizationFailureV1::None) => Ok(()),
            (SnpAuthorizationDecisionV1::Rejected, failure)
                if failure != SnpAuthorizationFailureV1::None =>
            {
                Ok(())
            }
            _ => Err(SnpCodecError::NonCanonicalEncoding),
        }
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        self.validate_decision()?;
        writer.write_bytes(&Self::MAGIC)?;
        writer.write_u8(Self::MAJOR_VERSION)?;
        writer.write_u8(Self::MINOR_VERSION)?;
        SnpRecordTypeV1::AuthorizationResult.encode(writer)?;
        writer.write_u32(Self::ENCODED_SIZE as u32)?;
        writer.write_u64(self.request_id)?;
        self.decision.encode(writer)?;
        SnpMaRoleV1::Destination.encode(writer)?;
        self.evidence_profile.encode(writer)?;
        self.tcb_profile.encode(writer)?;
        self.failure.encode(writer)?;
        self.algorithm.encode(writer)?;
        writer.write_u16(self.negotiated_migration_version)?;
        writer.write_zeroes(6)?;
        writer.write_bytes(&self.authorization_context_digest)
    }

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        let mut encoded = [0u8; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut encoded);
        self.encode(&mut writer)?;
        if writer.written() != Self::ENCODED_SIZE {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        let mut record = reader.sub(Self::ENCODED_SIZE)?;
        if record.read_array::<8>()? != Self::MAGIC {
            return Err(SnpCodecError::InvalidMagic);
        }
        if record.read_u8()? != Self::MAJOR_VERSION || record.read_u8()? != Self::MINOR_VERSION {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        if SnpRecordTypeV1::decode(&mut record)? != SnpRecordTypeV1::AuthorizationResult {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        if record.read_u32()? != Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }

        let request_id = record.read_u64()?;
        let decision = SnpAuthorizationDecisionV1::decode(&mut record)?;
        if SnpMaRoleV1::decode(&mut record)? != SnpMaRoleV1::Destination {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        let value = Self {
            request_id,
            decision,
            evidence_profile: SnpEvidenceProfileV1::decode(&mut record)?,
            tcb_profile: SnpTcbProfileV1::decode(&mut record)?,
            failure: SnpAuthorizationFailureV1::decode(&mut record)?,
            algorithm: SnpMigrationAlgorithmV1::decode(&mut record)?,
            negotiated_migration_version: record.read_u16()?,
            authorization_context_digest: {
                record.read_zeroes(6)?;
                record.read_array()?
            },
        };
        record.finish()?;
        value.validate_decision()?;
        Ok(value)
    }

    pub fn decode_exact(encoded: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(encoded);
        let value = Self::decode(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted_result() -> SnpAuthorizationResultV1 {
        SnpAuthorizationResultV1 {
            request_id: 0x0102_0304_0506_0708,
            decision: SnpAuthorizationDecisionV1::Accepted,
            evidence_profile: SnpEvidenceProfileV1::Production,
            tcb_profile: SnpTcbProfileV1::Turin,
            failure: SnpAuthorizationFailureV1::None,
            algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            negotiated_migration_version: 0x090A,
            authorization_context_digest: [0x55; SHA384_DIGEST_SIZE],
        }
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let encoded = accepted_result().encode_exact().unwrap();
        assert_eq!(&encoded[0x00..0x08], &SnpAuthorizationResultV1::MAGIC);
        assert_eq!(&encoded[0x08..0x0A], &[1, 0]);
        assert_eq!(&encoded[0x0A..0x0C], &[4, 0]);
        assert_eq!(&encoded[0x0C..0x10], &88u32.to_le_bytes());
        assert_eq!(
            &encoded[0x10..0x18],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&encoded[0x18..0x1C], &[1, 1, 1, 2]);
        assert_eq!(&encoded[0x1C..0x1E], &[0, 0]);
        assert_eq!(&encoded[0x1E..0x20], &[3, 0]);
        assert_eq!(&encoded[0x20..0x22], &[0x0A, 0x09]);
        assert_eq!(&encoded[0x22..0x28], &[0; 6]);
        assert_eq!(&encoded[0x28..0x58], &[0x55; SHA384_DIGEST_SIZE]);
    }

    #[test]
    fn local_algorithms_cannot_leak_into_inter_node_authorization_results() {
        for algorithm in [
            SnpMigrationAlgorithmV1::None,
            SnpMigrationAlgorithmV1::LocalHandoffSecretV1,
        ] {
            let mut value = accepted_result();
            value.algorithm = algorithm;
            assert_eq!(
                value.encode_exact(),
                Err(SnpCodecError::NonCanonicalEncoding)
            );
            let mut encoded = accepted_result().encode_exact().unwrap();
            encoded[0x1e..0x20].copy_from_slice(&(algorithm as u16).to_le_bytes());
            assert_eq!(
                SnpAuthorizationResultV1::decode_exact(&encoded),
                Err(SnpCodecError::NonCanonicalEncoding)
            );
        }
    }

    #[test]
    fn accepted_and_rejected_results_round_trip() {
        let accepted = accepted_result();
        let encoded = accepted.encode_exact().unwrap();
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded).unwrap(),
            accepted
        );

        let mut rejected = accepted_result();
        rejected.decision = SnpAuthorizationDecisionV1::Rejected;
        rejected.failure = SnpAuthorizationFailureV1::PolicyDenied;
        let encoded = rejected.encode_exact().unwrap();
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded).unwrap(),
            rejected
        );
    }

    #[test]
    fn inconsistent_decision_and_failure_are_rejected() {
        let mut result = accepted_result();
        result.failure = SnpAuthorizationFailureV1::InternalError;
        assert_eq!(
            result.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );

        let mut result = accepted_result();
        result.decision = SnpAuthorizationDecisionV1::Rejected;
        assert_eq!(
            result.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );

        let mut encoded = accepted_result().encode_exact().unwrap();
        encoded[0x1C..0x1E]
            .copy_from_slice(&(SnpAuthorizationFailureV1::InternalError as u16).to_le_bytes());
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn non_destination_role_is_rejected() {
        let mut encoded = accepted_result().encode_exact().unwrap();
        encoded[0x19] = SnpMaRoleV1::Source as u8;
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn malformed_header_and_reserved_bytes_are_rejected() {
        let mut encoded = accepted_result().encode_exact().unwrap();
        encoded[0] ^= 1;
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidMagic)
        );

        let mut encoded = accepted_result().encode_exact().unwrap();
        encoded[0x0C..0x10].copy_from_slice(&87u32.to_le_bytes());
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidLength)
        );

        let mut encoded = accepted_result().encode_exact().unwrap();
        encoded[0x22] = 1;
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded),
            Err(SnpCodecError::NonZeroReservedField)
        );
    }

    #[test]
    fn unknown_decision_failure_and_algorithm_are_rejected() {
        for (offset, value) in [(0x18, 0u8), (0x1C, 0x12u8), (0x1E, 1u8)] {
            let mut encoded = accepted_result().encode_exact().unwrap();
            encoded[offset] = value;
            assert_eq!(
                SnpAuthorizationResultV1::decode_exact(&encoded),
                Err(SnpCodecError::UnknownEnumValue)
            );
        }
    }

    #[test]
    fn unknown_evidence_and_tcb_profiles_are_rejected() {
        for offset in [0x1A, 0x1B] {
            let mut encoded = accepted_result().encode_exact().unwrap();
            encoded[offset] = 0xFF;
            assert_eq!(
                SnpAuthorizationResultV1::decode_exact(&encoded),
                Err(SnpCodecError::UnknownEnumValue)
            );
        }
    }

    #[test]
    fn truncated_and_trailing_input_are_rejected() {
        let encoded = accepted_result().encode_exact().unwrap();
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded[..encoded.len() - 1]),
            Err(SnpCodecError::Truncated)
        );

        let mut extended = [0u8; SnpAuthorizationResultV1::ENCODED_SIZE + 1];
        extended[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }
}
