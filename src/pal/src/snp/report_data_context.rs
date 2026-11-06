// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Canonical SNP migration report-data context.

use super::wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter};

pub const SHA384_DIGEST_SIZE: usize = 48;
pub const TENANT_REPORT_ID_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpEvidencePurposeV1 {
    InterNodeKeyContribution = 0x01,
    InterNodeTenantAuthorization = 0x02,
    InterNodePostInstallConfirmation = 0x03,
    LocalPlannedHandoffAuthorization = 0x04,
    LocalRecoveryHandoffAuthorization = 0x05,
    InterNodeSessionV2 = 0x06,
    InterNodeTenantAuthorizationV2 = 0x07,
}

impl SnpEvidencePurposeV1 {
    pub fn validate_role(self, role: SnpMaRoleV1) -> SnpCodecResult<()> {
        use SnpMaRoleV1::*;
        let legal = match self {
            Self::InterNodeKeyContribution
            | Self::InterNodeTenantAuthorization
            | Self::InterNodeSessionV2
            | Self::InterNodeTenantAuthorizationV2 => {
                matches!(role, Source | Destination)
            }
            Self::InterNodePostInstallConfirmation => role == Destination,
            Self::LocalPlannedHandoffAuthorization => matches!(role, Outgoing | Incoming),
            Self::LocalRecoveryHandoffAuthorization => role == Incoming,
        };
        if !legal {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x01 => Ok(Self::InterNodeKeyContribution),
            0x02 => Ok(Self::InterNodeTenantAuthorization),
            0x03 => Ok(Self::InterNodePostInstallConfirmation),
            0x04 => Ok(Self::LocalPlannedHandoffAuthorization),
            0x05 => Ok(Self::LocalRecoveryHandoffAuthorization),
            0x06 => Ok(Self::InterNodeSessionV2),
            0x07 => Ok(Self::InterNodeTenantAuthorizationV2),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    pub(crate) fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u8(self as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpMaRoleV1 {
    Source = 0x00,
    Destination = 0x01,
    Outgoing = 0x02,
    Incoming = 0x03,
}

impl SnpMaRoleV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x00 => Ok(Self::Source),
            0x01 => Ok(Self::Destination),
            0x02 => Ok(Self::Outgoing),
            0x03 => Ok(Self::Incoming),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    pub(crate) fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u8(self as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SnpMigrationAlgorithmV1 {
    None = 0x0000,
    Aes256GcmMigrationV1 = 0x0003,
    LocalHandoffSecretV1 = 0x0004,
}

impl SnpMigrationAlgorithmV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u16()? {
            0x0000 => Ok(Self::None),
            0x0003 => Ok(Self::Aes256GcmMigrationV1),
            0x0004 => Ok(Self::LocalHandoffSecretV1),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    pub(crate) fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u16(self as u16)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDataContextV1 {
    pub evidence_purpose: SnpEvidencePurposeV1,
    pub role: SnpMaRoleV1,
    pub request_id: u64,
    pub negotiated_migration_version: u16,
    pub algorithm: SnpMigrationAlgorithmV1,
    pub tenant_binding_id: [u8; TENANT_REPORT_ID_SIZE],
    pub th1: [u8; SHA384_DIGEST_SIZE],
    pub purpose_binding_digest: [u8; SHA384_DIGEST_SIZE],
    pub ma_policy_identity_digest: [u8; SHA384_DIGEST_SIZE],
}

impl ReportDataContextV1 {
    pub const DOMAIN: [u8; 28] = *b"AMD-SNP-MA-LM-REPORT-DATA-V1";
    pub const CONTEXT_VERSION: u16 = 1;
    pub const ENCODED_SIZE: usize = 220;

    pub fn validate(&self) -> SnpCodecResult<()> {
        use SnpEvidencePurposeV1::*;
        use SnpMigrationAlgorithmV1::*;
        self.evidence_purpose.validate_role(self.role)?;
        let legal = match self.evidence_purpose {
            InterNodeKeyContribution
            | InterNodeTenantAuthorization
            | InterNodeSessionV2
            | InterNodeTenantAuthorizationV2
            | InterNodePostInstallConfirmation => self.algorithm == Aes256GcmMigrationV1,
            LocalPlannedHandoffAuthorization => {
                self.algorithm == LocalHandoffSecretV1
                    && self.negotiated_migration_version == 1
                    && self.tenant_binding_id == [0; TENANT_REPORT_ID_SIZE]
            }
            LocalRecoveryHandoffAuthorization => {
                self.algorithm == None
                    && self.negotiated_migration_version == 1
                    && self.tenant_binding_id == [0; TENANT_REPORT_ID_SIZE]
                    && self.th1 == [0; SHA384_DIGEST_SIZE]
            }
        };
        if !legal {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn expected_report_data(&self) -> SnpCodecResult<[u8; 64]> {
        let digest = super::purpose_binding::sha384(&self.encode_exact()?);
        let mut expected = [0u8; 64];
        expected[..SHA384_DIGEST_SIZE].copy_from_slice(&digest);
        Ok(expected)
    }

    pub fn verify_report_data(&self, report_data: &[u8; 64]) -> SnpCodecResult<()> {
        if *report_data != self.expected_report_data()? {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    /// The expected context must be constructed from local trusted state, not peer input.
    pub fn verify_ma_evidence(
        &self,
        verifier: &dyn crate::traits::SnpEvidenceVerifier,
        evidence: &crate::types::MaEvidence,
        collateral: &crate::types::SnpVerificationCollateral,
        expected_vmpl: u32,
        trust: crate::types::SnpVerifierTrust,
    ) -> Result<crate::types::VerifiedSnpEvidence, crate::types::SnpVerificationError> {
        use crate::types::{
            MaEvidenceBinding, SnpEvidenceVerificationRequest, SnpReportRequestKind,
            SnpVerificationError,
        };
        if evidence.binding() != MaEvidenceBinding::RequestedReportData {
            return Err(SnpVerificationError::InvalidEvidence);
        }
        let expected = self
            .expected_report_data()
            .map_err(|_| SnpVerificationError::ReportDataBinding)?;
        let mut digest = [0u8; SHA384_DIGEST_SIZE];
        digest.copy_from_slice(&expected[..SHA384_DIGEST_SIZE]);
        let report_request = SnpReportRequestKind::GuestRequestedMa { expected_vmpl };
        let params = super::qvl::validate::AttestationVerificationParams::for_request(
            evidence.report(),
            &digest,
            report_request,
        );
        super::qvl::validate::validate(&params)
            .map_err(|_| SnpVerificationError::ReportDataBinding)?;
        let verified = verifier.verify_evidence(&SnpEvidenceVerificationRequest {
            evidence,
            collateral,
            expected_report_data: &digest,
            report_request,
            trust,
        })?;
        if verified.trust != trust {
            return Err(SnpVerificationError::UnsupportedTrust);
        }
        if verified.binding != evidence.binding() {
            return Err(SnpVerificationError::InvalidEvidence);
        }
        Ok(verified)
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        self.validate()?;
        writer.write_bytes(&Self::DOMAIN)?;
        writer.write_u16(Self::CONTEXT_VERSION)?;
        self.evidence_purpose.encode(writer)?;
        self.role.encode(writer)?;
        writer.write_u64(self.request_id)?;
        writer.write_u16(self.negotiated_migration_version)?;
        self.algorithm.encode(writer)?;
        writer.write_bytes(&self.tenant_binding_id)?;
        writer.write_bytes(&self.th1)?;
        writer.write_bytes(&self.purpose_binding_digest)?;
        writer.write_bytes(&self.ma_policy_identity_digest)
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
        if record.read_array::<28>()? != Self::DOMAIN {
            return Err(SnpCodecError::InvalidMagic);
        }
        if record.read_u16()? != Self::CONTEXT_VERSION {
            return Err(SnpCodecError::UnsupportedVersion);
        }

        let value = Self {
            evidence_purpose: SnpEvidencePurposeV1::decode(&mut record)?,
            role: SnpMaRoleV1::decode(&mut record)?,
            request_id: record.read_u64()?,
            negotiated_migration_version: record.read_u16()?,
            algorithm: SnpMigrationAlgorithmV1::decode(&mut record)?,
            tenant_binding_id: record.read_array()?,
            th1: record.read_array()?,
            purpose_binding_digest: record.read_array()?,
            ma_policy_identity_digest: record.read_array()?,
        };
        record.finish()?;
        value.validate()?;
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

    fn sample_context() -> ReportDataContextV1 {
        ReportDataContextV1 {
            evidence_purpose: SnpEvidencePurposeV1::InterNodeTenantAuthorization,
            role: SnpMaRoleV1::Source,
            request_id: 0x0102_0304_0506_0708,
            negotiated_migration_version: 0x090A,
            algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            tenant_binding_id: [0x11; TENANT_REPORT_ID_SIZE],
            th1: [0x22; SHA384_DIGEST_SIZE],
            purpose_binding_digest: [0x33; SHA384_DIGEST_SIZE],
            ma_policy_identity_digest: [0x44; SHA384_DIGEST_SIZE],
        }
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let encoded = sample_context().encode_exact().unwrap();
        assert_eq!(encoded.len(), ReportDataContextV1::ENCODED_SIZE);
        assert_eq!(&encoded[0x000..0x01C], &ReportDataContextV1::DOMAIN);
        assert_eq!(&encoded[0x01C..0x01E], &[0x01, 0x00]);
        assert_eq!(encoded[0x01E], 0x02);
        assert_eq!(encoded[0x01F], 0x00);
        assert_eq!(
            &encoded[0x020..0x028],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&encoded[0x028..0x02A], &[0x0A, 0x09]);
        assert_eq!(&encoded[0x02A..0x02C], &[0x03, 0x00]);
        assert_eq!(&encoded[0x02C..0x04C], &[0x11; TENANT_REPORT_ID_SIZE]);
        assert_eq!(&encoded[0x04C..0x07C], &[0x22; SHA384_DIGEST_SIZE]);
        assert_eq!(&encoded[0x07C..0x0AC], &[0x33; SHA384_DIGEST_SIZE]);
        assert_eq!(&encoded[0x0AC..0x0DC], &[0x44; SHA384_DIGEST_SIZE]);
    }

    #[test]
    fn exact_round_trip_preserves_context() {
        let expected = sample_context();
        let encoded = expected.encode_exact().unwrap();
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded).unwrap(),
            expected
        );
    }

    #[test]
    fn invalid_domain_is_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0] ^= 1;
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidMagic)
        );
    }

    #[test]
    fn unsupported_context_version_is_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0x01C] = 2;
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded),
            Err(SnpCodecError::UnsupportedVersion)
        );
    }

    #[test]
    fn unknown_evidence_purpose_is_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0x01E] = 0;
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded),
            Err(SnpCodecError::UnknownEnumValue)
        );
    }

    #[test]
    fn unknown_role_is_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0x01F] = 4;
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded),
            Err(SnpCodecError::UnknownEnumValue)
        );
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0x02A..0x02C].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded),
            Err(SnpCodecError::UnknownEnumValue)
        );
    }

    #[test]
    fn truncated_context_is_rejected() {
        let encoded = sample_context().encode_exact().unwrap();
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded[..encoded.len() - 1]),
            Err(SnpCodecError::Truncated)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let encoded = sample_context().encode_exact().unwrap();
        let mut extended = [0u8; ReportDataContextV1::ENCODED_SIZE + 1];
        extended[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            ReportDataContextV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }

    #[test]
    fn every_registered_purpose_role_algorithm_combination_is_checked_on_both_paths() {
        use SnpEvidencePurposeV1::*;
        use SnpMaRoleV1::*;
        use SnpMigrationAlgorithmV1::*;
        let purposes = [
            InterNodeKeyContribution,
            InterNodeTenantAuthorization,
            InterNodePostInstallConfirmation,
            LocalPlannedHandoffAuthorization,
            LocalRecoveryHandoffAuthorization,
        ];
        let mut accepted = 0;
        for purpose in purposes {
            for role in [Source, Destination, Outgoing, Incoming] {
                for algorithm in [None, Aes256GcmMigrationV1, LocalHandoffSecretV1] {
                    let mut value = sample_context();
                    value.evidence_purpose = purpose;
                    value.role = role;
                    value.algorithm = algorithm;
                    value.negotiated_migration_version = 1;
                    if purpose as u8 >= 4 {
                        value.tenant_binding_id.fill(0);
                    }
                    if purpose == LocalRecoveryHandoffAuthorization {
                        value.th1.fill(0);
                    }
                    let legal = matches!(
                        (purpose, role, algorithm),
                        (
                            InterNodeKeyContribution | InterNodeTenantAuthorization,
                            Source | Destination,
                            Aes256GcmMigrationV1
                        ) | (
                            InterNodePostInstallConfirmation,
                            Destination,
                            Aes256GcmMigrationV1
                        ) | (
                            LocalPlannedHandoffAuthorization,
                            Outgoing | Incoming,
                            LocalHandoffSecretV1
                        ) | (LocalRecoveryHandoffAuthorization, Incoming, None)
                    );
                    assert_eq!(value.encode_exact().is_ok(), legal);
                    let mut encoded = sample_context().encode_exact().unwrap();
                    encoded[0x1e] = purpose as u8;
                    encoded[0x1f] = role as u8;
                    encoded[0x28..0x2a].copy_from_slice(&1u16.to_le_bytes());
                    encoded[0x2a..0x2c].copy_from_slice(&(algorithm as u16).to_le_bytes());
                    encoded[0x2c..0x4c].copy_from_slice(&value.tenant_binding_id);
                    encoded[0x4c..0x7c].copy_from_slice(&value.th1);
                    assert_eq!(ReportDataContextV1::decode_exact(&encoded).is_ok(), legal);
                    accepted += usize::from(legal);
                }
            }
        }
        assert_eq!(accepted, 8);
    }

    #[test]
    fn local_context_version_tenant_and_recovery_transcript_are_canonical() {
        for purpose in [
            SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
            SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization,
        ] {
            let mut context = sample_context();
            context.evidence_purpose = purpose;
            context.role = SnpMaRoleV1::Incoming;
            context.algorithm = if purpose == SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization
            {
                SnpMigrationAlgorithmV1::LocalHandoffSecretV1
            } else {
                SnpMigrationAlgorithmV1::None
            };
            context.negotiated_migration_version = 1;
            context.tenant_binding_id.fill(0);
            context.th1.fill(0);
            let encoded = context.encode_exact().unwrap();
            for offset in [0x28, 0x2c, 0x4b] {
                let mut changed = encoded;
                changed[offset] ^= 1;
                assert!(ReportDataContextV1::decode_exact(&changed).is_err());
            }
            if purpose == SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization {
                for offset in 0x4c..0x7c {
                    let mut changed = encoded;
                    changed[offset] = 1;
                    assert!(ReportDataContextV1::decode_exact(&changed).is_err());
                }
            }
        }
    }

    #[test]
    fn every_context_byte_mutation_rejects_or_changes_all_byte_report_binding() {
        let context = sample_context();
        let encoded = context.encode_exact().unwrap();
        let expected = context.expected_report_data().unwrap();
        for offset in 0..encoded.len() {
            let mut changed = encoded;
            changed[offset] ^= 1;
            if let Ok(decoded) = ReportDataContextV1::decode_exact(&changed) {
                assert_ne!(decoded.expected_report_data().unwrap(), expected);
                assert!(decoded.verify_report_data(&expected).is_err());
            }
        }
        context.verify_report_data(&expected).unwrap();
        for offset in 0..64 {
            let mut changed = expected;
            changed[offset] ^= 1;
            assert!(context.verify_report_data(&changed).is_err());
        }
    }

    #[test]
    fn unknown_numeric_registry_values_fail_closed() {
        let encoded = sample_context().encode_exact().unwrap();
        for purpose in [0].into_iter().chain(8..=u8::MAX) {
            let mut changed = encoded;
            changed[0x1e] = purpose;
            assert_eq!(
                ReportDataContextV1::decode_exact(&changed),
                Err(SnpCodecError::UnknownEnumValue)
            );
        }
        for role in 4..=u8::MAX {
            let mut changed = encoded;
            changed[0x1f] = role;
            assert_eq!(
                ReportDataContextV1::decode_exact(&changed),
                Err(SnpCodecError::UnknownEnumValue)
            );
        }
        for algorithm in 0..=u16::MAX {
            if matches!(algorithm, 0 | 3 | 4) {
                continue;
            }
            let mut changed = encoded;
            changed[0x2a..0x2c].copy_from_slice(&algorithm.to_le_bytes());
            assert_eq!(
                ReportDataContextV1::decode_exact(&changed),
                Err(SnpCodecError::UnknownEnumValue)
            );
        }
    }
}
