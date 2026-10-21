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
    MaKeyContribution = 0x01,
    TenantMigrationAuthorization = 0x02,
    PostInstallConfirmation = 0x03,
}

impl SnpEvidencePurposeV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x01 => Ok(Self::MaKeyContribution),
            0x02 => Ok(Self::TenantMigrationAuthorization),
            0x03 => Ok(Self::PostInstallConfirmation),
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
}

impl SnpMaRoleV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x00 => Ok(Self::Source),
            0x01 => Ok(Self::Destination),
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
    Aes256Gcm = 0x0003,
}

impl SnpMigrationAlgorithmV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u16()? {
            0x0003 => Ok(Self::Aes256Gcm),
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
    pub tenant_report_id: [u8; TENANT_REPORT_ID_SIZE],
    pub th1: [u8; SHA384_DIGEST_SIZE],
    pub contribution_commitment: [u8; SHA384_DIGEST_SIZE],
    pub local_policy_digest: [u8; SHA384_DIGEST_SIZE],
}

impl ReportDataContextV1 {
    pub const DOMAIN: [u8; 28] = *b"AMD-SNP-MA-LM-REPORT-DATA-V1";
    pub const CONTEXT_VERSION: u16 = 1;
    pub const ENCODED_SIZE: usize = 220;

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_bytes(&Self::DOMAIN)?;
        writer.write_u16(Self::CONTEXT_VERSION)?;
        self.evidence_purpose.encode(writer)?;
        self.role.encode(writer)?;
        writer.write_u64(self.request_id)?;
        writer.write_u16(self.negotiated_migration_version)?;
        self.algorithm.encode(writer)?;
        writer.write_bytes(&self.tenant_report_id)?;
        writer.write_bytes(&self.th1)?;
        writer.write_bytes(&self.contribution_commitment)?;
        writer.write_bytes(&self.local_policy_digest)
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
            tenant_report_id: record.read_array()?,
            th1: record.read_array()?,
            contribution_commitment: record.read_array()?,
            local_policy_digest: record.read_array()?,
        };
        record.finish()?;
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
            evidence_purpose: SnpEvidencePurposeV1::TenantMigrationAuthorization,
            role: SnpMaRoleV1::Source,
            request_id: 0x0102_0304_0506_0708,
            negotiated_migration_version: 0x090A,
            algorithm: SnpMigrationAlgorithmV1::Aes256Gcm,
            tenant_report_id: [0x11; TENANT_REPORT_ID_SIZE],
            th1: [0x22; SHA384_DIGEST_SIZE],
            contribution_commitment: [0x33; SHA384_DIGEST_SIZE],
            local_policy_digest: [0x44; SHA384_DIGEST_SIZE],
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
        encoded[0x01F] = 2;
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
}
