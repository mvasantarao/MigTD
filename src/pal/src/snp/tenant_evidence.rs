// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Canonical tenant evidence record for SNP live migration.

use super::{
    evidence_header::{SnpEvidenceHeaderV1, SnpRecordTypeV1},
    ma_evidence::SNP_ATTESTATION_REPORT_SIZE,
    policy_identity::PolicyIdentityV1,
    report_data_context::{
        ReportDataContextV1, SnpEvidencePurposeV1, SnpMaRoleV1, SHA384_DIGEST_SIZE,
    },
    tenant_policy_context::TenantPolicyContextV1,
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpTenantEvidenceV1 {
    pub header: SnpEvidenceHeaderV1,
    pub report_data_context: ReportDataContextV1,
    pub policy_identity: PolicyIdentityV1,
    pub tenant_policy_context: TenantPolicyContextV1,
    pub collateral_digest: [u8; SHA384_DIGEST_SIZE],
    pub tenant_report: [u8; SNP_ATTESTATION_REPORT_SIZE],
}

impl SnpTenantEvidenceV1 {
    pub const ENCODED_SIZE: usize = 1_556;

    fn validate_structure(&self) -> SnpCodecResult<()> {
        if self.header.record_type != SnpRecordTypeV1::TenantEvidence
            || self.header.evidence_purpose != SnpEvidencePurposeV1::TenantMigrationAuthorization
            || self.header.role != SnpMaRoleV1::Source
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        if self.header.record_length != Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }
        Ok(())
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        self.validate_structure()?;
        self.header.encode(writer)?;
        self.report_data_context.encode(writer)?;
        self.policy_identity.encode(writer)?;
        self.tenant_policy_context.encode(writer)?;
        writer.write_bytes(&self.collateral_digest)?;
        writer.write_bytes(&self.tenant_report)
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
        let value = Self {
            header: SnpEvidenceHeaderV1::decode(&mut record)?,
            report_data_context: ReportDataContextV1::decode(&mut record)?,
            policy_identity: PolicyIdentityV1::decode(&mut record)?,
            tenant_policy_context: TenantPolicyContextV1::decode(&mut record)?,
            collateral_digest: record.read_array()?,
            tenant_report: record.read_array()?,
        };
        record.finish()?;
        value.validate_structure()?;
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
    use crate::snp::{
        evidence_header::{SnpEvidenceProfileV1, SnpTcbProfileV1},
        report_data_context::{SnpMigrationAlgorithmV1, TENANT_REPORT_ID_SIZE},
        tenant_policy_context::SnpEtcbProjectionProfileV1,
    };

    fn sample_evidence() -> SnpTenantEvidenceV1 {
        SnpTenantEvidenceV1 {
            header: SnpEvidenceHeaderV1 {
                record_type: SnpRecordTypeV1::TenantEvidence,
                record_length: SnpTenantEvidenceV1::ENCODED_SIZE as u32,
                request_id: 0x0102_0304_0506_0708,
                role: SnpMaRoleV1::Source,
                evidence_purpose: SnpEvidencePurposeV1::TenantMigrationAuthorization,
                evidence_profile: SnpEvidenceProfileV1::Production,
                tcb_profile: SnpTcbProfileV1::Turin,
            },
            report_data_context: ReportDataContextV1 {
                evidence_purpose: SnpEvidencePurposeV1::TenantMigrationAuthorization,
                role: SnpMaRoleV1::Source,
                request_id: 0x0102_0304_0506_0708,
                negotiated_migration_version: 1,
                algorithm: SnpMigrationAlgorithmV1::Aes256Gcm,
                tenant_report_id: [0x11; TENANT_REPORT_ID_SIZE],
                th1: [0x22; SHA384_DIGEST_SIZE],
                contribution_commitment: [0x33; SHA384_DIGEST_SIZE],
                local_policy_digest: [0x44; SHA384_DIGEST_SIZE],
            },
            policy_identity: PolicyIdentityV1 {
                policy_digest: [0x44; SHA384_DIGEST_SIZE],
            },
            tenant_policy_context: TenantPolicyContextV1 {
                tcb_profile: SnpTcbProfileV1::Turin,
                etcb_projection_profile: SnpEtcbProjectionProfileV1::ArgSvnV1,
            },
            collateral_digest: [0x55; SHA384_DIGEST_SIZE],
            tenant_report: [0x66; SNP_ATTESTATION_REPORT_SIZE],
        }
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let evidence = sample_evidence();
        let encoded = evidence.encode_exact().unwrap();
        assert_eq!(encoded.len(), SnpTenantEvidenceV1::ENCODED_SIZE);
        assert_eq!(
            &encoded[0x000..0x020],
            &evidence.header.encode_exact().unwrap()
        );
        assert_eq!(
            &encoded[0x020..0x0FC],
            &evidence.report_data_context.encode_exact().unwrap()
        );
        assert_eq!(
            &encoded[0x0FC..0x134],
            &evidence.policy_identity.encode_exact().unwrap()
        );
        assert_eq!(
            &encoded[0x134..0x144],
            &evidence.tenant_policy_context.encode_exact().unwrap()
        );
        assert_eq!(&encoded[0x144..0x174], &[0x55; SHA384_DIGEST_SIZE]);
        assert_eq!(&encoded[0x174..0x614], &[0x66; SNP_ATTESTATION_REPORT_SIZE]);
    }

    #[test]
    fn exact_round_trip_preserves_evidence() {
        let expected = sample_evidence();
        let encoded = expected.encode_exact().unwrap();
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded).unwrap(),
            expected
        );
    }

    #[test]
    fn wrong_record_type_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.header.record_type = SnpRecordTypeV1::MaEvidence;
        assert_eq!(
            evidence.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x0A..0x0C].copy_from_slice(&(SnpRecordTypeV1::MaEvidence as u16).to_le_bytes());
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn wrong_record_length_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.header.record_length -= 1;
        assert_eq!(evidence.encode_exact(), Err(SnpCodecError::InvalidLength));

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x0C..0x10]
            .copy_from_slice(&((SnpTenantEvidenceV1::ENCODED_SIZE - 1) as u32).to_le_bytes());
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidLength)
        );
    }

    #[test]
    fn wrong_evidence_purpose_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.header.evidence_purpose = SnpEvidencePurposeV1::MaKeyContribution;
        assert_eq!(
            evidence.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x19] = SnpEvidencePurposeV1::MaKeyContribution as u8;
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn destination_role_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.header.role = SnpMaRoleV1::Destination;
        assert_eq!(
            evidence.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x18] = SnpMaRoleV1::Destination as u8;
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn malformed_nested_contexts_are_rejected() {
        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x04A..0x04C].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::UnknownEnumValue)
        );

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x140..0x144].copy_from_slice(&0x0Fu32.to_le_bytes());
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn truncated_and_trailing_input_are_rejected() {
        let encoded = sample_evidence().encode_exact().unwrap();
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&encoded[..encoded.len() - 1]),
            Err(SnpCodecError::Truncated)
        );

        let mut extended = [0u8; SnpTenantEvidenceV1::ENCODED_SIZE + 1];
        extended[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            SnpTenantEvidenceV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }
}
