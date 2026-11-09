// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Canonical MA evidence record for SNP live migration.

use super::{
    evidence_header::{SnpEvidenceHeaderV1, SnpRecordTypeV1},
    policy_identity::PolicyIdentityV1,
    report_data_context::{ReportDataContextV1, SHA384_DIGEST_SIZE},
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};
pub use crate::types::SNP_ATTESTATION_REPORT_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpMaEvidenceV1 {
    pub header: SnpEvidenceHeaderV1,
    pub report_data_context: ReportDataContextV1,
    pub policy_identity: PolicyIdentityV1,
    pub collateral_digest: [u8; SHA384_DIGEST_SIZE],
    pub ma_report: [u8; SNP_ATTESTATION_REPORT_SIZE],
}

impl SnpMaEvidenceV1 {
    pub const ENCODED_SIZE: usize = 1_540;

    fn validate_structure(&self) -> SnpCodecResult<()> {
        if self.header.record_type != SnpRecordTypeV1::MaEvidence
            || self.header.evidence_purpose != self.report_data_context.evidence_purpose
            || self.header.role != self.report_data_context.role
            || self.header.request_id != self.report_data_context.request_id
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        if self.header.record_length != Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }
        self.report_data_context.validate()?;
        Ok(())
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        self.validate_structure()?;
        self.header.encode(writer)?;
        self.report_data_context.encode(writer)?;
        self.policy_identity.encode(writer)?;
        writer.write_bytes(&self.collateral_digest)?;
        writer.write_bytes(&self.ma_report)
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
            collateral_digest: record.read_array()?,
            ma_report: record.read_array()?,
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
        report_data_context::{
            SnpEvidencePurposeV1, SnpMaRoleV1, SnpMigrationAlgorithmV1, TENANT_REPORT_ID_SIZE,
        },
    };

    fn sample_evidence() -> SnpMaEvidenceV1 {
        SnpMaEvidenceV1 {
            header: SnpEvidenceHeaderV1 {
                record_type: SnpRecordTypeV1::MaEvidence,
                record_length: SnpMaEvidenceV1::ENCODED_SIZE as u32,
                request_id: 0x0102_0304_0506_0708,
                role: SnpMaRoleV1::Destination,
                evidence_purpose: SnpEvidencePurposeV1::InterNodeKeyContribution,
                evidence_profile: SnpEvidenceProfileV1::Production,
                tcb_profile: SnpTcbProfileV1::MilanGenoa,
            },
            report_data_context: ReportDataContextV1 {
                evidence_purpose: SnpEvidencePurposeV1::InterNodeKeyContribution,
                role: SnpMaRoleV1::Destination,
                request_id: 0x0102_0304_0506_0708,
                negotiated_migration_version: 1,
                algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
                tenant_binding_id: [0x11; TENANT_REPORT_ID_SIZE],
                th1: [0x22; SHA384_DIGEST_SIZE],
                purpose_binding_digest: [0x33; SHA384_DIGEST_SIZE],
                ma_policy_identity_digest: [0x44; SHA384_DIGEST_SIZE],
            },
            policy_identity: PolicyIdentityV1 {
                policy_digest: [0x44; SHA384_DIGEST_SIZE],
            },
            collateral_digest: [0x55; SHA384_DIGEST_SIZE],
            ma_report: [0x66; SNP_ATTESTATION_REPORT_SIZE],
        }
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let encoded = sample_evidence().encode_exact().unwrap();
        assert_eq!(encoded.len(), SnpMaEvidenceV1::ENCODED_SIZE);
        assert_eq!(
            &encoded[0x000..0x020],
            &sample_evidence().header.encode_exact().unwrap()
        );
        assert_eq!(
            &encoded[0x020..0x0FC],
            &sample_evidence()
                .report_data_context
                .encode_exact()
                .unwrap()
        );
        assert_eq!(
            &encoded[0x0FC..0x134],
            &sample_evidence().policy_identity.encode_exact().unwrap()
        );
        assert_eq!(&encoded[0x134..0x164], &[0x55; SHA384_DIGEST_SIZE]);
        assert_eq!(&encoded[0x164..0x604], &[0x66; SNP_ATTESTATION_REPORT_SIZE]);
    }

    #[test]
    fn exact_round_trip_preserves_evidence() {
        let expected = sample_evidence();
        let encoded = expected.encode_exact().unwrap();
        assert_eq!(SnpMaEvidenceV1::decode_exact(&encoded).unwrap(), expected);
    }

    #[test]
    fn wrong_record_type_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.header.record_type = SnpRecordTypeV1::TenantEvidence;
        assert_eq!(
            evidence.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x0A..0x0C]
            .copy_from_slice(&(SnpRecordTypeV1::TenantEvidence as u16).to_le_bytes());
        assert_eq!(
            SnpMaEvidenceV1::decode_exact(&encoded),
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
            .copy_from_slice(&((SnpMaEvidenceV1::ENCODED_SIZE - 1) as u32).to_le_bytes());
        assert_eq!(
            SnpMaEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidLength)
        );
    }

    #[test]
    fn wrong_evidence_purpose_is_rejected() {
        let mut evidence = sample_evidence();
        evidence.header.evidence_purpose = SnpEvidencePurposeV1::InterNodeTenantAuthorization;
        assert_eq!(
            evidence.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x19] = SnpEvidencePurposeV1::InterNodeTenantAuthorization as u8;
        assert_eq!(
            SnpMaEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn malformed_nested_records_are_rejected() {
        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x020] ^= 1;
        assert_eq!(
            SnpMaEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidMagic)
        );

        let mut encoded = sample_evidence().encode_exact().unwrap();
        encoded[0x0FE] = 1;
        assert_eq!(
            SnpMaEvidenceV1::decode_exact(&encoded),
            Err(SnpCodecError::NonZeroReservedField)
        );
    }

    #[test]
    fn truncated_and_trailing_input_are_rejected() {
        let encoded = sample_evidence().encode_exact().unwrap();
        assert_eq!(
            SnpMaEvidenceV1::decode_exact(&encoded[..encoded.len() - 1]),
            Err(SnpCodecError::Truncated)
        );

        let mut extended = [0u8; SnpMaEvidenceV1::ENCODED_SIZE + 1];
        extended[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            SnpMaEvidenceV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }

    #[test]
    fn header_and_context_request_role_and_purpose_must_match() {
        for offset in [0x10, 0x18, 0x19] {
            let mut encoded = sample_evidence().encode_exact().unwrap();
            encoded[offset] ^= if offset == 0x19 { 3 } else { 1 };
            assert_eq!(
                SnpMaEvidenceV1::decode_exact(&encoded),
                Err(SnpCodecError::NonCanonicalEncoding)
            );
        }
        for field in 0..3 {
            let mut evidence = sample_evidence();
            match field {
                0 => evidence.header.request_id ^= 1,
                1 => evidence.header.role = SnpMaRoleV1::Source,
                _ => {
                    evidence.header.evidence_purpose =
                        SnpEvidencePurposeV1::InterNodeTenantAuthorization
                }
            }
            assert_eq!(
                evidence.encode_exact(),
                Err(SnpCodecError::NonCanonicalEncoding)
            );
        }
    }

    #[test]
    fn all_frozen_ma_purposes_use_the_same_envelope() {
        for purpose in [
            SnpEvidencePurposeV1::InterNodeKeyContribution,
            SnpEvidencePurposeV1::InterNodeTenantAuthorization,
            SnpEvidencePurposeV1::InterNodePostInstallConfirmation,
            SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
            SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization,
        ] {
            let mut evidence = sample_evidence();
            let context = &mut evidence.report_data_context;
            context.evidence_purpose = purpose;
            context.role = if purpose as u8 >= 4 {
                SnpMaRoleV1::Incoming
            } else {
                SnpMaRoleV1::Destination
            };
            if purpose as u8 >= 4 {
                context.tenant_binding_id.fill(0);
                context.negotiated_migration_version = 1;
                context.algorithm =
                    if purpose == SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization {
                        SnpMigrationAlgorithmV1::LocalHandoffSecretV1
                    } else {
                        context.th1.fill(0);
                        SnpMigrationAlgorithmV1::None
                    };
            }
            evidence.header.evidence_purpose = context.evidence_purpose;
            evidence.header.role = context.role;
            let encoded = evidence.encode_exact().unwrap();
            assert_eq!(SnpMaEvidenceV1::decode_exact(&encoded).unwrap(), evidence);
            assert_eq!(encoded.len(), 1540);
        }
    }
}
