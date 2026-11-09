// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Contribution wire codec, not an authenticated exchange or commitment verifier.

use core::fmt;
use zeroize::{Zeroize, Zeroizing};

use super::{
    authorization_result::SnpAuthorizationFailureV1,
    evidence_header::SnpRecordTypeV1,
    report_data_context::{ReportDataContextV1, SnpEvidencePurposeV1},
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

pub const SNP_KEY_CONTRIBUTION_SIZE: usize = 32;

pub struct SnpKeyContributionV1 {
    pub report_data_context: ReportDataContextV1,
    contribution: Zeroizing<[u8; SNP_KEY_CONTRIBUTION_SIZE]>,
}

impl fmt::Debug for SnpKeyContributionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnpKeyContributionV1")
            .field("report_data_context", &self.report_data_context)
            .field("contribution", &"<redacted>")
            .finish()
    }
}

impl SnpKeyContributionV1 {
    pub const MAGIC: [u8; 8] = *b"SNP-LM-K";
    pub const MAJOR_VERSION: u8 = 1;
    pub const MINOR_VERSION: u8 = 0;
    pub const ENCODED_SIZE: usize = 272;

    pub fn new(
        report_data_context: ReportDataContextV1,
        contribution: Zeroizing<[u8; SNP_KEY_CONTRIBUTION_SIZE]>,
    ) -> SnpCodecResult<Self> {
        if report_data_context.evidence_purpose != SnpEvidencePurposeV1::InterNodeKeyContribution {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        report_data_context.validate()?;
        Ok(Self {
            report_data_context,
            contribution,
        })
    }

    pub fn contribution(&self) -> &[u8; SNP_KEY_CONTRIBUTION_SIZE] {
        &self.contribution
    }

    pub fn clear_contribution(&mut self) {
        self.contribution.zeroize();
    }

    pub fn encode_exact(&self) -> SnpCodecResult<Zeroizing<[u8; Self::ENCODED_SIZE]>> {
        if self.report_data_context.evidence_purpose
            != SnpEvidencePurposeV1::InterNodeKeyContribution
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        let mut encoded = Zeroizing::new([0u8; Self::ENCODED_SIZE]);
        let mut writer = StrictWriter::new(encoded.as_mut());
        writer.write_bytes(&Self::MAGIC)?;
        writer.write_u8(Self::MAJOR_VERSION)?;
        writer.write_u8(Self::MINOR_VERSION)?;
        SnpRecordTypeV1::KeyContribution.encode(&mut writer)?;
        writer.write_u32(Self::ENCODED_SIZE as u32)?;
        writer.write_zeroes(4)?;
        self.report_data_context.encode(&mut writer)?;
        writer.write_bytes(self.contribution.as_ref())?;
        if writer.written() != Self::ENCODED_SIZE {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(encoded)
    }

    /// Erases the supplied payload on success or error; transport copies remain
    /// the caller's responsibility.
    pub fn decode_exact(encoded: &mut [u8]) -> SnpCodecResult<Self> {
        let result = (|| {
            let mut reader = StrictReader::new(encoded);
            if reader.read_array::<8>()? != Self::MAGIC {
                return Err(SnpCodecError::InvalidMagic);
            }
            if reader.read_u8()? != Self::MAJOR_VERSION || reader.read_u8()? != Self::MINOR_VERSION
            {
                return Err(SnpCodecError::UnsupportedVersion);
            }
            if SnpRecordTypeV1::decode(&mut reader)? != SnpRecordTypeV1::KeyContribution {
                return Err(SnpCodecError::NonCanonicalEncoding);
            }
            if reader.read_u32()? != Self::ENCODED_SIZE as u32 {
                return Err(SnpCodecError::InvalidLength);
            }
            reader.read_zeroes(4)?;
            let context = ReportDataContextV1::decode(&mut reader)?;
            let mut value = Self::new(context, Zeroizing::new([0; SNP_KEY_CONTRIBUTION_SIZE]))?;
            value
                .contribution
                .copy_from_slice(reader.take(SNP_KEY_CONTRIBUTION_SIZE)?);
            reader.finish()?;
            Ok(value)
        })();
        encoded.zeroize();
        result
    }

    /// `expected` must come from verified MA evidence in the current session.
    /// This compares the attested commitment reference, not its preimage.
    pub fn validate_context(
        &mut self,
        expected: &ReportDataContextV1,
    ) -> Result<(), SnpAuthorizationFailureV1> {
        let result = self.check_context(expected);
        if result.is_err() {
            self.clear_contribution();
        }
        result
    }

    fn check_context(
        &self,
        expected: &ReportDataContextV1,
    ) -> Result<(), SnpAuthorizationFailureV1> {
        let actual = &self.report_data_context;
        if actual.evidence_purpose != SnpEvidencePurposeV1::InterNodeKeyContribution
            || expected.evidence_purpose != SnpEvidencePurposeV1::InterNodeKeyContribution
        {
            return Err(SnpAuthorizationFailureV1::UnexpectedMessage);
        }
        actual
            .validate()
            .and_then(|_| expected.validate())
            .map_err(|_| SnpAuthorizationFailureV1::ProtocolStateViolation)?;
        if actual.request_id != expected.request_id || actual.role != expected.role {
            return Err(SnpAuthorizationFailureV1::ProtocolStateViolation);
        }
        if actual.tenant_binding_id != expected.tenant_binding_id {
            return Err(SnpAuthorizationFailureV1::IdentityBindingFailed);
        }
        if actual != expected {
            return Err(SnpAuthorizationFailureV1::ReportDataBindingFailed);
        }
        Ok(())
    }

    pub fn codec_failure(error: SnpCodecError) -> SnpAuthorizationFailureV1 {
        match error {
            SnpCodecError::UnsupportedVersion => SnpAuthorizationFailureV1::UnsupportedVersion,
            SnpCodecError::LengthOverflow
            | SnpCodecError::RecordTooLarge
            | SnpCodecError::MessageTooLarge
            | SnpCodecError::CertificateTooLarge
            | SnpCodecError::CertificateSetTooLarge => {
                SnpAuthorizationFailureV1::ResourceLimitExceeded
            }
            SnpCodecError::BufferTooSmall => SnpAuthorizationFailureV1::InternalError,
            SnpCodecError::Truncated
            | SnpCodecError::InvalidMagic
            | SnpCodecError::UnknownRecordType
            | SnpCodecError::UnknownEnumValue
            | SnpCodecError::InvalidLength
            | SnpCodecError::InvalidCount
            | SnpCodecError::DuplicateCertificateRole
            | SnpCodecError::MissingRequiredCertificate
            | SnpCodecError::InvalidCertificateOrder
            | SnpCodecError::NonZeroReservedField
            | SnpCodecError::TrailingBytes
            | SnpCodecError::NonCanonicalEncoding => SnpAuthorizationFailureV1::MalformedMessage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp::report_data_context::{SnpMaRoleV1, SnpMigrationAlgorithmV1};

    fn context(role: SnpMaRoleV1) -> ReportDataContextV1 {
        ReportDataContextV1 {
            evidence_purpose: SnpEvidencePurposeV1::InterNodeKeyContribution,
            role,
            request_id: 0x0102_0304_0506_0708,
            negotiated_migration_version: 0x090A,
            algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            tenant_binding_id: [0x11; 32],
            th1: [0x22; 48],
            purpose_binding_digest: [0x33; 48],
            ma_policy_identity_digest: [0x44; 48],
        }
    }

    fn sample(role: SnpMaRoleV1) -> SnpKeyContributionV1 {
        SnpKeyContributionV1::new(context(role), Zeroizing::new([0xA5; 32])).unwrap()
    }

    #[test]
    fn source_and_destination_golden_vectors_are_exact() {
        for role in [SnpMaRoleV1::Source, SnpMaRoleV1::Destination] {
            let mut expected = [0u8; 272];
            expected[..8].copy_from_slice(b"SNP-LM-K");
            expected[8..12].copy_from_slice(&[1, 0, 5, 0]);
            expected[12..16].copy_from_slice(&272u32.to_le_bytes());
            expected[20..48].copy_from_slice(b"AMD-SNP-MA-LM-REPORT-DATA-V1");
            expected[48..52].copy_from_slice(&[1, 0, 1, role as u8]);
            expected[52..60].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
            expected[60..64].copy_from_slice(&[0x0A, 0x09, 3, 0]);
            expected[64..96].fill(0x11);
            expected[96..144].fill(0x22);
            expected[144..192].fill(0x33);
            expected[192..240].fill(0x44);
            expected[240..272].fill(0xA5);
            let value = sample(role);
            let mut encoded = value.encode_exact().unwrap();
            assert_eq!(encoded.as_ref(), &expected);
            let decoded = SnpKeyContributionV1::decode_exact(encoded.as_mut()).unwrap();
            assert_eq!(decoded.report_data_context, value.report_data_context);
            assert_eq!(decoded.contribution(), value.contribution());
            assert_eq!(decoded.encode_exact().unwrap().as_ref(), &expected);
            assert!(encoded.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn malformed_fields_are_rejected_and_input_is_erased() {
        let cases = [
            (0, 0, SnpCodecError::InvalidMagic),
            (8, 2, SnpCodecError::UnsupportedVersion),
            (9, 1, SnpCodecError::UnsupportedVersion),
            (10, 0xFF, SnpCodecError::UnknownRecordType),
            (10, 1, SnpCodecError::NonCanonicalEncoding),
            (12, 0, SnpCodecError::InvalidLength),
            (20, 0, SnpCodecError::InvalidMagic),
            (48, 2, SnpCodecError::UnsupportedVersion),
            (50, 0, SnpCodecError::UnknownEnumValue),
            (50, 2, SnpCodecError::NonCanonicalEncoding),
            (51, 4, SnpCodecError::UnknownEnumValue),
            (62, 1, SnpCodecError::UnknownEnumValue),
        ];
        for (offset, byte, error) in cases {
            let mut encoded = sample(SnpMaRoleV1::Source).encode_exact().unwrap();
            encoded[offset] = byte;
            assert_eq!(
                SnpKeyContributionV1::decode_exact(encoded.as_mut()).unwrap_err(),
                error
            );
            assert!(encoded.iter().all(|b| *b == 0));
        }
        for offset in 16..20 {
            let mut encoded = sample(SnpMaRoleV1::Source).encode_exact().unwrap();
            encoded[offset] = 1;
            assert_eq!(
                SnpKeyContributionV1::decode_exact(encoded.as_mut()).unwrap_err(),
                SnpCodecError::NonZeroReservedField
            );
            assert!(encoded.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn every_truncation_and_trailing_bytes_are_rejected_and_erased() {
        for end in 0..SnpKeyContributionV1::ENCODED_SIZE {
            let mut encoded = sample(SnpMaRoleV1::Source).encode_exact().unwrap();
            assert!(SnpKeyContributionV1::decode_exact(&mut encoded[..end]).is_err());
            assert!(encoded[..end].iter().all(|b| *b == 0));
        }
        let encoded = sample(SnpMaRoleV1::Source).encode_exact().unwrap();
        let mut extended = Zeroizing::new([0u8; 273]);
        extended[..272].copy_from_slice(encoded.as_ref());
        assert_eq!(
            SnpKeyContributionV1::decode_exact(extended.as_mut()).unwrap_err(),
            SnpCodecError::TrailingBytes
        );
        assert!(extended.iter().all(|b| *b == 0));
    }

    #[test]
    fn binding_rejects_wrong_request_role_tenant_session_commitment_and_policy() {
        let mut value = sample(SnpMaRoleV1::Source);
        let expected = value.report_data_context.clone();
        value.validate_context(&expected).unwrap();
        value.report_data_context.request_id ^= 1;
        assert_eq!(
            value.validate_context(&expected),
            Err(SnpAuthorizationFailureV1::ProtocolStateViolation)
        );
        assert_eq!(value.contribution(), &[0; 32]);
        value = sample(SnpMaRoleV1::Source);
        value.report_data_context.role = SnpMaRoleV1::Destination;
        assert_eq!(
            value.validate_context(&expected),
            Err(SnpAuthorizationFailureV1::ProtocolStateViolation)
        );
        assert_eq!(value.contribution(), &[0; 32]);
        value = sample(SnpMaRoleV1::Source);
        value.report_data_context.tenant_binding_id[0] ^= 1;
        assert_eq!(
            value.validate_context(&expected),
            Err(SnpAuthorizationFailureV1::IdentityBindingFailed)
        );
        assert_eq!(value.contribution(), &[0; 32]);
        for field in 0..4 {
            value = sample(SnpMaRoleV1::Source);
            match field {
                0 => value.report_data_context.th1[0] ^= 1,
                1 => value.report_data_context.purpose_binding_digest[0] ^= 1,
                2 => value.report_data_context.ma_policy_identity_digest[0] ^= 1,
                _ => value.report_data_context.negotiated_migration_version ^= 1,
            }
            assert_eq!(
                value.validate_context(&expected),
                Err(SnpAuthorizationFailureV1::ReportDataBindingFailed)
            );
            assert_eq!(value.contribution(), &[0; 32]);
        }
    }

    #[test]
    fn codec_errors_have_explicit_protocol_failures() {
        for (error, failure) in [
            (
                SnpCodecError::InvalidMagic,
                SnpAuthorizationFailureV1::MalformedMessage,
            ),
            (
                SnpCodecError::UnsupportedVersion,
                SnpAuthorizationFailureV1::UnsupportedVersion,
            ),
            (
                SnpCodecError::RecordTooLarge,
                SnpAuthorizationFailureV1::ResourceLimitExceeded,
            ),
            (
                SnpCodecError::BufferTooSmall,
                SnpAuthorizationFailureV1::InternalError,
            ),
        ] {
            assert_eq!(SnpKeyContributionV1::codec_failure(error), failure);
        }
    }

    #[test]
    fn non_contribution_purpose_is_rejected_before_encoding_or_binding() {
        let mut invalid = context(SnpMaRoleV1::Source);
        invalid.evidence_purpose = SnpEvidencePurposeV1::InterNodePostInstallConfirmation;
        assert_eq!(
            SnpKeyContributionV1::new(invalid.clone(), Zeroizing::new([0xA5; 32])).unwrap_err(),
            SnpCodecError::NonCanonicalEncoding
        );
        let mut value = sample(SnpMaRoleV1::Source);
        assert_eq!(
            value.validate_context(&invalid),
            Err(SnpAuthorizationFailureV1::UnexpectedMessage)
        );
        value.report_data_context = invalid;
        assert_eq!(
            value.encode_exact().unwrap_err(),
            SnpCodecError::NonCanonicalEncoding
        );
    }

    #[test]
    fn secrets_can_be_cleared_and_debug_output_is_redacted() {
        let mut value = sample(SnpMaRoleV1::Source);
        let debug = format!("{value:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("165"));
        value.clear_contribution();
        assert_eq!(value.contribution(), &[0; 32]);
        let mut encoded = value.encode_exact().unwrap();
        encoded.zeroize();
        assert!(encoded.iter().all(|b| *b == 0));
    }
}
