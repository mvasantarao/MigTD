// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Common header for canonical SNP migration evidence records.

use super::{
    report_data_context::{SnpEvidencePurposeV1, SnpMaRoleV1},
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SnpRecordTypeV1 {
    MaEvidence = 0x0001,
    TenantEvidence = 0x0002,
    CollateralSet = 0x0003,
    AuthorizationResult = 0x0004,
}

impl SnpRecordTypeV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u16()? {
            0x0001 => Ok(Self::MaEvidence),
            0x0002 => Ok(Self::TenantEvidence),
            0x0003 => Ok(Self::CollateralSet),
            0x0004 => Ok(Self::AuthorizationResult),
            _ => Err(SnpCodecError::UnknownRecordType),
        }
    }

    pub(crate) fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u16(self as u16)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpEvidenceProfileV1 {
    Production = 0x01,
    Fixture = 0x02,
}

impl SnpEvidenceProfileV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x01 => Ok(Self::Production),
            0x02 => Ok(Self::Fixture),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    pub(crate) fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u8(self as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpTcbProfileV1 {
    MilanGenoa = 0x01,
    Turin = 0x02,
}

impl SnpTcbProfileV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x01 => Ok(Self::MilanGenoa),
            0x02 => Ok(Self::Turin),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    pub(crate) fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u8(self as u8)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpEvidenceHeaderV1 {
    pub record_type: SnpRecordTypeV1,
    pub record_length: u32,
    pub request_id: u64,
    pub role: SnpMaRoleV1,
    pub evidence_purpose: SnpEvidencePurposeV1,
    pub evidence_profile: SnpEvidenceProfileV1,
    pub tcb_profile: SnpTcbProfileV1,
}

impl SnpEvidenceHeaderV1 {
    pub const MAGIC: [u8; 8] = *b"SNP-LM-E";
    pub const MAJOR_VERSION: u8 = 1;
    pub const MINOR_VERSION: u8 = 0;
    pub const ENCODED_SIZE: usize = 32;

    fn validate_record_type(record_type: SnpRecordTypeV1) -> SnpCodecResult<()> {
        if !matches!(
            record_type,
            SnpRecordTypeV1::MaEvidence | SnpRecordTypeV1::TenantEvidence
        ) {
            return Err(SnpCodecError::UnknownRecordType);
        }
        Ok(())
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        Self::validate_record_type(self.record_type)?;
        if self.record_length < Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }

        writer.write_bytes(&Self::MAGIC)?;
        writer.write_u8(Self::MAJOR_VERSION)?;
        writer.write_u8(Self::MINOR_VERSION)?;
        self.record_type.encode(writer)?;
        writer.write_u32(self.record_length)?;
        writer.write_u64(self.request_id)?;
        self.role.encode(writer)?;
        self.evidence_purpose.encode(writer)?;
        self.evidence_profile.encode(writer)?;
        self.tcb_profile.encode(writer)?;
        writer.write_u32(0)
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
        let mut header = reader.sub(Self::ENCODED_SIZE)?;
        if header.read_array::<8>()? != Self::MAGIC {
            return Err(SnpCodecError::InvalidMagic);
        }
        if header.read_u8()? != Self::MAJOR_VERSION || header.read_u8()? != Self::MINOR_VERSION {
            return Err(SnpCodecError::UnsupportedVersion);
        }

        let record_type = SnpRecordTypeV1::decode(&mut header)?;
        Self::validate_record_type(record_type)?;
        let record_length = header.read_u32()?;
        if record_length < Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }

        let value = Self {
            record_type,
            record_length,
            request_id: header.read_u64()?,
            role: SnpMaRoleV1::decode(&mut header)?,
            evidence_purpose: SnpEvidencePurposeV1::decode(&mut header)?,
            evidence_profile: SnpEvidenceProfileV1::decode(&mut header)?,
            tcb_profile: SnpTcbProfileV1::decode(&mut header)?,
        };
        header.read_zeroes(4)?;
        header.finish()?;
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

    fn sample_header() -> SnpEvidenceHeaderV1 {
        SnpEvidenceHeaderV1 {
            record_type: SnpRecordTypeV1::MaEvidence,
            record_length: 1_540,
            request_id: 0x0102_0304_0506_0708,
            role: SnpMaRoleV1::Destination,
            evidence_purpose: SnpEvidencePurposeV1::MaKeyContribution,
            evidence_profile: SnpEvidenceProfileV1::Production,
            tcb_profile: SnpTcbProfileV1::MilanGenoa,
        }
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let encoded = sample_header().encode_exact().unwrap();
        assert_eq!(&encoded[0x00..0x08], &SnpEvidenceHeaderV1::MAGIC);
        assert_eq!(&encoded[0x08..0x0A], &[1, 0]);
        assert_eq!(&encoded[0x0A..0x0C], &[1, 0]);
        assert_eq!(&encoded[0x0C..0x10], &1_540u32.to_le_bytes());
        assert_eq!(
            &encoded[0x10..0x18],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&encoded[0x18..0x1C], &[1, 1, 1, 1]);
        assert_eq!(&encoded[0x1C..0x20], &[0; 4]);
    }

    #[test]
    fn exact_round_trip_preserves_header() {
        let expected = sample_header();
        let encoded = expected.encode_exact().unwrap();
        assert_eq!(
            SnpEvidenceHeaderV1::decode_exact(&encoded).unwrap(),
            expected
        );
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let mut encoded = sample_header().encode_exact().unwrap();
        encoded[0] ^= 1;
        assert_eq!(
            SnpEvidenceHeaderV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidMagic)
        );
    }

    #[test]
    fn unsupported_major_or_minor_version_is_rejected() {
        for offset in [0x08, 0x09] {
            let mut encoded = sample_header().encode_exact().unwrap();
            encoded[offset] = 2;
            assert_eq!(
                SnpEvidenceHeaderV1::decode_exact(&encoded),
                Err(SnpCodecError::UnsupportedVersion)
            );
        }
    }

    #[test]
    fn unknown_record_type_is_rejected() {
        let mut encoded = sample_header().encode_exact().unwrap();
        encoded[0x0A..0x0C].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            SnpEvidenceHeaderV1::decode_exact(&encoded),
            Err(SnpCodecError::UnknownRecordType)
        );
    }

    #[test]
    fn known_non_evidence_record_types_are_rejected() {
        for record_type in [
            SnpRecordTypeV1::CollateralSet,
            SnpRecordTypeV1::AuthorizationResult,
        ] {
            let mut header = sample_header();
            header.record_type = record_type;
            assert_eq!(header.encode_exact(), Err(SnpCodecError::UnknownRecordType));

            let mut encoded = sample_header().encode_exact().unwrap();
            encoded[0x0A..0x0C].copy_from_slice(&(record_type as u16).to_le_bytes());
            assert_eq!(
                SnpEvidenceHeaderV1::decode_exact(&encoded),
                Err(SnpCodecError::UnknownRecordType)
            );
        }
    }

    #[test]
    fn too_short_record_length_is_rejected_for_encode_and_decode() {
        let mut header = sample_header();
        header.record_length = (SnpEvidenceHeaderV1::ENCODED_SIZE - 1) as u32;
        assert_eq!(header.encode_exact(), Err(SnpCodecError::InvalidLength));

        let mut encoded = sample_header().encode_exact().unwrap();
        encoded[0x0C..0x10]
            .copy_from_slice(&((SnpEvidenceHeaderV1::ENCODED_SIZE - 1) as u32).to_le_bytes());
        assert_eq!(
            SnpEvidenceHeaderV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidLength)
        );
    }

    #[test]
    fn unknown_profile_values_are_rejected() {
        for offset in [0x1A, 0x1B] {
            let mut encoded = sample_header().encode_exact().unwrap();
            encoded[offset] = 0;
            assert_eq!(
                SnpEvidenceHeaderV1::decode_exact(&encoded),
                Err(SnpCodecError::UnknownEnumValue)
            );
        }
    }

    #[test]
    fn nonzero_flags_are_rejected() {
        let mut encoded = sample_header().encode_exact().unwrap();
        encoded[0x1C] = 1;
        assert_eq!(
            SnpEvidenceHeaderV1::decode_exact(&encoded),
            Err(SnpCodecError::NonZeroReservedField)
        );
    }

    #[test]
    fn truncated_and_trailing_input_are_rejected() {
        let encoded = sample_header().encode_exact().unwrap();
        assert_eq!(
            SnpEvidenceHeaderV1::decode_exact(&encoded[..encoded.len() - 1]),
            Err(SnpCodecError::Truncated)
        );

        let mut extended = [0u8; SnpEvidenceHeaderV1::ENCODED_SIZE + 1];
        extended[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            SnpEvidenceHeaderV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }
}
