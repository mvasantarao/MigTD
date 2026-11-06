// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Canonical interpretation contract for tenant SNP evidence.

use super::{
    evidence_header::SnpTcbProfileV1,
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpEtcbProjectionProfileV1 {
    ArgSvnV1 = 0x01,
    VeniceV1 = 0x02,
}

impl SnpEtcbProjectionProfileV1 {
    pub(crate) fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0x01 => Ok(Self::ArgSvnV1),
            0x02 => Ok(Self::VeniceV1),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    pub(crate) fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u8(self as u8)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPolicyContextV1 {
    pub tcb_profile: SnpTcbProfileV1,
    pub etcb_projection_profile: SnpEtcbProjectionProfileV1,
}

impl TenantPolicyContextV1 {
    pub const MAJOR_VERSION: u8 = 1;
    pub const MINOR_VERSION: u8 = 0;
    pub const ENCODED_SIZE: usize = 16;
    pub const MIGRATION_DATA_VERSION: u8 = 1;
    pub const REQUIRED_VALIDATION_RULES: u32 = 0x0000_001F;

    pub fn venice() -> Self {
        Self {
            tcb_profile: SnpTcbProfileV1::Venice,
            etcb_projection_profile: SnpEtcbProjectionProfileV1::VeniceV1,
        }
    }

    fn validate_profiles(&self) -> SnpCodecResult<()> {
        if (self.tcb_profile == SnpTcbProfileV1::Venice)
            != (self.etcb_projection_profile == SnpEtcbProjectionProfileV1::VeniceV1)
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        self.validate_profiles()?;
        writer.write_u8(Self::MAJOR_VERSION)?;
        writer.write_u8(Self::MINOR_VERSION)?;
        self.tcb_profile.encode(writer)?;
        self.etcb_projection_profile.encode(writer)?;
        writer.write_u32(Self::ENCODED_SIZE as u32)?;
        writer.write_u8(Self::MIGRATION_DATA_VERSION)?;
        writer.write_zeroes(3)?;
        writer.write_u32(Self::REQUIRED_VALIDATION_RULES)
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
        if record.read_u8()? != Self::MAJOR_VERSION || record.read_u8()? != Self::MINOR_VERSION {
            return Err(SnpCodecError::UnsupportedVersion);
        }

        let value = Self {
            tcb_profile: SnpTcbProfileV1::decode(&mut record)?,
            etcb_projection_profile: SnpEtcbProjectionProfileV1::decode(&mut record)?,
        };
        if record.read_u32()? != Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }
        if record.read_u8()? != Self::MIGRATION_DATA_VERSION {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        record.read_zeroes(3)?;
        if record.read_u32()? != Self::REQUIRED_VALIDATION_RULES {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        record.finish()?;
        value.validate_profiles()?;
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

    fn sample_context() -> TenantPolicyContextV1 {
        TenantPolicyContextV1 {
            tcb_profile: SnpTcbProfileV1::Turin,
            etcb_projection_profile: SnpEtcbProjectionProfileV1::ArgSvnV1,
        }
    }

    #[test]
    fn venice_descriptor_has_new_allocations_and_rejects_mixed_profiles() {
        let value = TenantPolicyContextV1::venice();
        let encoded = value.encode_exact().unwrap();
        assert_eq!(encoded, [1, 0, 3, 2, 16, 0, 0, 0, 1, 0, 0, 0, 31, 0, 0, 0]);
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&encoded).unwrap(),
            value
        );
        for (tcb, projection) in [(3, 1), (1, 2), (2, 2)] {
            let mut changed = encoded;
            changed[2] = tcb;
            changed[3] = projection;
            assert_eq!(
                TenantPolicyContextV1::decode_exact(&changed),
                Err(SnpCodecError::NonCanonicalEncoding)
            );
        }
        let mut invalid = value;
        invalid.etcb_projection_profile = SnpEtcbProjectionProfileV1::ArgSvnV1;
        assert_eq!(
            invalid.encode_exact(),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let encoded = sample_context().encode_exact().unwrap();
        assert_eq!(&encoded[0x00..0x04], &[1, 0, 2, 1]);
        assert_eq!(&encoded[0x04..0x08], &16u32.to_le_bytes());
        assert_eq!(encoded[0x08], 1);
        assert_eq!(&encoded[0x09..0x0C], &[0; 3]);
        assert_eq!(&encoded[0x0C..0x10], &0x1Fu32.to_le_bytes());
    }

    #[test]
    fn exact_round_trip_preserves_context() {
        let expected = sample_context();
        let encoded = expected.encode_exact().unwrap();
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&encoded).unwrap(),
            expected
        );
    }

    #[test]
    fn unsupported_record_version_is_rejected() {
        for offset in [0x00, 0x01] {
            let mut encoded = sample_context().encode_exact().unwrap();
            encoded[offset] = 2;
            assert_eq!(
                TenantPolicyContextV1::decode_exact(&encoded),
                Err(SnpCodecError::UnsupportedVersion)
            );
        }
    }

    #[test]
    fn unknown_tcb_or_etcb_profile_is_rejected() {
        for offset in [0x02, 0x03] {
            let mut encoded = sample_context().encode_exact().unwrap();
            encoded[offset] = 0;
            assert_eq!(
                TenantPolicyContextV1::decode_exact(&encoded),
                Err(SnpCodecError::UnknownEnumValue)
            );
        }
    }

    #[test]
    fn wrong_encoded_length_is_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0x04..0x08].copy_from_slice(&15u32.to_le_bytes());
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidLength)
        );
    }

    #[test]
    fn unsupported_migration_data_version_is_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0x08] = 2;
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&encoded),
            Err(SnpCodecError::UnsupportedVersion)
        );
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        let mut encoded = sample_context().encode_exact().unwrap();
        encoded[0x09] = 1;
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&encoded),
            Err(SnpCodecError::NonZeroReservedField)
        );
    }

    #[test]
    fn weakened_or_extended_validation_mask_is_rejected() {
        for mask in [0x0Fu32, 0x3Fu32] {
            let mut encoded = sample_context().encode_exact().unwrap();
            encoded[0x0C..0x10].copy_from_slice(&mask.to_le_bytes());
            assert_eq!(
                TenantPolicyContextV1::decode_exact(&encoded),
                Err(SnpCodecError::NonCanonicalEncoding)
            );
        }
    }

    #[test]
    fn truncated_and_trailing_input_are_rejected() {
        let encoded = sample_context().encode_exact().unwrap();
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&encoded[..encoded.len() - 1]),
            Err(SnpCodecError::Truncated)
        );

        let mut extended = [0u8; TenantPolicyContextV1::ENCODED_SIZE + 1];
        extended[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }
}
