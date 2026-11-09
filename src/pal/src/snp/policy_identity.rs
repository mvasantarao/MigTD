// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Canonical SNP migration policy identity.

use super::{
    report_data_context::SHA384_DIGEST_SIZE,
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentityV1 {
    pub policy_digest: [u8; SHA384_DIGEST_SIZE],
}

impl PolicyIdentityV1 {
    pub const MAJOR_VERSION: u8 = 1;
    pub const MINOR_VERSION: u8 = 0;
    pub const ENCODED_SIZE: usize = 56;

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u8(Self::MAJOR_VERSION)?;
        writer.write_u8(Self::MINOR_VERSION)?;
        writer.write_zeroes(2)?;
        writer.write_u32(Self::ENCODED_SIZE as u32)?;
        writer.write_bytes(&self.policy_digest)
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
        record.read_zeroes(2)?;
        if record.read_u32()? != Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }

        let value = Self {
            policy_digest: record.read_array()?,
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

    fn sample_identity() -> PolicyIdentityV1 {
        PolicyIdentityV1 {
            policy_digest: [0xA5; SHA384_DIGEST_SIZE],
        }
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let encoded = sample_identity().encode_exact().unwrap();
        assert_eq!(&encoded[0x00..0x02], &[1, 0]);
        assert_eq!(&encoded[0x02..0x04], &[0, 0]);
        assert_eq!(&encoded[0x04..0x08], &56u32.to_le_bytes());
        assert_eq!(&encoded[0x08..0x38], &[0xA5; SHA384_DIGEST_SIZE]);
    }

    #[test]
    fn exact_round_trip_preserves_identity() {
        let expected = sample_identity();
        let encoded = expected.encode_exact().unwrap();
        assert_eq!(PolicyIdentityV1::decode_exact(&encoded).unwrap(), expected);
    }

    #[test]
    fn unsupported_major_or_minor_version_is_rejected() {
        for offset in [0x00, 0x01] {
            let mut encoded = sample_identity().encode_exact().unwrap();
            encoded[offset] = 2;
            assert_eq!(
                PolicyIdentityV1::decode_exact(&encoded),
                Err(SnpCodecError::UnsupportedVersion)
            );
        }
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        let mut encoded = sample_identity().encode_exact().unwrap();
        encoded[0x02] = 1;
        assert_eq!(
            PolicyIdentityV1::decode_exact(&encoded),
            Err(SnpCodecError::NonZeroReservedField)
        );
    }

    #[test]
    fn wrong_encoded_length_is_rejected() {
        let mut encoded = sample_identity().encode_exact().unwrap();
        encoded[0x04..0x08].copy_from_slice(&55u32.to_le_bytes());
        assert_eq!(
            PolicyIdentityV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidLength)
        );
    }

    #[test]
    fn truncated_and_trailing_input_are_rejected() {
        let encoded = sample_identity().encode_exact().unwrap();
        assert_eq!(
            PolicyIdentityV1::decode_exact(&encoded[..encoded.len() - 1]),
            Err(SnpCodecError::Truncated)
        );

        let mut extended = [0u8; PolicyIdentityV1::ENCODED_SIZE + 1];
        extended[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            PolicyIdentityV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }
}
