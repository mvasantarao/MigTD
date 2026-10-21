// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Canonical SNP certificate collateral set.

use super::{
    evidence_header::{SnpEvidenceProfileV1, SnpRecordTypeV1, SnpTcbProfileV1},
    limits::{MAX_SNP_CERTIFICATE_SIZE, MAX_SNP_COLLATERAL_SET_SIZE},
    wire::{checked_add, SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SnpCertificateRoleV1 {
    Vcek = 0x0001,
    Vlek = 0x0002,
    Ask = 0x0003,
}

impl SnpCertificateRoleV1 {
    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u16()? {
            0x0001 => Ok(Self::Vcek),
            0x0002 => Ok(Self::Vlek),
            0x0003 => Ok(Self::Ask),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    fn encode(self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u16(self as u16)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpCertificateEntryV1 {
    pub role: SnpCertificateRoleV1,
    pub certificate_der: Vec<u8>,
}

impl SnpCertificateEntryV1 {
    pub const HEADER_SIZE: usize = 8;

    fn certificate_length(&self) -> SnpCodecResult<usize> {
        let length = self.certificate_der.len();
        if length == 0 {
            return Err(SnpCodecError::InvalidLength);
        }
        if length > MAX_SNP_CERTIFICATE_SIZE {
            return Err(SnpCodecError::CertificateTooLarge);
        }
        Ok(length)
    }

    fn encoded_length(&self) -> SnpCodecResult<usize> {
        checked_add(Self::HEADER_SIZE, self.certificate_length()?)
    }

    fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        let certificate_length = self.certificate_length()?;
        self.role.encode(writer)?;
        writer.write_zeroes(2)?;
        writer.write_u32(certificate_length as u32)?;
        writer.write_bytes(&self.certificate_der)
    }

    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        let role = SnpCertificateRoleV1::decode(reader)?;
        reader.read_zeroes(2)?;
        let certificate_length =
            usize::try_from(reader.read_u32()?).map_err(|_| SnpCodecError::LengthOverflow)?;
        if certificate_length == 0 {
            return Err(SnpCodecError::InvalidLength);
        }
        if certificate_length > MAX_SNP_CERTIFICATE_SIZE {
            return Err(SnpCodecError::CertificateTooLarge);
        }

        Ok(Self {
            role,
            certificate_der: reader.take(certificate_length)?.to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpCollateralSetV1 {
    pub evidence_profile: SnpEvidenceProfileV1,
    pub tcb_profile: SnpTcbProfileV1,
    pub leaf_certificate: SnpCertificateEntryV1,
    pub ask_certificate: SnpCertificateEntryV1,
}

impl SnpCollateralSetV1 {
    pub const MAGIC: [u8; 8] = *b"SNP-LM-C";
    pub const MAJOR_VERSION: u8 = 1;
    pub const MINOR_VERSION: u8 = 0;
    pub const HEADER_SIZE: usize = 24;
    pub const CERTIFICATE_COUNT: u16 = 2;
    pub const MINIMUM_SIZE_BEFORE_DER: usize =
        Self::HEADER_SIZE + (2 * SnpCertificateEntryV1::HEADER_SIZE);

    fn validate_certificate_order(&self) -> SnpCodecResult<()> {
        if self.leaf_certificate.role == self.ask_certificate.role {
            return Err(SnpCodecError::DuplicateCertificateRole);
        }
        if !matches!(
            self.leaf_certificate.role,
            SnpCertificateRoleV1::Vcek | SnpCertificateRoleV1::Vlek
        ) || self.ask_certificate.role != SnpCertificateRoleV1::Ask
        {
            return Err(SnpCodecError::InvalidCertificateOrder);
        }
        Ok(())
    }

    pub fn encoded_length(&self) -> SnpCodecResult<usize> {
        self.validate_certificate_order()?;
        let length = checked_add(Self::HEADER_SIZE, self.leaf_certificate.encoded_length()?)?;
        let length = checked_add(length, self.ask_certificate.encoded_length()?)?;
        if length > MAX_SNP_COLLATERAL_SET_SIZE {
            return Err(SnpCodecError::CertificateSetTooLarge);
        }
        Ok(length)
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        let encoded_length = self.encoded_length()?;
        writer.write_bytes(&Self::MAGIC)?;
        writer.write_u8(Self::MAJOR_VERSION)?;
        writer.write_u8(Self::MINOR_VERSION)?;
        SnpRecordTypeV1::CollateralSet.encode(writer)?;
        writer.write_u32(encoded_length as u32)?;
        self.evidence_profile.encode(writer)?;
        self.tcb_profile.encode(writer)?;
        writer.write_u16(Self::CERTIFICATE_COUNT)?;
        writer.write_zeroes(4)?;
        self.leaf_certificate.encode(writer)?;
        self.ask_certificate.encode(writer)
    }

    pub fn encode_exact(&self) -> SnpCodecResult<Vec<u8>> {
        let encoded_length = self.encoded_length()?;
        let mut encoded = vec![0u8; encoded_length];
        let mut writer = StrictWriter::new(&mut encoded);
        self.encode(&mut writer)?;
        if writer.written() != encoded_length {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(encoded)
    }

    pub fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        if reader.read_array::<8>()? != Self::MAGIC {
            return Err(SnpCodecError::InvalidMagic);
        }
        if reader.read_u8()? != Self::MAJOR_VERSION || reader.read_u8()? != Self::MINOR_VERSION {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        if SnpRecordTypeV1::decode(reader)? != SnpRecordTypeV1::CollateralSet {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }

        let record_length =
            usize::try_from(reader.read_u32()?).map_err(|_| SnpCodecError::LengthOverflow)?;
        if record_length < Self::MINIMUM_SIZE_BEFORE_DER {
            return Err(SnpCodecError::InvalidLength);
        }
        if record_length > MAX_SNP_COLLATERAL_SET_SIZE {
            return Err(SnpCodecError::CertificateSetTooLarge);
        }

        let evidence_profile = SnpEvidenceProfileV1::decode(reader)?;
        let tcb_profile = SnpTcbProfileV1::decode(reader)?;
        if reader.read_u16()? != Self::CERTIFICATE_COUNT {
            return Err(SnpCodecError::InvalidCount);
        }
        reader.read_zeroes(4)?;

        let body_length = record_length - Self::HEADER_SIZE;
        let mut body = reader.sub(body_length)?;
        let value = Self {
            evidence_profile,
            tcb_profile,
            leaf_certificate: SnpCertificateEntryV1::decode(&mut body)?,
            ask_certificate: SnpCertificateEntryV1::decode(&mut body)?,
        };
        body.finish()?;
        value.validate_certificate_order()?;
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

    fn entry(role: SnpCertificateRoleV1, bytes: &[u8]) -> SnpCertificateEntryV1 {
        SnpCertificateEntryV1 {
            role,
            certificate_der: bytes.to_vec(),
        }
    }

    fn sample_set() -> SnpCollateralSetV1 {
        SnpCollateralSetV1 {
            evidence_profile: SnpEvidenceProfileV1::Production,
            tcb_profile: SnpTcbProfileV1::MilanGenoa,
            leaf_certificate: entry(SnpCertificateRoleV1::Vcek, &[1, 2]),
            ask_certificate: entry(SnpCertificateRoleV1::Ask, &[3, 4, 5]),
        }
    }

    #[test]
    fn canonical_encoding_has_exact_layout() {
        let encoded = sample_set().encode_exact().unwrap();
        assert_eq!(encoded.len(), 45);
        assert_eq!(&encoded[0x00..0x08], &SnpCollateralSetV1::MAGIC);
        assert_eq!(&encoded[0x08..0x0A], &[1, 0]);
        assert_eq!(&encoded[0x0A..0x0C], &[3, 0]);
        assert_eq!(&encoded[0x0C..0x10], &45u32.to_le_bytes());
        assert_eq!(&encoded[0x10..0x12], &[1, 1]);
        assert_eq!(&encoded[0x12..0x14], &[2, 0]);
        assert_eq!(&encoded[0x14..0x18], &[0; 4]);
        assert_eq!(&encoded[0x18..0x20], &[1, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&encoded[0x20..0x22], &[1, 2]);
        assert_eq!(&encoded[0x22..0x2A], &[3, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(&encoded[0x2A..0x2D], &[3, 4, 5]);
    }

    #[test]
    fn vcek_and_vlek_sets_round_trip() {
        for role in [SnpCertificateRoleV1::Vcek, SnpCertificateRoleV1::Vlek] {
            let mut expected = sample_set();
            expected.leaf_certificate.role = role;
            let encoded = expected.encode_exact().unwrap();
            assert_eq!(
                SnpCollateralSetV1::decode_exact(&encoded).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn empty_or_oversized_certificate_is_rejected() {
        let mut set = sample_set();
        set.leaf_certificate.certificate_der.clear();
        assert_eq!(set.encode_exact(), Err(SnpCodecError::InvalidLength));

        set.leaf_certificate.certificate_der = vec![0; MAX_SNP_CERTIFICATE_SIZE + 1];
        assert_eq!(set.encode_exact(), Err(SnpCodecError::CertificateTooLarge));
    }

    #[test]
    fn oversized_complete_set_is_rejected() {
        let mut set = sample_set();
        set.leaf_certificate.certificate_der = vec![0; 2_300];
        set.ask_certificate.certificate_der = vec![0; 2_300];
        assert_eq!(
            set.encode_exact(),
            Err(SnpCodecError::CertificateSetTooLarge)
        );
    }

    #[test]
    fn invalid_order_and_duplicate_roles_are_rejected() {
        let mut set = sample_set();
        set.leaf_certificate.role = SnpCertificateRoleV1::Ask;
        set.ask_certificate.role = SnpCertificateRoleV1::Vcek;
        assert_eq!(
            set.encode_exact(),
            Err(SnpCodecError::InvalidCertificateOrder)
        );

        set.ask_certificate.role = SnpCertificateRoleV1::Ask;
        assert_eq!(
            set.encode_exact(),
            Err(SnpCodecError::DuplicateCertificateRole)
        );
    }

    #[test]
    fn invalid_count_and_reserved_bytes_are_rejected() {
        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidCount)
        );

        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x14] = 1;
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::NonZeroReservedField)
        );

        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x1A] = 1;
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::NonZeroReservedField)
        );
    }

    #[test]
    fn bounds_are_checked_before_body_allocation() {
        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x0C..0x10]
            .copy_from_slice(&((MAX_SNP_COLLATERAL_SET_SIZE + 1) as u32).to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::CertificateSetTooLarge)
        );

        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x1C..0x20].copy_from_slice(&((MAX_SNP_CERTIFICATE_SIZE + 1) as u32).to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::CertificateTooLarge)
        );
    }

    #[test]
    fn unknown_role_and_trailing_input_are_rejected() {
        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x18..0x1A].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::UnknownEnumValue)
        );

        let encoded = sample_set().encode_exact().unwrap();
        let mut extended = encoded.clone();
        extended.push(0);
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }

    #[test]
    fn malformed_header_fields_are_rejected() {
        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0] ^= 1;
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::InvalidMagic)
        );

        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x08] = 2;
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::UnsupportedVersion)
        );

        let mut encoded = sample_set().encode_exact().unwrap();
        encoded[0x0A..0x0C].copy_from_slice(&(SnpRecordTypeV1::MaEvidence as u16).to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded),
            Err(SnpCodecError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn declared_length_mismatch_is_rejected() {
        let encoded = sample_set().encode_exact().unwrap();

        let mut shorter = encoded.clone();
        shorter[0x0C..0x10].copy_from_slice(&((encoded.len() - 1) as u32).to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&shorter),
            Err(SnpCodecError::Truncated)
        );

        let mut longer = encoded;
        let declared_length = (longer.len() + 1) as u32;
        longer[0x0C..0x10].copy_from_slice(&declared_length.to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&longer),
            Err(SnpCodecError::Truncated)
        );
    }

    #[test]
    fn decoded_order_duplicates_and_missing_der_are_rejected() {
        let mut swapped = sample_set().encode_exact().unwrap();
        swapped[0x18..0x1A].copy_from_slice(&(SnpCertificateRoleV1::Ask as u16).to_le_bytes());
        swapped[0x22..0x24].copy_from_slice(&(SnpCertificateRoleV1::Vcek as u16).to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&swapped),
            Err(SnpCodecError::InvalidCertificateOrder)
        );

        let mut duplicate = sample_set().encode_exact().unwrap();
        duplicate[0x18..0x1A].copy_from_slice(&(SnpCertificateRoleV1::Ask as u16).to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&duplicate),
            Err(SnpCodecError::DuplicateCertificateRole)
        );

        let mut missing_der = sample_set().encode_exact().unwrap();
        missing_der[0x26..0x2A].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&missing_der),
            Err(SnpCodecError::InvalidLength)
        );
    }
}
