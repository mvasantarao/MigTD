// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Strict wire helpers for the SNP migration protocol.

use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpCodecError {
    BufferTooSmall,
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    UnknownRecordType,
    UnknownEnumValue,
    InvalidLength,
    LengthOverflow,
    RecordTooLarge,
    MessageTooLarge,
    InvalidCount,
    DuplicateCertificateRole,
    MissingRequiredCertificate,
    InvalidCertificateOrder,
    CertificateTooLarge,
    CertificateSetTooLarge,
    NonZeroReservedField,
    TrailingBytes,
    NonCanonicalEncoding,
}

pub type SnpCodecResult<T> = Result<T, SnpCodecError>;

pub struct StrictReader<'a> {
    inner: Reader<'a>,
}

impl<'a> StrictReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: Reader::init(bytes),
        }
    }

    pub fn remaining(&self) -> usize {
        self.inner.left()
    }

    pub fn consumed(&self) -> usize {
        self.inner.used()
    }

    pub fn is_empty(&self) -> bool {
        !self.inner.any_left()
    }

    pub fn take(&mut self, length: usize) -> SnpCodecResult<&[u8]> {
        self.inner.take(length).ok_or(SnpCodecError::Truncated)
    }

    pub fn sub(&mut self, length: usize) -> SnpCodecResult<StrictReader<'_>> {
        self.inner
            .sub(length)
            .map(|inner| StrictReader { inner })
            .ok_or(SnpCodecError::Truncated)
    }

    pub fn read_u8(&mut self) -> SnpCodecResult<u8> {
        u8::read(&mut self.inner).ok_or(SnpCodecError::Truncated)
    }

    pub fn read_u16(&mut self) -> SnpCodecResult<u16> {
        u16::read(&mut self.inner).ok_or(SnpCodecError::Truncated)
    }

    pub fn read_u32(&mut self) -> SnpCodecResult<u32> {
        u32::read(&mut self.inner).ok_or(SnpCodecError::Truncated)
    }

    pub fn read_u64(&mut self) -> SnpCodecResult<u64> {
        u64::read(&mut self.inner).ok_or(SnpCodecError::Truncated)
    }

    pub fn read_array<const N: usize>(&mut self) -> SnpCodecResult<[u8; N]> {
        let mut value = [0u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    pub fn read_bounded_bytes(
        &mut self,
        wire_length: u32,
        maximum: usize,
    ) -> SnpCodecResult<&[u8]> {
        self.take(bounded_length(wire_length, maximum)?)
    }

    pub fn read_zeroes(&mut self, length: usize) -> SnpCodecResult<()> {
        if self.take(length)?.iter().any(|byte| *byte != 0) {
            return Err(SnpCodecError::NonZeroReservedField);
        }
        Ok(())
    }

    pub fn finish(self) -> SnpCodecResult<()> {
        if self.inner.any_left() {
            return Err(SnpCodecError::TrailingBytes);
        }
        Ok(())
    }
}

pub struct StrictWriter<'a> {
    inner: Writer<'a>,
}

impl<'a> StrictWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            inner: Writer::init(bytes),
        }
    }

    pub fn remaining(&self) -> usize {
        self.inner.left()
    }

    pub fn written(&self) -> usize {
        self.inner.used()
    }

    pub fn written_slice(&self) -> &[u8] {
        self.inner.used_slice()
    }

    pub fn write_u8(&mut self, value: u8) -> SnpCodecResult<()> {
        value
            .encode(&mut self.inner)
            .map(|_| ())
            .map_err(|_| SnpCodecError::BufferTooSmall)
    }

    pub fn write_u16(&mut self, value: u16) -> SnpCodecResult<()> {
        value
            .encode(&mut self.inner)
            .map(|_| ())
            .map_err(|_| SnpCodecError::BufferTooSmall)
    }

    pub fn write_u32(&mut self, value: u32) -> SnpCodecResult<()> {
        value
            .encode(&mut self.inner)
            .map(|_| ())
            .map_err(|_| SnpCodecError::BufferTooSmall)
    }

    pub fn write_u64(&mut self, value: u64) -> SnpCodecResult<()> {
        value
            .encode(&mut self.inner)
            .map(|_| ())
            .map_err(|_| SnpCodecError::BufferTooSmall)
    }

    pub fn write_bytes(&mut self, value: &[u8]) -> SnpCodecResult<()> {
        self.inner
            .extend_from_slice(value)
            .map(|_| ())
            .ok_or(SnpCodecError::BufferTooSmall)
    }

    pub fn write_zeroes(&mut self, length: usize) -> SnpCodecResult<()> {
        for _ in 0..length {
            self.write_u8(0)?;
        }
        Ok(())
    }
}

pub fn checked_add(left: usize, right: usize) -> SnpCodecResult<usize> {
    left.checked_add(right).ok_or(SnpCodecError::LengthOverflow)
}

pub fn checked_mul(left: usize, right: usize) -> SnpCodecResult<usize> {
    left.checked_mul(right).ok_or(SnpCodecError::LengthOverflow)
}

pub fn bounded_length(length: u32, maximum: usize) -> SnpCodecResult<usize> {
    let length = usize::try_from(length).map_err(|_| SnpCodecError::LengthOverflow)?;
    if length > maximum {
        return Err(SnpCodecError::RecordTooLarge);
    }
    Ok(length)
}

pub fn exact_length(actual: usize, expected: usize) -> SnpCodecResult<()> {
    if actual != expected {
        return Err(SnpCodecError::InvalidLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_round_trip_is_little_endian() {
        let mut bytes = [0u8; 15];
        let mut writer = StrictWriter::new(&mut bytes);
        writer.write_u8(0x12).unwrap();
        writer.write_u16(0x3456).unwrap();
        writer.write_u32(0x789A_BCDE).unwrap();
        writer.write_u64(0x0123_4567_89AB_CDEF).unwrap();
        assert_eq!(writer.written(), 15);
        assert_eq!(
            writer.written_slice(),
            &[
                0x12, 0x56, 0x34, 0xDE, 0xBC, 0x9A, 0x78, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23,
                0x01,
            ]
        );

        let mut reader = StrictReader::new(&bytes);
        assert_eq!(reader.read_u8().unwrap(), 0x12);
        assert_eq!(reader.read_u16().unwrap(), 0x3456);
        assert_eq!(reader.read_u32().unwrap(), 0x789A_BCDE);
        assert_eq!(reader.read_u64().unwrap(), 0x0123_4567_89AB_CDEF);
        reader.finish().unwrap();
    }

    #[test]
    fn truncated_read_is_rejected() {
        let mut reader = StrictReader::new(&[0u8; 3]);
        assert_eq!(reader.read_u32(), Err(SnpCodecError::Truncated));
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        let mut reader = StrictReader::new(&[0, 1, 0]);
        assert_eq!(
            reader.read_zeroes(3),
            Err(SnpCodecError::NonZeroReservedField)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut reader = StrictReader::new(&[1, 2]);
        assert_eq!(reader.read_u8().unwrap(), 1);
        assert_eq!(reader.finish(), Err(SnpCodecError::TrailingBytes));
    }

    #[test]
    fn sub_reader_enforces_exact_consumption() {
        let mut reader = StrictReader::new(&[1, 2, 3]);
        let mut sub = reader.sub(2).unwrap();
        assert_eq!(sub.read_u8().unwrap(), 1);
        assert_eq!(sub.finish(), Err(SnpCodecError::TrailingBytes));
        assert_eq!(reader.read_u8().unwrap(), 3);
        reader.finish().unwrap();
    }

    #[test]
    fn short_destination_is_rejected() {
        let mut bytes = [0u8; 1];
        let mut writer = StrictWriter::new(&mut bytes);
        assert_eq!(writer.write_u16(0x1234), Err(SnpCodecError::BufferTooSmall));
    }

    #[test]
    fn checked_arithmetic_rejects_overflow() {
        assert_eq!(
            checked_add(usize::MAX, 1),
            Err(SnpCodecError::LengthOverflow)
        );
        assert_eq!(
            checked_mul(usize::MAX, 2),
            Err(SnpCodecError::LengthOverflow)
        );
    }

    #[test]
    fn bounded_length_rejects_oversized_value() {
        assert_eq!(bounded_length(8, 8).unwrap(), 8);
        assert_eq!(bounded_length(9, 8), Err(SnpCodecError::RecordTooLarge));
    }

    #[test]
    fn bounded_read_checks_limit_before_consuming_input() {
        let mut reader = StrictReader::new(&[1, 2, 3]);
        assert_eq!(
            reader.read_bounded_bytes(3, 2),
            Err(SnpCodecError::RecordTooLarge)
        );
        assert_eq!(reader.consumed(), 0);
        assert_eq!(reader.read_bounded_bytes(2, 2).unwrap(), &[1, 2]);
        assert_eq!(reader.read_u8().unwrap(), 3);
        reader.finish().unwrap();
    }

    #[test]
    fn exact_length_rejects_mismatch() {
        exact_length(8, 8).unwrap();
        assert_eq!(exact_length(7, 8), Err(SnpCodecError::InvalidLength));
    }
}
