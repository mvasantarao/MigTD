// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Frozen Venice history contract. Inputs must come from an authenticated-claims
//! adapter; validating these logical fields does not authenticate a raw report.

use super::{
    evidence_header::SnpTcbProfileV1,
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VeniceTcbV1 {
    pub fmc: u8,
    pub tee: u8,
    pub snp: u8,
}

impl VeniceTcbV1 {
    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(bytes);
        let value = Self {
            fmc: reader.read_u8()?,
            tee: reader.read_u8()?,
            snp: reader.read_u8()?,
        };
        reader.read_zeroes(5)?;
        reader.finish()?;
        Ok(value)
    }

    pub fn encode_exact(&self) -> [u8; 8] {
        [self.fmc, self.tee, self.snp, 0, 0, 0, 0, 0]
    }

    pub fn component_min(&self, other: &Self) -> Self {
        Self {
            fmc: self.fmc.min(other.fmc),
            tee: self.tee.min(other.tee),
            snp: self.snp.min(other.snp),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VeniceEtcbV1 {
    pub ip_key_manager: u8,
    pub mp1: u8,
    pub art_fmc: u8,
    pub art_rt: u8,
    pub had_driver: u8,
    pub boot_driver: u8,
    pub pre_esid: u8,
    pub tmpm: u8,
    pub microcode: u8,
    pub soc_driver: u8,
    pub asp_os_driver: u8,
    pub fhp_driver: u8,
    pub dpe_driver: u8,
    pub arg: u8,
}

impl VeniceEtcbV1 {
    fn from_defined(bytes: [u8; 14]) -> Self {
        Self {
            ip_key_manager: bytes[0],
            mp1: bytes[1],
            art_fmc: bytes[2],
            art_rt: bytes[3],
            had_driver: bytes[4],
            boot_driver: bytes[5],
            pre_esid: bytes[6],
            tmpm: bytes[7],
            microcode: bytes[8],
            soc_driver: bytes[9],
            asp_os_driver: bytes[10],
            fhp_driver: bytes[11],
            dpe_driver: bytes[12],
            arg: bytes[13],
        }
    }

    pub fn defined_components(&self) -> [u8; 14] {
        [
            self.ip_key_manager,
            self.mp1,
            self.art_fmc,
            self.art_rt,
            self.had_driver,
            self.boot_driver,
            self.pre_esid,
            self.tmpm,
            self.microcode,
            self.soc_driver,
            self.asp_os_driver,
            self.fhp_driver,
            self.dpe_driver,
            self.arg,
        ]
    }

    pub fn from_report_bytes(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(bytes);
        let defined = reader.read_array()?;
        reader.read_zeroes(18)?;
        reader.finish()?;
        Ok(Self::from_defined(defined))
    }

    pub fn to_report_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..14].copy_from_slice(&self.defined_components());
        bytes
    }

    pub fn component_min(&self, other: &Self) -> Self {
        let left = self.defined_components();
        let right = other.defined_components();
        Self::from_defined(core::array::from_fn(|i| left[i].min(right[i])))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationHistoryError {
    Codec(SnpCodecError),
    UnsupportedReportVersion,
    UnsupportedProfile,
    MissingValidHistory,
    TenantMaBindingMismatch,
    InitialMaIdentityMismatch,
    HistoryMismatch,
    ArgSvnBelowMinimum,
}

impl From<SnpCodecError> for MigrationHistoryError {
    fn from(error: SnpCodecError) -> Self {
        Self::Codec(error)
    }
}

/// Logical fields supplied by the future authenticated-claims adapter, never
/// host-proposed launch values. No parser for the conflicting raw layout is implied.
pub struct TenantHistoryInputV1<'a> {
    pub report_version: u32,
    pub profile: SnpTcbProfileV1,
    pub launch_tcb: [u8; 8],
    pub launch_etcb: [u8; 32],
    pub launch_mitigation_vector: u64,
    pub report_id_ma: [u8; 32],
    pub migration_data_valid: bool,
    pub migration_data: Option<&'a [u8; 64]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationDataV1 {
    pub min_launch_tcb: VeniceTcbV1,
    pub min_launch_mit_vector: u64,
    pub min_launch_etcb: VeniceEtcbV1,
    pub init_ma_report_id: [u8; 32],
}

impl MigrationDataV1 {
    pub const FORMAT_VERSION: u8 = 1;
    pub const PROFILE: u8 = SnpTcbProfileV1::Venice as u8;
    pub const ENCODED_SIZE: usize = 64;

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        let mut bytes = [0u8; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut bytes);
        writer.write_u8(Self::FORMAT_VERSION)?;
        writer.write_u8(Self::PROFILE)?;
        writer.write_bytes(&self.min_launch_tcb.encode_exact())?;
        writer.write_u64(self.min_launch_mit_vector)?;
        writer.write_bytes(&self.min_launch_etcb.defined_components())?;
        writer.write_bytes(&self.init_ma_report_id)?;
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(bytes);
        if reader.read_u8()? != Self::FORMAT_VERSION {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        if reader.read_u8()? != Self::PROFILE {
            return Err(SnpCodecError::UnknownEnumValue);
        }
        let value = Self {
            min_launch_tcb: VeniceTcbV1::decode_exact(reader.take(8)?)?,
            min_launch_mit_vector: reader.read_u64()?,
            min_launch_etcb: VeniceEtcbV1::from_defined(reader.read_array()?),
            init_ma_report_id: reader.read_array()?,
        };
        reader.finish()?;
        Ok(value)
    }

    pub fn from_tenant(
        input: &TenantHistoryInputV1<'_>,
        verified_source_ma_report_id: &[u8; 32],
    ) -> Result<Self, MigrationHistoryError> {
        if input.report_version != 6 {
            return Err(MigrationHistoryError::UnsupportedReportVersion);
        }
        if input.profile != SnpTcbProfileV1::Venice {
            return Err(MigrationHistoryError::UnsupportedProfile);
        }
        if input.report_id_ma != *verified_source_ma_report_id {
            return Err(MigrationHistoryError::TenantMaBindingMismatch);
        }
        let launch_tcb = VeniceTcbV1::decode_exact(&input.launch_tcb)?;
        let launch_etcb = VeniceEtcbV1::from_report_bytes(&input.launch_etcb)?;
        if !input.migration_data_valid {
            return Ok(Self {
                min_launch_tcb: launch_tcb,
                min_launch_mit_vector: input.launch_mitigation_vector,
                min_launch_etcb: launch_etcb,
                init_ma_report_id: *verified_source_ma_report_id,
            });
        }
        let previous = Self::decode_exact(
            input
                .migration_data
                .ok_or(MigrationHistoryError::MissingValidHistory)?,
        )?;
        Ok(Self {
            min_launch_tcb: previous.min_launch_tcb.component_min(&launch_tcb),
            min_launch_mit_vector: previous.min_launch_mit_vector & input.launch_mitigation_vector,
            min_launch_etcb: previous.min_launch_etcb.component_min(&launch_etcb),
            init_ma_report_id: previous.init_ma_report_id,
        })
    }

    /// Also used for local handoff/recovery: compare unchanged history, not an update.
    pub fn validate_exact_history(&self, candidate: &[u8]) -> Result<(), MigrationHistoryError> {
        let candidate = Self::decode_exact(candidate)?;
        if candidate.init_ma_report_id != self.init_ma_report_id {
            return Err(MigrationHistoryError::InitialMaIdentityMismatch);
        }
        if candidate != *self {
            return Err(MigrationHistoryError::HistoryMismatch);
        }
        Ok(())
    }

    pub fn validate_installation_pair(
        &self,
        source: &[u8],
        destination: &[u8],
    ) -> Result<(), MigrationHistoryError> {
        self.validate_exact_history(source)?;
        self.validate_exact_history(destination)
    }

    pub fn validate_authorization_initial_ma(
        &self,
        report_id: &[u8],
    ) -> Result<(), MigrationHistoryError> {
        if report_id.len() != 32 {
            return Err(SnpCodecError::InvalidLength.into());
        }
        if report_id != self.init_ma_report_id {
            return Err(MigrationHistoryError::InitialMaIdentityMismatch);
        }
        Ok(())
    }
}

/// Absolute policy admission on authenticated CURRENT_ETCB, not launch history.
pub fn validate_current_arg_floor(
    current_etcb: &[u8],
    minimum_arg_svn: u8,
) -> Result<(), MigrationHistoryError> {
    if VeniceEtcbV1::from_report_bytes(current_etcb)?.arg < minimum_arg_svn {
        return Err(MigrationHistoryError::ArgSvnBelowMinimum);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: &str = "010309020b00000000005555aaaaccccf0f01415161718191a1b1c1d1e1f2021808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const NEXT: &str = "010308020a00000000000505aaaac0c0c0c00a150c170e19101b121d141f1621808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const ZERO: &str = "0103000000000000000000000000000000000000000000000000000000000000808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), 2 * N);
        core::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
    }

    fn identity() -> [u8; 32] {
        core::array::from_fn(|i| 0x80 + i as u8)
    }

    fn initial<'a>() -> TenantHistoryInputV1<'a> {
        let mut etcb = [0u8; 32];
        for (i, byte) in etcb[..14].iter_mut().enumerate() {
            *byte = 20 + i as u8;
        }
        TenantHistoryInputV1 {
            report_version: 6,
            profile: SnpTcbProfileV1::Venice,
            launch_tcb: [9, 2, 11, 0, 0, 0, 0, 0],
            launch_etcb: etcb,
            launch_mitigation_vector: 0xF0F0_CCCC_AAAA_5555,
            report_id_ma: identity(),
            migration_data_valid: false,
            migration_data: None,
        }
    }

    fn first() -> MigrationDataV1 {
        MigrationDataV1::from_tenant(&initial(), &identity()).unwrap()
    }

    fn next_input(previous: &[u8; 64]) -> TenantHistoryInputV1<'_> {
        let mut input = initial();
        input.launch_tcb = [8, 9, 10, 0, 0, 0, 0, 0];
        for (i, byte) in input.launch_etcb[..14].iter_mut().enumerate() {
            *byte = if i % 2 == 0 {
                10 + i as u8
            } else {
                40 + i as u8
            };
        }
        input.launch_mitigation_vector = 0xCCCC_F0F0_FFFF_0F0F;
        input.migration_data_valid = true;
        input.migration_data = Some(previous);
        input
    }

    #[test]
    fn independent_first_and_subsequent_migration_vectors_are_exact() {
        let first = first();
        let encoded = first.encode_exact().unwrap();
        assert_eq!(encoded, hex::<64>(FIRST));
        assert_eq!(MigrationDataV1::decode_exact(&encoded).unwrap(), first);
        assert_eq!(&encoded[..2], &[1, 3]);
        assert_eq!(&encoded[2..10], &[9, 2, 11, 0, 0, 0, 0, 0]);
        assert_eq!(&encoded[10..18], &0xF0F0_CCCC_AAAA_5555u64.to_le_bytes());
        assert_eq!(&encoded[18..32], &initial().launch_etcb[..14]);
        assert_eq!(&encoded[32..], &identity());
        let next = MigrationDataV1::from_tenant(&next_input(&encoded), &identity()).unwrap();
        assert_eq!(next.encode_exact().unwrap(), hex::<64>(NEXT));
        assert_eq!(
            next.min_launch_tcb,
            VeniceTcbV1 {
                fmc: 8,
                tee: 2,
                snp: 10
            }
        );
        for (bytes, hash) in [
            (hex::<64>(FIRST), "d69a703a75c0acf4959fc952e18ee5328c5f78ef0a036f4efbf571598a7926e6d984aa2f9f305c8bd1f434ac62afe0e4"),
            (hex::<64>(NEXT), "16e243fc1d85e72d417bbccdff5b50be403550489fea90da46c785bf986ae9b412f3e8b817e3dcc981f14c3791117f9f"),
            (hex::<64>(ZERO), "9cd1411b29f9aae117caa6c74b1c3cd0d95bcea88ea1fd21a41cad159cbc5a31314d947112d86cc81c052a8516832682"),
        ] {
            assert_eq!(super::super::purpose_binding::sha384(&bytes), hex::<48>(hash));
        }
    }

    #[test]
    fn invalid_history_is_ignored_not_parsed_or_used_as_zero_minima() {
        let garbage = [0xff; 64];
        let zeros = [0; 64];
        for opaque in [&garbage, &zeros] {
            let mut input = initial();
            input.migration_data = Some(opaque);
            assert_eq!(
                MigrationDataV1::from_tenant(&input, &identity()).unwrap(),
                first()
            );
        }
    }

    #[test]
    fn previously_valid_history_must_be_present_and_canonical() {
        let previous = first().encode_exact().unwrap();
        let mut input = next_input(&previous);
        input.migration_data = None;
        assert_eq!(
            MigrationDataV1::from_tenant(&input, &identity()),
            Err(MigrationHistoryError::MissingValidHistory)
        );
        let malformed = [0xff; 64];
        input.migration_data = Some(&malformed);
        assert_eq!(
            MigrationDataV1::from_tenant(&input, &identity()),
            Err(MigrationHistoryError::Codec(
                SnpCodecError::UnsupportedVersion
            ))
        );
    }

    #[test]
    fn initialization_requires_version_6_venice_and_exact_source_ma_binding() {
        for version in [0, 1, 2, 3, 4, 5, 7, u32::MAX] {
            let mut input = initial();
            input.report_version = version;
            assert_eq!(
                MigrationDataV1::from_tenant(&input, &identity()),
                Err(MigrationHistoryError::UnsupportedReportVersion)
            );
        }
        for profile in [SnpTcbProfileV1::MilanGenoa, SnpTcbProfileV1::Turin] {
            let mut input = initial();
            input.profile = profile;
            assert_eq!(
                MigrationDataV1::from_tenant(&input, &identity()),
                Err(MigrationHistoryError::UnsupportedProfile)
            );
        }
        for i in 0..32 {
            let mut input = initial();
            input.report_id_ma[i] ^= 1;
            assert_eq!(
                MigrationDataV1::from_tenant(&input, &identity()),
                Err(MigrationHistoryError::TenantMaBindingMismatch)
            );
        }
    }

    #[test]
    fn venice_tcb_uses_fmc_tee_snp_not_legacy_bootloader_microcode_positions() {
        let bytes = [1, 2, 3, 0, 0, 0, 0, 0];
        let tcb = VeniceTcbV1::decode_exact(&bytes).unwrap();
        assert_eq!(
            tcb,
            VeniceTcbV1 {
                fmc: 1,
                tee: 2,
                snp: 3
            }
        );
        assert_eq!(tcb.encode_exact(), bytes);
        for offset in 3..8 {
            for byte in 1..=u8::MAX {
                let mut changed = bytes;
                changed[offset] = byte;
                assert_eq!(
                    VeniceTcbV1::decode_exact(&changed),
                    Err(SnpCodecError::NonZeroReservedField)
                );
            }
        }
        for end in 0..8 {
            assert!(VeniceTcbV1::decode_exact(&bytes[..end]).is_err());
        }
        assert!(VeniceTcbV1::decode_exact(&[0; 9]).is_err());
    }

    #[test]
    fn all_fourteen_etcb_components_have_exact_abi_order_and_reserved_bits_fail() {
        let mut raw = [0u8; 32];
        for (i, b) in raw[..14].iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        let etcb = VeniceEtcbV1::from_report_bytes(&raw).unwrap();
        assert_eq!(
            [
                etcb.ip_key_manager,
                etcb.mp1,
                etcb.art_fmc,
                etcb.art_rt,
                etcb.had_driver,
                etcb.boot_driver,
                etcb.pre_esid,
                etcb.tmpm,
                etcb.microcode,
                etcb.soc_driver,
                etcb.asp_os_driver,
                etcb.fhp_driver,
                etcb.dpe_driver,
                etcb.arg
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        );
        assert_eq!(etcb.to_report_bytes(), raw);
        for offset in 14..32 {
            for byte in 1..=u8::MAX {
                let mut changed = raw;
                changed[offset] = byte;
                assert_eq!(
                    VeniceEtcbV1::from_report_bytes(&changed),
                    Err(SnpCodecError::NonZeroReservedField)
                );
            }
        }
        for end in 0..32 {
            assert!(VeniceEtcbV1::from_report_bytes(&raw[..end]).is_err());
        }
        assert!(VeniceEtcbV1::from_report_bytes(&[0; 33]).is_err());
    }

    #[test]
    fn codec_rejects_all_alternate_versions_profiles_lengths_and_reserved_tcb_bytes() {
        let encoded = first().encode_exact().unwrap();
        for offset in [0, 1] {
            for byte in 0..=u8::MAX {
                if byte == encoded[offset] {
                    continue;
                }
                let mut changed = encoded;
                changed[offset] = byte;
                assert!(MigrationDataV1::decode_exact(&changed).is_err());
            }
        }
        for offset in 5..10 {
            let mut changed = encoded;
            changed[offset] = 1;
            assert_eq!(
                MigrationDataV1::decode_exact(&changed),
                Err(SnpCodecError::NonZeroReservedField)
            );
        }
        for end in 0..64 {
            assert!(MigrationDataV1::decode_exact(&encoded[..end]).is_err());
        }
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert_eq!(
            MigrationDataV1::decode_exact(&extended),
            Err(SnpCodecError::TrailingBytes)
        );
    }

    #[test]
    fn launch_input_reserved_tcb_or_etcb_bits_fail_before_history_exposure() {
        for offset in 3..8 {
            let mut input = initial();
            input.launch_tcb[offset] = 1;
            assert!(MigrationDataV1::from_tenant(&input, &identity()).is_err());
        }
        for offset in 14..32 {
            let mut input = initial();
            input.launch_etcb[offset] = 1;
            assert!(MigrationDataV1::from_tenant(&input, &identity()).is_err());
        }
    }

    #[test]
    fn higher_launch_never_increases_minima_and_zero_launch_reaches_zero_vector() {
        let previous = hex::<64>(NEXT);
        let mut input = next_input(&previous);
        input.launch_tcb = [255, 255, 255, 0, 0, 0, 0, 0];
        input.launch_etcb[..14].fill(255);
        input.launch_mitigation_vector = u64::MAX;
        assert_eq!(
            MigrationDataV1::from_tenant(&input, &identity())
                .unwrap()
                .encode_exact()
                .unwrap(),
            previous
        );
        input.launch_tcb.fill(0);
        input.launch_etcb.fill(0);
        input.launch_mitigation_vector = 0;
        assert_eq!(
            MigrationDataV1::from_tenant(&input, &identity())
                .unwrap()
                .encode_exact()
                .unwrap(),
            hex::<64>(ZERO)
        );
    }

    #[test]
    fn repeated_migrations_are_componentwise_monotone_and_keep_initial_ma() {
        let mut history = first();
        for step in 0..256u16 {
            let previous = history.encode_exact().unwrap();
            let mut input = next_input(&previous);
            input.report_id_ma = [0x55; 32];
            input.launch_tcb = [
                (step % 17) as u8,
                (step % 13) as u8,
                (step % 19) as u8,
                0,
                0,
                0,
                0,
                0,
            ];
            for (i, byte) in input.launch_etcb[..14].iter_mut().enumerate() {
                *byte = ((step + i as u16) % 23) as u8;
            }
            input.launch_mitigation_vector = u64::MAX >> (step % 64);
            let next = MigrationDataV1::from_tenant(&input, &[0x55; 32]).unwrap();
            let encoded = next.encode_exact().unwrap();
            for i in (2..5).chain(18..32) {
                assert_eq!(
                    encoded[i],
                    previous[i].min(if i < 5 {
                        input.launch_tcb[i - 2]
                    } else {
                        input.launch_etcb[i - 18]
                    })
                );
            }
            assert_eq!(
                next.min_launch_mit_vector,
                history.min_launch_mit_vector & input.launch_mitigation_vector
            );
            assert_eq!(next.init_ma_report_id, identity());
            history = next;
        }
    }

    #[test]
    fn installation_and_local_rebind_require_byte_identical_history() {
        let expected = first();
        let encoded = expected.encode_exact().unwrap();
        expected
            .validate_installation_pair(&encoded, &encoded)
            .unwrap();
        for operation in ["planned handoff", "recovery"] {
            expected.validate_exact_history(&encoded).unwrap();
            for offset in 0..64 {
                let mut changed = encoded;
                changed[offset] ^= 1;
                assert!(
                    expected.validate_exact_history(&changed).is_err(),
                    "{operation}, byte {offset}"
                );
            }
        }
        for offset in 32..64 {
            let mut changed = encoded;
            changed[offset] ^= 1;
            assert_eq!(
                expected.validate_installation_pair(&encoded, &changed),
                Err(MigrationHistoryError::InitialMaIdentityMismatch)
            );
            assert_eq!(
                expected.validate_installation_pair(&changed, &encoded),
                Err(MigrationHistoryError::InitialMaIdentityMismatch)
            );
        }
        let mut lower = expected;
        lower.min_launch_tcb.fmc = 0;
        assert_eq!(
            expected.validate_exact_history(&lower.encode_exact().unwrap()),
            Err(MigrationHistoryError::HistoryMismatch)
        );
    }

    #[test]
    fn initial_ma_authorization_requires_all_32_exact_bytes() {
        let history = first();
        history
            .validate_authorization_initial_ma(&identity())
            .unwrap();
        for offset in 0..32 {
            let mut changed = identity();
            changed[offset] ^= 1;
            assert_eq!(
                history.validate_authorization_initial_ma(&changed),
                Err(MigrationHistoryError::InitialMaIdentityMismatch)
            );
        }
        for length in [0, 1, 31, 33, 64] {
            assert_eq!(
                history.validate_authorization_initial_ma(&vec![0; length]),
                Err(MigrationHistoryError::Codec(SnpCodecError::InvalidLength))
            );
        }
    }

    #[test]
    fn current_arg_floor_is_absolute_and_separate_from_launch_history() {
        let mut current = [0u8; 32];
        current[13] = 200;
        validate_current_arg_floor(&current, 200).unwrap();
        assert_eq!(
            validate_current_arg_floor(&current, 201),
            Err(MigrationHistoryError::ArgSvnBelowMinimum)
        );
        let mut input = initial();
        input.launch_etcb[13] = 1;
        let history = MigrationDataV1::from_tenant(&input, &identity()).unwrap();
        assert_eq!(history.min_launch_etcb.arg, 1);
        validate_current_arg_floor(&current, 100).unwrap();
        current[14] = 1;
        assert!(validate_current_arg_floor(&current, 0).is_err());
    }
}
