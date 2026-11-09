// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Frozen P0.3 purpose preimages. These helpers do not authorize firmware operations.

use super::{
    report_data_context::{
        ReportDataContextV1, SnpEvidencePurposeV1, SnpMaRoleV1, SHA384_DIGEST_SIZE,
        TENANT_REPORT_ID_SIZE,
    },
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};
use crate::{
    traits::SnpEvidenceVerifier,
    types::{SnpEvidenceVerificationRequest, SnpReportRequestKind, SnpVerificationError},
};

const TENANT_SET_DOMAIN: &[u8] = b"SNP-LM-TENANT-SET-v1";
const RESULT_SET_DOMAIN: &[u8] = b"SNP-LM-REBIND-RESULT-SET-v1";
const INSTALLATION_DOMAIN: &[u8] = b"SNP-LM-INSTALLATION-RESULT-v1";
const POST_INSTALL_DOMAIN: &[u8] = b"SNP-LM-POST-INSTALL-v1";
const PLANNED_DOMAIN: &[u8] = b"SNP-LM-PLANNED-HANDOFF-v1";
const RECOVERY_DOMAIN: &[u8] = b"SNP-LM-RECOVERY-HANDOFF-v1";

pub(crate) fn sha384(bytes: &[u8]) -> [u8; SHA384_DIGEST_SIZE] {
    finish_sha384(ring::digest::digest(&ring::digest::SHA384, bytes))
}

fn finish_sha384(digest: ring::digest::Digest) -> [u8; SHA384_DIGEST_SIZE] {
    let mut bytes = [0u8; SHA384_DIGEST_SIZE];
    bytes.copy_from_slice(digest.as_ref());
    bytes
}

pub use crate::tenant_identity::VerifiedTenantIdentity as VerifiedTenantReportIdV1;

impl VerifiedTenantReportIdV1 {
    pub fn verify(
        verifier: &dyn SnpEvidenceVerifier,
        request: &SnpEvidenceVerificationRequest<'_>,
    ) -> Result<Self, SnpVerificationError> {
        if request.report_request != SnpReportRequestKind::HostRequestedTenant
            || request.evidence.binding() != crate::types::MaEvidenceBinding::RequestedReportData
        {
            return Err(SnpVerificationError::InvalidEvidence);
        }
        let params = super::qvl::validate::AttestationVerificationParams::for_request(
            request.evidence.report(),
            request.expected_report_data,
            request.report_request,
        );
        super::qvl::validate::validate(&params)
            .map_err(|_| SnpVerificationError::InvalidEvidence)?;
        let verified = verifier.verify_evidence(request)?;
        if verified.trust != request.trust {
            return Err(SnpVerificationError::UnsupportedTrust);
        }
        if verified.binding != request.evidence.binding() {
            return Err(SnpVerificationError::InvalidEvidence);
        }
        let mut id = [0u8; TENANT_REPORT_ID_SIZE];
        id.copy_from_slice(&request.evidence.report()[0x140..0x160]);
        Ok(Self::from_verified_report_id(id))
    }
}

#[derive(Debug)]
pub struct CanonicalTenantSetV1<'a> {
    ids: &'a [VerifiedTenantReportIdV1],
    count: u32,
}

impl<'a> CanonicalTenantSetV1<'a> {
    pub fn new(count: u32, ids: &'a [VerifiedTenantReportIdV1]) -> SnpCodecResult<Self> {
        if ids.is_empty()
            || usize::try_from(count).map_err(|_| SnpCodecError::InvalidCount)? != ids.len()
        {
            return Err(SnpCodecError::InvalidCount);
        }
        if ids
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(Self { ids, count })
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u32(self.count)?;
        for id in self.ids {
            writer.write_bytes(id.as_bytes())?;
        }
        Ok(())
    }

    pub fn digest(&self) -> [u8; SHA384_DIGEST_SIZE] {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA384);
        hash.update(TENANT_SET_DOMAIN);
        hash.update(&self.count.to_le_bytes());
        for id in self.ids {
            hash.update(id.as_bytes());
        }
        finish_sha384(hash.finish())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareRebindResultV1 {
    pub tenant_report_id: [u8; TENANT_REPORT_ID_SIZE],
    pub raw_status: u32,
    pub binding_changed: u8,
    pub previous_ma_report_id: [u8; 32],
    pub resulting_ma_report_id: [u8; 32],
}

impl FirmwareRebindResultV1 {
    pub const ENCODED_SIZE: usize = 104;

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        if self.binding_changed > 1 {
            return Err(SnpCodecError::UnknownEnumValue);
        }
        let mut encoded = [0u8; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut encoded);
        writer.write_bytes(&self.tenant_report_id)?;
        writer.write_u32(self.raw_status)?;
        writer.write_u8(self.binding_changed)?;
        writer.write_zeroes(3)?;
        writer.write_bytes(&self.previous_ma_report_id)?;
        writer.write_bytes(&self.resulting_ma_report_id)?;
        Ok(encoded)
    }

    pub fn decode_exact(encoded: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(encoded);
        let value = Self {
            tenant_report_id: reader.read_array()?,
            raw_status: reader.read_u32()?,
            binding_changed: reader.read_u8()?,
            previous_ma_report_id: {
                reader.read_zeroes(3)?;
                reader.read_array()?
            },
            resulting_ma_report_id: reader.read_array()?,
        };
        reader.finish()?;
        value.encode_exact()?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct CanonicalFirmwareResultSetV1<'a> {
    tenant_set_digest: [u8; SHA384_DIGEST_SIZE],
    results: &'a [FirmwareRebindResultV1],
    count: u32,
    previous_ma_report_id: [u8; 32],
    new_ma_report_id: [u8; 32],
}

impl<'a> CanonicalFirmwareResultSetV1<'a> {
    pub fn new(
        count: u32,
        results: &'a [FirmwareRebindResultV1],
        tenants: &CanonicalTenantSetV1<'_>,
        previous_ma_report_id: [u8; 32],
        new_ma_report_id: [u8; 32],
    ) -> SnpCodecResult<Self> {
        if count != tenants.count || results.len() != tenants.ids.len() {
            return Err(SnpCodecError::InvalidCount);
        }
        for (result, tenant) in results.iter().zip(tenants.ids) {
            result.encode_exact()?;
            let success = result.raw_status == 0;
            if &result.tenant_report_id != tenant.as_bytes()
                || result.previous_ma_report_id != previous_ma_report_id
                || result.binding_changed != u8::from(success)
                || result.resulting_ma_report_id
                    != if success {
                        new_ma_report_id
                    } else {
                        previous_ma_report_id
                    }
            {
                return Err(SnpCodecError::NonCanonicalEncoding);
            }
        }
        Ok(Self {
            tenant_set_digest: tenants.digest(),
            results,
            count,
            previous_ma_report_id,
            new_ma_report_id,
        })
    }

    pub fn encode(&self, writer: &mut StrictWriter<'_>) -> SnpCodecResult<()> {
        writer.write_u32(self.count)?;
        for result in self.results {
            writer.write_bytes(&result.encode_exact()?)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> SnpCodecResult<[u8; SHA384_DIGEST_SIZE]> {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA384);
        hash.update(RESULT_SET_DOMAIN);
        hash.update(&self.count.to_le_bytes());
        for result in self.results {
            hash.update(&result.encode_exact()?);
        }
        Ok(finish_sha384(hash.finish()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostInstallBindingV1 {
    request_id: u64,
    tenant_report_id: [u8; 32],
    destination_ma_report_id: [u8; 32],
    migration_data_digest: [u8; SHA384_DIGEST_SIZE],
    installation_result_digest: [u8; SHA384_DIGEST_SIZE],
}

impl PostInstallBindingV1 {
    /// The caller supplies the actual firmware outcome and persisted bytes, not a proposal.
    pub fn after_successful_persistence(
        request_id: u64,
        tenant_report_id: [u8; 32],
        destination_ma_report_id: [u8; 32],
        installed_migration_data: &[u8; 64],
        raw_status: u32,
        persisted: bool,
    ) -> SnpCodecResult<Self> {
        if raw_status != 0 || !persisted {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        let migration_data_digest = sha384(installed_migration_data);
        let mut preimage = [0u8; 89];
        let mut writer = StrictWriter::new(&mut preimage);
        writer.write_bytes(INSTALLATION_DOMAIN)?;
        writer.write_u16(1)?;
        writer.write_u32(0)?;
        writer.write_u16(0x0003)?;
        writer.write_u8(1)?;
        writer.write_zeroes(3)?;
        writer.write_bytes(&migration_data_digest)?;
        Ok(Self {
            request_id,
            tenant_report_id,
            destination_ma_report_id,
            migration_data_digest,
            installation_result_digest: sha384(&preimage),
        })
    }

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; 192]> {
        let mut preimage = [0u8; 192];
        let mut writer = StrictWriter::new(&mut preimage);
        writer.write_bytes(POST_INSTALL_DOMAIN)?;
        writer.write_u16(1)?;
        writer.write_u64(self.request_id)?;
        writer.write_bytes(&self.tenant_report_id)?;
        writer.write_bytes(&self.destination_ma_report_id)?;
        writer.write_bytes(&self.migration_data_digest)?;
        writer.write_bytes(&self.installation_result_digest)?;
        Ok(preimage)
    }

    pub const fn installation_result_digest(&self) -> &[u8; SHA384_DIGEST_SIZE] {
        &self.installation_result_digest
    }

    pub fn digest(&self) -> SnpCodecResult<[u8; SHA384_DIGEST_SIZE]> {
        Ok(sha384(&self.encode_exact()?))
    }

    pub fn verify_context(&self, context: &ReportDataContextV1) -> SnpCodecResult<()> {
        context.validate()?;
        if context.evidence_purpose != SnpEvidencePurposeV1::InterNodePostInstallConfirmation
            || context.role != SnpMaRoleV1::Destination
            || context.request_id != self.request_id
            || context.tenant_binding_id != self.tenant_report_id
            || context.purpose_binding_digest != self.digest()?
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpOperationStageV1 {
    PrepareAuthorization = 0x01,
    FirmwareResultConfirmation = 0x02,
}

impl SnpOperationStageV1 {
    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            1 => Ok(Self::PrepareAuthorization),
            2 => Ok(Self::FirmwareResultConfirmation),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }
}

/// Previous/new denote outgoing/incoming for planned handoff and failed/replacement
/// for recovery. No outgoing proof, SPDM session, secret, or routing handle is encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHandoffBindingV1 {
    pub purpose: SnpEvidencePurposeV1,
    pub stage: SnpOperationStageV1,
    pub attempt_number: u32,
    pub operation_id: [u8; 16],
    pub request_id: u64,
    pub operation_epoch: u64,
    pub deadline_unix_seconds: u64,
    pub previous_ma_report_id: [u8; 32],
    pub new_ma_report_id: [u8; 32],
    pub tenant_set_digest: [u8; SHA384_DIGEST_SIZE],
    pub ma_policy_identity_digest: [u8; SHA384_DIGEST_SIZE],
    pub firmware_result_set_digest: [u8; SHA384_DIGEST_SIZE],
}

impl LocalHandoffBindingV1 {
    fn domain(purpose: SnpEvidencePurposeV1) -> SnpCodecResult<&'static [u8]> {
        match purpose {
            SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization => Ok(PLANNED_DOMAIN),
            SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization => Ok(RECOVERY_DOMAIN),
            _ => Err(SnpCodecError::NonCanonicalEncoding),
        }
    }

    fn validate_stage(&self) -> SnpCodecResult<()> {
        let zero = self.firmware_result_set_digest == [0; SHA384_DIGEST_SIZE];
        if zero != (self.stage == SnpOperationStageV1::PrepareAuthorization) {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<Vec<u8>> {
        self.validate_stage()?;
        let domain = Self::domain(self.purpose)?;
        let mut encoded = vec![0u8; domain.len() + 256];
        let mut writer = StrictWriter::new(&mut encoded);
        writer.write_bytes(domain)?;
        writer.write_u16(1)?;
        writer.write_u8(self.stage as u8)?;
        writer.write_zeroes(1)?;
        writer.write_u32(self.attempt_number)?;
        writer.write_bytes(&self.operation_id)?;
        writer.write_u64(self.request_id)?;
        writer.write_u64(self.operation_epoch)?;
        writer.write_u64(self.deadline_unix_seconds)?;
        writer.write_bytes(&self.previous_ma_report_id)?;
        writer.write_bytes(&self.new_ma_report_id)?;
        writer.write_bytes(&self.tenant_set_digest)?;
        writer.write_bytes(&self.ma_policy_identity_digest)?;
        writer.write_bytes(&self.firmware_result_set_digest)?;
        Ok(encoded)
    }

    pub fn decode_exact(purpose: SnpEvidencePurposeV1, encoded: &[u8]) -> SnpCodecResult<Self> {
        let domain = Self::domain(purpose)?;
        let mut reader = StrictReader::new(encoded);
        if reader.take(domain.len())? != domain {
            return Err(SnpCodecError::InvalidMagic);
        }
        if reader.read_u16()? != 1 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        let stage = SnpOperationStageV1::decode(&mut reader)?;
        reader.read_zeroes(1)?;
        let value = Self {
            purpose,
            stage,
            attempt_number: reader.read_u32()?,
            operation_id: reader.read_array()?,
            request_id: reader.read_u64()?,
            operation_epoch: reader.read_u64()?,
            deadline_unix_seconds: reader.read_u64()?,
            previous_ma_report_id: reader.read_array()?,
            new_ma_report_id: reader.read_array()?,
            tenant_set_digest: reader.read_array()?,
            ma_policy_identity_digest: reader.read_array()?,
            firmware_result_set_digest: reader.read_array()?,
        };
        reader.finish()?;
        value.validate_stage()?;
        Ok(value)
    }

    pub fn digest(
        &self,
        tenants: &CanonicalTenantSetV1<'_>,
        results: Option<&CanonicalFirmwareResultSetV1<'_>>,
    ) -> SnpCodecResult<[u8; SHA384_DIGEST_SIZE]> {
        if self.tenant_set_digest != tenants.digest() {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        match (self.stage, results) {
            (SnpOperationStageV1::PrepareAuthorization, None) => {}
            (SnpOperationStageV1::FirmwareResultConfirmation, Some(results))
                if results.tenant_set_digest == self.tenant_set_digest
                    && results.previous_ma_report_id == self.previous_ma_report_id
                    && results.new_ma_report_id == self.new_ma_report_id
                    && results.digest()? == self.firmware_result_set_digest => {}
            _ => return Err(SnpCodecError::NonCanonicalEncoding),
        }
        Ok(sha384(&self.encode_exact()?))
    }

    /// `expected` must come from the authoritative current operation, not peer input.
    pub fn validate_current(&self, expected: &Self, now_unix_seconds: u64) -> SnpCodecResult<()> {
        if self != expected || now_unix_seconds >= self.deadline_unix_seconds {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        self.encode_exact()?;
        Ok(())
    }

    /// Checks canonical binding; freshness additionally requires `validate_current`.
    pub fn verify_context(
        &self,
        context: &ReportDataContextV1,
        tenants: &CanonicalTenantSetV1<'_>,
        results: Option<&CanonicalFirmwareResultSetV1<'_>>,
    ) -> SnpCodecResult<()> {
        context.validate()?;
        if context.evidence_purpose != self.purpose
            || context.request_id != self.request_id
            || context.ma_policy_identity_digest != self.ma_policy_identity_digest
            || context.purpose_binding_digest != self.digest(tenants, results)?
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::report_data_context::SnpMigrationAlgorithmV1;
    use super::*;
    use crate::types::{
        MaEvidence, MaEvidenceBinding, SnpVerificationCollateral, SnpVerifierTrust, TcbStatus,
        VerifiedSnpEvidence,
    };

    const REQUEST_ID: u64 = 0x0102_0304_0506_0708;
    const TENANTS_DIGEST: &str = "f6f95d694c34c88e790289e70ca6bb57b26ce91f6792dab23bc3857ad5484022e6b040028bcbee8e027ba05f9acd9d0f";
    const RESULTS_DIGEST: &str = "c7f5f3f3b9fdbf536f0d45e92785fb1a6db3254550e64a7f2d8d76d4505f6ac03ff962496d45dff623dc71499948daa1";

    fn hex(value: &str) -> [u8; 48] {
        assert_eq!(value.len(), 96);
        std::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
    }

    fn ids() -> [VerifiedTenantReportIdV1; 2] {
        [
            VerifiedTenantReportIdV1::from_verified_report_id([0x11; 32]),
            VerifiedTenantReportIdV1::from_verified_report_id([0x22; 32]),
        ]
    }

    fn results() -> [FirmwareRebindResultV1; 2] {
        std::array::from_fn(|i| FirmwareRebindResultV1 {
            tenant_report_id: [if i == 0 { 0x11 } else { 0x22 }; 32],
            raw_status: if i == 0 { 0 } else { 0x16 },
            binding_changed: u8::from(i == 0),
            previous_ma_report_id: [0x55; 32],
            resulting_ma_report_id: [if i == 0 { 0x66 } else { 0x55 }; 32],
        })
    }

    fn local(purpose: SnpEvidencePurposeV1) -> LocalHandoffBindingV1 {
        LocalHandoffBindingV1 {
            purpose,
            stage: SnpOperationStageV1::PrepareAuthorization,
            attempt_number: 7,
            operation_id: [0x77; 16],
            request_id: REQUEST_ID,
            operation_epoch: 9,
            deadline_unix_seconds: 2_000_000_000,
            previous_ma_report_id: [0x55; 32],
            new_ma_report_id: [0x66; 32],
            tenant_set_digest: hex(TENANTS_DIGEST),
            ma_policy_identity_digest: [0x44; 48],
            firmware_result_set_digest: [0; 48],
        }
    }

    fn context(purpose: SnpEvidencePurposeV1) -> ReportDataContextV1 {
        let local = purpose as u8 >= 4;
        let recovery = purpose == SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization;
        ReportDataContextV1 {
            evidence_purpose: purpose,
            role: if local {
                SnpMaRoleV1::Incoming
            } else {
                SnpMaRoleV1::Destination
            },
            request_id: REQUEST_ID,
            negotiated_migration_version: 1,
            algorithm: if recovery {
                SnpMigrationAlgorithmV1::None
            } else if local {
                SnpMigrationAlgorithmV1::LocalHandoffSecretV1
            } else {
                SnpMigrationAlgorithmV1::Aes256GcmMigrationV1
            },
            tenant_binding_id: [if local { 0 } else { 0x11 }; 32],
            th1: [if recovery { 0 } else { 0x22 }; 48],
            purpose_binding_digest: [0x33; 48],
            ma_policy_identity_digest: [0x44; 48],
        }
    }

    fn assert_local_mutations_bind_report_data(binding: &LocalHandoffBindingV1) {
        let encoded = binding.encode_exact().unwrap();
        let mut original_context = context(binding.purpose);
        original_context.purpose_binding_digest = sha384(&encoded);
        let original_report_data = original_context.expected_report_data().unwrap();
        for offset in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            if let Ok(changed) = LocalHandoffBindingV1::decode_exact(binding.purpose, &changed) {
                let mut changed_context = original_context.clone();
                changed_context.purpose_binding_digest = sha384(&changed.encode_exact().unwrap());
                assert_ne!(
                    changed_context.expected_report_data().unwrap(),
                    original_report_data
                );
                assert!(changed.validate_current(binding, 1_999_999_999).is_err());
            }
        }
    }

    #[test]
    fn independent_context_digest_vectors_cover_all_purposes() {
        for (purpose, digest) in [
                    (SnpEvidencePurposeV1::InterNodeKeyContribution,
                     "ec53a58d0aaed60f67ce628471fb844429f81408e34e1e6b3f677f970de8bcc833991c6f24d14f45f49f769bb0e38d85"),
                    (SnpEvidencePurposeV1::InterNodeTenantAuthorization,
                     "f43323407ea776c66fcac5f713e96bdb489b08031694ec084b695846c7333c71ba634c730ec2cc0c45699e7dfc0e01d3"),
                    (SnpEvidencePurposeV1::InterNodePostInstallConfirmation,
                     "9f74e1c727de7e729adca92fb3cb15c574e0e60c13940007c3d5356a7afcdcc79487c722e271c22036ad631c0d0102d4"),
                    (SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
                     "b2f77d2268a1c016540b9a6aad87516f8d2d4deda7c7602ff4e718c38270116634e67535581ee2ebaaf10642d6fb494e"),
                    (SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization,
                     "39407261fe6c780ebd5487eae99b23f142922ec29b7eff08c9af6815d48e26f59906fe0c623464e89f501c07d42f3ed5"),
                ] {
                    let mut context = context(purpose);
                    if purpose as u8 <= 2 { context.role = SnpMaRoleV1::Source; }
                    if purpose as u8 == 4 { context.role = SnpMaRoleV1::Outgoing; }
                    let encoded = context.encode_exact().unwrap();
                    assert_eq!(encoded.len(), 220);
                    let report_data = context.expected_report_data().unwrap();
                    assert_eq!(&report_data[..48], &hex(digest));
                    assert_eq!(&report_data[48..], &[0; 16]);
                }
    }

    #[test]
    fn independent_tenant_and_firmware_result_set_vectors() {
        let ids = ids();
        let tenants = CanonicalTenantSetV1::new(2, &ids).unwrap();
        assert_eq!(tenants.digest(), hex(TENANTS_DIGEST));
        let mut encoded = [0u8; 68];
        tenants
            .encode(&mut StrictWriter::new(&mut encoded))
            .unwrap();
        assert_eq!(&encoded[..4], &2u32.to_le_bytes());
        assert_eq!(&encoded[4..36], &[0x11; 32]);
        assert_eq!(&encoded[36..], &[0x22; 32]);
        let results = results();
        let set = CanonicalFirmwareResultSetV1::new(2, &results, &tenants, [0x55; 32], [0x66; 32])
            .unwrap();
        assert_eq!(set.digest().unwrap(), hex(RESULTS_DIGEST));
        let mut encoded = [0u8; 212];
        set.encode(&mut StrictWriter::new(&mut encoded)).unwrap();
        assert_eq!(&encoded[..4], &2u32.to_le_bytes());
        for (index, result) in results.iter().enumerate() {
            let start = 4 + 104 * index;
            assert_eq!(
                FirmwareRebindResultV1::decode_exact(&encoded[start..start + 104]).unwrap(),
                *result
            );
            assert_eq!(&encoded[start + 37..start + 40], &[0; 3]);
        }
    }

    #[test]
    fn empty_duplicate_reordered_and_wrong_count_tenant_sets_fail() {
        assert!(CanonicalTenantSetV1::new(0, &[]).is_err());
        let ids = ids();
        assert!(CanonicalTenantSetV1::new(1, &ids).is_err());
        assert!(CanonicalTenantSetV1::new(3, &ids).is_err());
        assert!(CanonicalTenantSetV1::new(2, &[ids[0].clone(), ids[0].clone()]).is_err());
        assert!(CanonicalTenantSetV1::new(2, &[ids[1].clone(), ids[0].clone()]).is_err());
    }

    #[test]
    fn firmware_results_reject_missing_extra_duplicate_order_status_binding_and_identity_errors() {
        let ids = ids();
        let tenants = CanonicalTenantSetV1::new(2, &ids).unwrap();
        let original = results();
        for case in 0..10 {
            let mut results = original.clone().to_vec();
            let mut count = 2;
            match case {
                0 => {
                    results.pop();
                }
                1 => {
                    results.push(original[0].clone());
                }
                2 => {
                    results[1] = original[0].clone();
                }
                3 => results.swap(0, 1),
                4 => results[0].binding_changed = 2,
                5 => results[0].binding_changed = 0,
                6 => results[1].binding_changed = 1,
                7 => results[0].previous_ma_report_id[0] ^= 1,
                8 => results[1].resulting_ma_report_id = [0x66; 32],
                _ => count = 1,
            }
            assert!(
                CanonicalFirmwareResultSetV1::new(
                    count, &results, &tenants, [0x55; 32], [0x66; 32]
                )
                .is_err(),
                "case {case}"
            );
        }
        let encoded = original[0].encode_exact().unwrap();
        for offset in 37..40 {
            let mut changed = encoded;
            changed[offset] = 1;
            assert_eq!(
                FirmwareRebindResultV1::decode_exact(&changed),
                Err(SnpCodecError::NonZeroReservedField)
            );
        }
        for end in 0..104 {
            assert!(FirmwareRebindResultV1::decode_exact(&encoded[..end]).is_err());
        }
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(FirmwareRebindResultV1::decode_exact(&extended).is_err());
    }

    #[test]
    fn independent_post_install_vector_requires_success_and_persistence() {
        let data = std::array::from_fn(|i| i as u8);
        let binding = PostInstallBindingV1::after_successful_persistence(
            REQUEST_ID, [0x11; 32], [0x66; 32], &data, 0, true,
        )
        .unwrap();
        assert_eq!(binding.migration_data_digest, hex("9f2c9eb7116b3d7a4ba84a74a4d4eff8a5efcf54b6d7b662693c38577914c73a214766f0a175339bb0895a863824fc0a"));
        assert_eq!(binding.installation_result_digest, hex("248b7f3968e5b2b6b3760b9d5c70a9c4db95a1806cdc41016c956b9957ac8fcd258536aaac87dcae5a9506e206bae496"));
        assert_eq!(binding.digest().unwrap(), hex("41ee44ff4499362e794d83e40ededb915b0c59e227ba8fc9c9a9fe831ce6b783a73c106c7c939e8daf511fb108c5df67"));
        for (status, persisted) in [(0, false), (1, true), (1, false)] {
            assert!(PostInstallBindingV1::after_successful_persistence(
                REQUEST_ID, [0x11; 32], [0x66; 32], &data, status, persisted,
            )
            .is_err());
        }
        let mut context = context(SnpEvidencePurposeV1::InterNodePostInstallConfirmation);
        context.purpose_binding_digest = binding.digest().unwrap();
        binding.verify_context(&context).unwrap();
        let expected_report_data = context.expected_report_data().unwrap();
        for field in 0..5 {
            let mut changed = binding.clone();
            match field {
                0 => changed.request_id ^= 1,
                1 => changed.tenant_report_id[0] ^= 1,
                2 => changed.destination_ma_report_id[0] ^= 1,
                3 => changed.migration_data_digest[0] ^= 1,
                _ => changed.installation_result_digest[0] ^= 1,
            }
            let mut changed_context = context.clone();
            changed_context.request_id = changed.request_id;
            changed_context.tenant_binding_id = changed.tenant_report_id;
            changed_context.purpose_binding_digest = changed.digest().unwrap();
            assert_ne!(
                changed_context.expected_report_data().unwrap(),
                expected_report_data
            );
        }
        context.evidence_purpose = SnpEvidencePurposeV1::InterNodeTenantAuthorization;
        assert!(binding.verify_context(&context).is_err());
        for index in 0..64 {
            let mut changed = data;
            changed[index] ^= 1;
            let changed = PostInstallBindingV1::after_successful_persistence(
                REQUEST_ID, [0x11; 32], [0x66; 32], &changed, 0, true,
            )
            .unwrap();
            assert_ne!(changed.digest().unwrap(), binding.digest().unwrap());
        }
    }

    #[test]
    fn independent_planned_and_recovery_prepare_and_confirmation_vectors() {
        let ids = ids();
        let tenants = CanonicalTenantSetV1::new(2, &ids).unwrap();
        let results = results();
        let results =
            CanonicalFirmwareResultSetV1::new(2, &results, &tenants, [0x55; 32], [0x66; 32])
                .unwrap();
        for (purpose, prepare, confirmation) in [
                    (SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
                     "a3272edf71951a5b67f941c9fe07fbcb96b158cbab9628dfd69e32046695fc60ca380b2e752528252d7a1ce05da72a24",
                     "a60b5f8a76b111a132467296cb2f37079f43e66a374d2b4979bb2d8b3388e423ec3804bd970c2fe877842fa940704359"),
                    (SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization,
                     "0e4a55f9f62b8e6c5f597c180a97dde94b74a0c3127ae8cbf8e12624e2a64ab0b2851e7234f1892411b752ec66d38042",
                     "26f44077273c7e87f29c91febabbcc0dd93ade9013f5f80705f084456020b192981734e9a12275e630525f7f7445daaf"),
                ] {
                    let mut binding = local(purpose);
                    assert_local_mutations_bind_report_data(&binding);
                    assert_eq!(binding.digest(&tenants, None).unwrap(), hex(prepare));
                    let encoded = binding.encode_exact().unwrap();
                    assert_eq!(encoded.len(), if purpose as u8 == 4 { 281 } else { 282 });
                    assert_eq!(LocalHandoffBindingV1::decode_exact(purpose, &encoded).unwrap(), binding);
                    let mut context = context(purpose);
                    context.purpose_binding_digest = binding.digest(&tenants, None).unwrap();
                    binding.verify_context(&context, &tenants, None).unwrap();
                    if purpose as u8 == 4 {
                        let incoming = context.expected_report_data().unwrap();
                        context.role = SnpMaRoleV1::Outgoing;
                        binding.verify_context(&context, &tenants, None).unwrap();
                        assert_ne!(context.expected_report_data().unwrap(), incoming);
                    }
                    assert!(binding.digest(&tenants, Some(&results)).is_err());
                    binding.firmware_result_set_digest = results.digest().unwrap();
                    assert!(binding.encode_exact().is_err());
                    binding.stage = SnpOperationStageV1::FirmwareResultConfirmation;
                    assert_local_mutations_bind_report_data(&binding);
                    assert!(binding.digest(&tenants, None).is_err());
                    assert_eq!(binding.digest(&tenants, Some(&results)).unwrap(), hex(confirmation));
                    binding.firmware_result_set_digest[0] ^= 1;
                    assert!(binding.digest(&tenants, Some(&results)).is_err());
                }
    }

    #[test]
    fn recovery_canonical_record_rejects_replay_mutations_unknown_fields_and_routing_suffixes() {
        let purpose = SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization;
        let original = local(purpose);
        original.validate_current(&original, 1_999_999_999).unwrap();
        assert!(original.validate_current(&original, 2_000_000_000).is_err());
        let encoded = original.encode_exact().unwrap();
        let domain = RECOVERY_DOMAIN.len();
        for offset in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            if let Ok(changed) = LocalHandoffBindingV1::decode_exact(purpose, &changed) {
                assert!(changed.validate_current(&original, 1_999_999_999).is_err());
                assert_ne!(sha384(&changed.encode_exact().unwrap()), sha384(&encoded));
            }
        }
        for (offset, byte, error) in [
            (domain, 2, SnpCodecError::UnsupportedVersion),
            (domain + 2, 0, SnpCodecError::UnknownEnumValue),
            (domain + 2, 3, SnpCodecError::UnknownEnumValue),
            (domain + 3, 1, SnpCodecError::NonZeroReservedField),
        ] {
            let mut changed = encoded.clone();
            changed[offset] = byte;
            assert_eq!(
                LocalHandoffBindingV1::decode_exact(purpose, &changed),
                Err(error)
            );
        }
        for end in 0..encoded.len() {
            assert!(LocalHandoffBindingV1::decode_exact(purpose, &encoded[..end]).is_err());
        }
        for suffix in [vec![0], vec![0x11; 32], vec![0x22; 48], vec![0x33; 1184]] {
            let mut extended = encoded.clone();
            extended.extend_from_slice(&suffix);
            assert_eq!(
                LocalHandoffBindingV1::decode_exact(purpose, &extended),
                Err(SnpCodecError::TrailingBytes)
            );
        }
        assert!(LocalHandoffBindingV1::decode_exact(
            SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization,
            &encoded
        )
        .is_err());
    }

    struct TestVerifier(bool);

    impl SnpEvidenceVerifier for TestVerifier {
        fn verify_evidence(
            &self,
            request: &SnpEvidenceVerificationRequest<'_>,
        ) -> Result<VerifiedSnpEvidence, SnpVerificationError> {
            if !self.0 {
                return Err(SnpVerificationError::CryptographicVerification);
            }
            Ok(VerifiedSnpEvidence {
                binding: request.evidence.binding(),
                tcb_status: TcbStatus::UpToDate,
                platform_tcb: None,
                trust: request.trust,
            })
        }
    }

    #[test]
    fn typed_tenant_ids_require_host_semantics_and_a_successful_verifier() {
        let mut report = [0u8; 1184];
        report[..4].copy_from_slice(&6u32.to_le_bytes());
        report[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
        report[0x140..0x160].fill(0x11);
        let collateral = SnpVerificationCollateral::new(vec![], vec![]);
        let evidence = MaEvidence::new(report, MaEvidenceBinding::RequestedReportData);
        let mut request = SnpEvidenceVerificationRequest {
            evidence: &evidence,
            collateral: &collateral,
            expected_report_data: &[0; 48],
            report_request: SnpReportRequestKind::HostRequestedTenant,
            trust: SnpVerifierTrust::PinnedMilanArkTest,
        };
        assert_eq!(
            VerifiedTenantReportIdV1::verify(&TestVerifier(false), &request),
            Err(SnpVerificationError::CryptographicVerification)
        );
        assert_eq!(
            VerifiedTenantReportIdV1::verify(&TestVerifier(true), &request)
                .unwrap()
                .as_bytes(),
            &[0x11; 32]
        );
        let captured = MaEvidence::new(report, MaEvidenceBinding::CapturedFixture);
        request.evidence = &captured;
        assert_eq!(
            VerifiedTenantReportIdV1::verify(&TestVerifier(true), &request),
            Err(SnpVerificationError::InvalidEvidence)
        );
        request.evidence = &evidence;
        request.report_request = SnpReportRequestKind::GuestRequestedMa { expected_vmpl: 0 };
        assert_eq!(
            VerifiedTenantReportIdV1::verify(&TestVerifier(true), &request),
            Err(SnpVerificationError::InvalidEvidence)
        );
    }

    #[test]
    fn canonical_ma_context_is_required_before_verifier_dispatch() {
        let context = context(SnpEvidencePurposeV1::LocalRecoveryHandoffAuthorization);
        let mut report = [0u8; 1184];
        report[..4].copy_from_slice(&6u32.to_le_bytes());
        report[0x50..0x90].copy_from_slice(&context.expected_report_data().unwrap());
        let collateral = SnpVerificationCollateral::new(vec![], vec![]);
        let evidence = MaEvidence::new(report, MaEvidenceBinding::RequestedReportData);
        assert!(context
            .verify_ma_evidence(
                &TestVerifier(true),
                &evidence,
                &collateral,
                0,
                SnpVerifierTrust::PinnedMilanArkTest
            )
            .is_ok());
        assert_eq!(
            context.verify_ma_evidence(
                &TestVerifier(false),
                &evidence,
                &collateral,
                0,
                SnpVerifierTrust::PinnedMilanArkTest
            ),
            Err(SnpVerificationError::CryptographicVerification)
        );
        let mut changed = context.clone();
        changed.request_id ^= 1;
        assert_eq!(
            changed.verify_ma_evidence(
                &TestVerifier(true),
                &evidence,
                &collateral,
                0,
                SnpVerifierTrust::PinnedMilanArkTest
            ),
            Err(SnpVerificationError::ReportDataBinding)
        );
        assert_eq!(
            context.verify_ma_evidence(
                &TestVerifier(true),
                &evidence,
                &collateral,
                1,
                SnpVerifierTrust::PinnedMilanArkTest
            ),
            Err(SnpVerificationError::ReportDataBinding)
        );
        let captured = MaEvidence::new(report, MaEvidenceBinding::CapturedFixture);
        assert_eq!(
            context.verify_ma_evidence(
                &TestVerifier(true),
                &captured,
                &collateral,
                0,
                SnpVerifierTrust::PinnedMilanArkTest
            ),
            Err(SnpVerificationError::InvalidEvidence)
        );
    }
}
