// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Direct-random V2 key ownership and canonical nonsecret session context.
//! Inputs are independently admitted local claims, never peer-proposed digests.

use core::fmt;
use zeroize::Zeroizing;

use super::{
    direct_authorization::{DirectAuthorizationErrorV2, TenantAuthorizationContextV2},
    migration_data::MigrationDataV1,
    purpose_binding::sha384,
    report_data_context::{ReportDataContextV1, SnpMaRoleV1},
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};
use crate::{
    random::{RandomSource, Secret32},
    tenant_replay::VerifiedTenantAuthorizationV1,
    types::{MigrationRole, SnpVerifierTrust},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpSessionReferenceV2 {
    pub request_id: u64,
    pub session_context_digest: [u8; 48],
}

/// Complete evidence includes every authenticated emulator supplement byte.
/// Approval hashes and history come from the already-admitted claims adapter;
/// constructing this logical recipe does not perform policy/history admission.
pub struct SessionClaimsV2 {
    pub source_complete_evidence_digest: [u8; 48],
    pub destination_complete_evidence_digest: [u8; 48],
    pub tenant_collateral_digest: [u8; 48],
    pub migration_data: [u8; 64],
    pub trust: SnpVerifierTrust,
    pub interpretation: u16,
    pub approval_profile: u16,
    pub source_approval_digest: [u8; 48],
    pub destination_approval_digest: [u8; 48],
    pub initial_authorization_digest: [u8; 48],
}

/// Locally reconstructed reference, not durable replay or firmware authority.
#[derive(Clone)]
pub struct MigrationSessionContextV2 {
    reference: SnpSessionReferenceV2,
    source: ReportDataContextV1,
    destination: ReportDataContextV1,
    migration_data: [u8; 64],
    role: MigrationRole,
    authorization_digest: [u8; 48],
}

impl MigrationSessionContextV2 {
    pub const PREIMAGE_SIZE: usize = 703;

    pub fn new(
        context: &TenantAuthorizationContextV2,
        authorization: &VerifiedTenantAuthorizationV1,
        claims: &SessionClaimsV2,
    ) -> Result<Self, DirectAuthorizationErrorV2> {
        let binding = context.replay_binding()?;
        if authorization.binding() != &binding || claims.trust != binding.as_stored().trust {
            return Err(DirectAuthorizationErrorV2::ContextMismatch);
        }
        let preimage = Self::canonical_preimage(context, claims)?;
        Ok(Self {
            reference: SnpSessionReferenceV2 {
                request_id: binding.as_stored().operation.request_id.value(),
                session_context_digest: sha384(&preimage),
            },
            source: context.session_context(SnpMaRoleV1::Source)?.clone(),
            destination: context.session_context(SnpMaRoleV1::Destination)?.clone(),
            migration_data: claims.migration_data,
            role: binding.as_stored().operation.role,
            authorization_digest: binding.as_stored().authorization_context_digest,
        })
    }

    pub fn canonical_preimage(
        context: &TenantAuthorizationContextV2,
        claims: &SessionClaimsV2,
    ) -> Result<[u8; Self::PREIMAGE_SIZE], DirectAuthorizationErrorV2> {
        MigrationDataV1::decode_exact(&claims.migration_data)
            .map_err(DirectAuthorizationErrorV2::Codec)?;
        if !matches!(claims.interpretation, 1 | 2)
            || !matches!(claims.approval_profile, 1 | 2)
            || (claims.approval_profile == 1 && claims.initial_authorization_digest != [0; 48])
            || (claims.approval_profile == 2 && claims.initial_authorization_digest == [0; 48])
        {
            return Err(DirectAuthorizationErrorV2::ContextMismatch);
        }
        let mut bytes = [0; Self::PREIMAGE_SIZE];
        let mut w = StrictWriter::new(&mut bytes);
        let authorization = context.encode_exact()?;
        let encode = |w: &mut StrictWriter<'_>| {
            w.write_bytes(b"SNP-LM-SESSION-v2")?;
            w.write_u16(2)?;
            w.write_bytes(&authorization)?;
            w.write_bytes(&claims.source_complete_evidence_digest)?;
            w.write_bytes(&claims.destination_complete_evidence_digest)?;
            w.write_bytes(&claims.tenant_collateral_digest)?;
            w.write_bytes(&claims.migration_data)?;
            w.write_u16(match claims.trust {
                SnpVerifierTrust::PinnedMilanArkTest => 1,
                SnpVerifierTrust::AzureProduction => 2,
            })?;
            w.write_u16(claims.interpretation)?;
            w.write_u8(3)?; // Venice, as in the admitted history contract.
            w.write_u16(claims.approval_profile)?;
            w.write_bytes(&claims.source_approval_digest)?;
            w.write_bytes(&claims.destination_approval_digest)?;
            w.write_bytes(&claims.initial_authorization_digest)
        };
        encode(&mut w).map_err(DirectAuthorizationErrorV2::Codec)?;
        Ok(bytes)
    }

    pub fn reference(&self) -> &SnpSessionReferenceV2 {
        &self.reference
    }
    pub fn source_context(&self) -> &ReportDataContextV1 {
        &self.source
    }
    pub fn destination_context(&self) -> &ReportDataContextV1 {
        &self.destination
    }
    pub fn migration_data(&self) -> &[u8; 64] {
        &self.migration_data
    }
    pub fn role(&self) -> MigrationRole {
        self.role
    }
    pub fn authorization_digest(&self) -> &[u8; 48] {
        &self.authorization_digest
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        reference: SnpSessionReferenceV2,
        source: ReportDataContextV1,
        destination: ReportDataContextV1,
        migration_data: [u8; 64],
        role: MigrationRole,
    ) -> Self {
        Self {
            reference,
            source,
            destination,
            migration_data,
            role,
            authorization_digest: [0x66; 48],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectKeyErrorV2 {
    Codec(SnpCodecError),
    WrongRole,
    RandomnessUnavailable,
    ContextMismatch,
}

/// Trusted CSPRNG adapter; deterministic sources are for tests only.
/// Each call fills a fresh independent 32-byte value, not a derivation seed.
pub trait MigrationRandomSourceV2 {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), DirectKeyErrorV2>;
}

impl<T: RandomSource + ?Sized> MigrationRandomSourceV2 for T {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), DirectKeyErrorV2> {
        RandomSource::fill_random32(self, output)
            .map_err(|_| DirectKeyErrorV2::RandomnessUnavailable)
    }
}

pub struct UnavailableMigrationRandomSourceV2;
impl MigrationRandomSourceV2 for UnavailableMigrationRandomSourceV2 {
    fn fill_random32(&mut self, _: &mut [u8; 32]) -> Result<(), DirectKeyErrorV2> {
        Err(DirectKeyErrorV2::RandomnessUnavailable)
    }
}

/// One operation-owned plaintext value. Not clonable, loggable or persistent.
/// Runtime orchestration must admit generation once and retain the SAME owner
/// for an authorized retry; reconstructing a context is not retry authority.
///
/// ```compile_fail
/// use pal::snp::direct_key::MigrationKeyV2;
/// fn duplicate(key: MigrationKeyV2) { key.clone(); }
/// ```
pub struct MigrationKeyV2 {
    bytes: Secret32,
    session: SnpSessionReferenceV2,
    migration_data: [u8; 64],
}
impl fmt::Debug for MigrationKeyV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationKeyV2(<redacted>)")
    }
}
impl MigrationKeyV2 {
    pub const DELIVERY_SIZE: usize = 168;
    pub fn generate<R: MigrationRandomSourceV2 + ?Sized>(
        context: &MigrationSessionContextV2,
        random: &mut R,
    ) -> Result<Self, DirectKeyErrorV2> {
        if context.role != MigrationRole::Source {
            return Err(DirectKeyErrorV2::WrongRole);
        }
        let mut bytes = Secret32::zeroed();
        random.fill_random32(bytes.as_mut()).inspect_err(|error| {
            log::error!("migration random32 generation failed: {error:?}");
        })?;
        Ok(Self {
            bytes,
            session: context.reference.clone(),
            migration_data: context.migration_data,
        })
    }
    /// Borrow solely for the role-correct typed installer; no owned byte copy.
    pub fn for_installation(
        &self,
        context: &MigrationSessionContextV2,
    ) -> Result<&[u8; 32], DirectKeyErrorV2> {
        if self.session != context.reference || self.migration_data != context.migration_data {
            return Err(DirectKeyErrorV2::ContextMismatch);
        }
        Ok(self.bytes.as_bytes())
    }
    /// Retire on completion, cancellation, timeout or terminal failure.
    /// An authorized retry retains the same owner instead of calling this.
    ///
    /// ```compile_fail
    /// use pal::snp::direct_key::MigrationKeyV2;
    /// fn reuse(key: MigrationKeyV2) {
    ///     key.clear();
    ///     key.encode_delivery();
    /// }
    /// ```
    pub fn clear(self) {
        drop(self);
    }
    pub fn encode_delivery(&self) -> SnpCodecResult<Zeroizing<[u8; Self::DELIVERY_SIZE]>> {
        let mut bytes = Zeroizing::new([0; Self::DELIVERY_SIZE]);
        let mut w = StrictWriter::new(bytes.as_mut());
        write_header(&mut w, b"SNP-LM-K", 10, Self::DELIVERY_SIZE)?;
        write_session(&mut w, &self.session)?;
        w.write_bytes(self.bytes.as_bytes())?;
        w.write_bytes(&self.migration_data)?;
        Ok(bytes)
    }
    /// Decoder wipes the caller's secret-bearing payload on success AND error.
    pub(crate) fn decode_delivery(bytes: &mut [u8]) -> SnpCodecResult<Self> {
        let result = (|| {
            let mut r = StrictReader::new(bytes);
            read_header(&mut r, b"SNP-LM-K", 10, Self::DELIVERY_SIZE)?;
            let session = read_session(&mut r)?;
            let key = Secret32::from_bytes(r.read_array()?);
            let migration_data = r.read_array()?;
            r.finish()?;
            MigrationDataV1::decode_exact(&migration_data)?;
            Ok(Self {
                bytes: key,
                session,
                migration_data,
            })
        })();
        zeroize::Zeroize::zeroize(bytes);
        result
    }
    pub(crate) fn matches(&self, context: &MigrationSessionContextV2) -> bool {
        self.session == context.reference && self.migration_data == context.migration_data
    }
}

pub(crate) fn write_header(
    w: &mut StrictWriter<'_>,
    magic: &[u8; 8],
    kind: u16,
    length: usize,
) -> SnpCodecResult<()> {
    w.write_bytes(magic)?;
    w.write_u16(2)?;
    w.write_u16(kind)?;
    w.write_u32(length as u32)
}
pub(crate) fn read_header(
    r: &mut StrictReader<'_>,
    magic: &[u8; 8],
    kind: u16,
    length: usize,
) -> SnpCodecResult<()> {
    if &r.read_array::<8>()? != magic {
        return Err(SnpCodecError::InvalidMagic);
    }
    if r.read_u16()? != 2 {
        return Err(SnpCodecError::UnsupportedVersion);
    }
    if r.read_u16()? != kind {
        return Err(SnpCodecError::UnknownRecordType);
    }
    if r.read_u32()? as usize != length {
        return Err(SnpCodecError::InvalidLength);
    }
    Ok(())
}
pub(crate) fn write_session(
    w: &mut StrictWriter<'_>,
    value: &SnpSessionReferenceV2,
) -> SnpCodecResult<()> {
    w.write_u64(value.request_id)?;
    w.write_bytes(&value.session_context_digest)
}
pub(crate) fn read_session(r: &mut StrictReader<'_>) -> SnpCodecResult<SnpSessionReferenceV2> {
    Ok(SnpSessionReferenceV2 {
        request_id: r.read_u64()?,
        session_context_digest: r.read_array()?,
    })
}
