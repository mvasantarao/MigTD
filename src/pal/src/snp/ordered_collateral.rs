// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Custom production-intent SNP collateral v1. Fixture execution is not deployment approval.

use super::*;
use crate::tenant_identity::VerifiedTenantReportDeliveryV1;

const RELEASE_DOMAIN: &[u8] = b"SNP-MA-COLLATERAL-v1";
const INITIAL_DOMAIN: &[u8] = b"SNP-INITIAL-MA-AUTH-v1";
const KEY_DOMAIN: &[u8] = b"SNP-COLLATERAL-KEY-v1";
pub const MAX_RELEASE_MAPPINGS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ReleaseStatusV1 {
    Approved = 1,
    HistoricalOnly = 2,
    Revoked = 3,
}

/// One approval and immutable security-version mapping, not a platform TCB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaPolicyTcbMapping {
    pub identity_digest: [u8; 48],
    pub combined_svn: u32,
    pub status: ReleaseStatusV1,
}

/// Complete publisher snapshot. Retained entries cannot disappear or change SVN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaReleaseEndorsementV1 {
    pub publisher_id: [u8; 48],
    pub signing_key_id: [u8; 48],
    pub trust_epoch: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub mappings: Vec<MaPolicyTcbMapping>,
    pub signature: [u8; 96],
}

impl MaReleaseEndorsementV1 {
    pub const HEADER_SIZE: usize = 152;
    pub const ENTRY_SIZE: usize = 56;
    pub const MAX_ENCODED_SIZE: usize =
        Self::HEADER_SIZE + MAX_RELEASE_MAPPINGS * Self::ENTRY_SIZE + 96;

    fn validate(&self) -> SnpCodecResult<()> {
        if self.mappings.is_empty()
            || self.mappings.len() > MAX_RELEASE_MAPPINGS
            || self
                .mappings
                .windows(2)
                .any(|p| p[0].identity_digest >= p[1].identity_digest)
            || self.issued_at >= self.expires_at
            || self.publisher_id == [0; 48]
            || self.signing_key_id == [0; 48]
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<Vec<u8>> {
        self.validate()?;
        let length = Self::HEADER_SIZE + self.mappings.len() * Self::ENTRY_SIZE + 96;
        let mut bytes = vec![0; length];
        let mut w = StrictWriter::new(&mut bytes);
        header(&mut w, b"SNP-MA-R", length)?;
        w.write_bytes(&self.publisher_id)?;
        w.write_bytes(&self.signing_key_id)?;
        for value in [
            self.trust_epoch,
            self.sequence,
            self.issued_at,
            self.expires_at,
        ] {
            w.write_u64(value)?;
        }
        w.write_u32(self.mappings.len() as u32)?;
        w.write_zeroes(4)?;
        for mapping in &self.mappings {
            w.write_bytes(&mapping.identity_digest)?;
            w.write_u32(mapping.combined_svn)?;
            w.write_u16(mapping.status as u16)?;
            w.write_zeroes(2)?;
        }
        w.write_bytes(&self.signature)?;
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        if bytes.len() > Self::MAX_ENCODED_SIZE {
            return Err(SnpCodecError::RecordTooLarge);
        }
        let mut r = StrictReader::new(bytes);
        read_header(&mut r, b"SNP-MA-R", bytes.len())?;
        let mut value = Self {
            publisher_id: r.read_array()?,
            signing_key_id: r.read_array()?,
            trust_epoch: r.read_u64()?,
            sequence: r.read_u64()?,
            issued_at: r.read_u64()?,
            expires_at: r.read_u64()?,
            mappings: Vec::new(),
            signature: [0; 96],
        };
        let count = r.read_u32()? as usize;
        r.read_zeroes(4)?;
        if count == 0
            || count > MAX_RELEASE_MAPPINGS
            || bytes.len() != Self::HEADER_SIZE + count * Self::ENTRY_SIZE + 96
        {
            return Err(SnpCodecError::InvalidCount);
        }
        for _ in 0..count {
            let identity_digest = r.read_array()?;
            let combined_svn = r.read_u32()?;
            let status = match r.read_u16()? {
                1 => ReleaseStatusV1::Approved,
                2 => ReleaseStatusV1::HistoricalOnly,
                3 => ReleaseStatusV1::Revoked,
                _ => return Err(SnpCodecError::UnknownEnumValue),
            };
            r.read_zeroes(2)?;
            value.mappings.push(MaPolicyTcbMapping {
                identity_digest,
                combined_svn,
                status,
            });
        }
        value.signature = r.read_array()?;
        r.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn signature_message(&self) -> SnpCodecResult<Vec<u8>> {
        signature_message(RELEASE_DOMAIN, &self.encode_exact()?)
    }
}

/// A historical authority signs only after checking the original tenant/MA
/// evidence and endorsement. Its key is distinct in purpose from release signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialMaAuthorizationV1 {
    pub publisher_id: [u8; 48],
    pub signing_key_id: [u8; 48],
    pub trust_epoch: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub tenant_report_id: [u8; 32],
    pub initial_ma_report_id: [u8; 32],
    pub identity_digest: [u8; 48],
    pub lm_policy_digest: [u8; 48],
    pub combined_svn: u32,
    pub observed_at: u64,
    pub signature: [u8; 96],
}

impl InitialMaAuthorizationV1 {
    pub const ENCODED_SIZE: usize = 416;

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        if self.issued_at >= self.expires_at
            || self.observed_at > self.issued_at
            || self.publisher_id == [0; 48]
            || self.signing_key_id == [0; 48]
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut w = StrictWriter::new(&mut bytes);
        header(&mut w, b"SNP-MA-H", Self::ENCODED_SIZE)?;
        w.write_bytes(&self.publisher_id)?;
        w.write_bytes(&self.signing_key_id)?;
        for v in [
            self.trust_epoch,
            self.sequence,
            self.issued_at,
            self.expires_at,
        ] {
            w.write_u64(v)?;
        }
        w.write_bytes(&self.tenant_report_id)?;
        w.write_bytes(&self.initial_ma_report_id)?;
        w.write_bytes(&self.identity_digest)?;
        w.write_bytes(&self.lm_policy_digest)?;
        w.write_u32(self.combined_svn)?;
        w.write_zeroes(4)?;
        w.write_u64(self.observed_at)?;
        w.write_bytes(&self.signature)?;
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut r = StrictReader::new(bytes);
        read_header(&mut r, b"SNP-MA-H", Self::ENCODED_SIZE)?;
        let mut value = Self {
            publisher_id: r.read_array()?,
            signing_key_id: r.read_array()?,
            trust_epoch: r.read_u64()?,
            sequence: r.read_u64()?,
            issued_at: r.read_u64()?,
            expires_at: r.read_u64()?,
            tenant_report_id: r.read_array()?,
            initial_ma_report_id: r.read_array()?,
            identity_digest: r.read_array()?,
            lm_policy_digest: r.read_array()?,
            combined_svn: r.read_u32()?,
            observed_at: 0,
            signature: [0; 96],
        };
        r.read_zeroes(4)?;
        value.observed_at = r.read_u64()?;
        value.signature = r.read_array()?;
        r.finish()?;
        value.encode_exact()?;
        Ok(value)
    }

    pub fn signature_message(&self) -> SnpCodecResult<Vec<u8>> {
        signature_message(INITIAL_DOMAIN, &self.encode_exact()?)
    }

    fn same_history(&self, other: &Self) -> bool {
        self.publisher_id == other.publisher_id
            && self.tenant_report_id == other.tenant_report_id
            && self.initial_ma_report_id == other.initial_ma_report_id
            && self.identity_digest == other.identity_digest
            && self.lm_policy_digest == other.lm_policy_digest
            && self.combined_svn == other.combined_svn
            && self.observed_at == other.observed_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollateralSignerPurposeV1 {
    ReleaseSnapshot,
    InitialAuthorization,
}

pub struct CollateralKeyRequestV1 {
    pub publisher_id: [u8; 48],
    pub key_id: [u8; 48],
    pub purpose: CollateralSignerPurposeV1,
    pub trust: MaPolicyTrustV1,
    pub trust_epoch: u64,
    pub issued_at: u64,
    pub now: u64,
}

/// Trusted registry output; key membership, publisher/purpose, epoch, current
/// revocation and signing-time validity must ALL be checked by the provider.
/// Root/intermediate/leaf updates require independently anchored monotonic trust
/// state. Unknown keys, stale/unavailable revocation and unapproved root changes
/// fail closed. Transported chains never establish authority by themselves.
pub trait CollateralKeyProviderV1 {
    fn authorized_key(&self, request: &CollateralKeyRequestV1)
        -> Result<[u8; 97], MaPolicyErrorV1>;
}

pub fn collateral_key_id_v1(key: &[u8; 97]) -> [u8; 48] {
    hash_parts(&[KEY_DOMAIN, key])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollateralStateV1 {
    pub revision: u64,
    pub record: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollateralStateSlotV1 {
    ReleaseSnapshot,
    InitialAuthorization {
        tenant_report_id: [u8; 32],
        initial_ma_report_id: [u8; 32],
    },
}

/// Authenticated state per (trust,publisher,slot), bounded before allocation,
/// independently rollback anchored. Empty means provisioned, never file missing.
/// CAS acknowledges only atomic durable success, including idempotent retries.
/// Historical records are retained through migration/rebind and renewed without
/// altering immutable history. Retention/retrieval authorization is provider-owned.
pub trait OrderedCollateralStoreV1 {
    fn load_authenticated(
        &mut self,
        trust: MaPolicyTrustV1,
        publisher: &[u8; 48],
        slot: CollateralStateSlotV1,
    ) -> Result<CollateralStateV1, MaPolicyErrorV1>;
    fn commit(
        &mut self,
        trust: MaPolicyTrustV1,
        publisher: &[u8; 48],
        slot: CollateralStateSlotV1,
        revision: u64,
        record: &[u8],
    ) -> Result<(), MaPolicyErrorV1>;
}

/// Must authenticate the tenant's complete evidence/current persisted
/// MigrationDataV1, check its exact Venice profile and report digest against
/// this receipt, and return the actual INIT_MA_REPORT_ID, never host metadata.
pub trait HistoricalTenantBindingProviderV1 {
    fn initial_ma_report_id(
        &self,
        tenant: &VerifiedTenantReportDeliveryV1,
    ) -> Result<[u8; 32], MaPolicyErrorV1>;
}

pub struct UnavailableOrderedCollateralServicesV1;

impl CollateralKeyProviderV1 for UnavailableOrderedCollateralServicesV1 {
    fn authorized_key(&self, _: &CollateralKeyRequestV1) -> Result<[u8; 97], MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::LifecycleUnavailable)
    }
}

impl OrderedCollateralStoreV1 for UnavailableOrderedCollateralServicesV1 {
    fn load_authenticated(
        &mut self,
        _: MaPolicyTrustV1,
        _: &[u8; 48],
        _: CollateralStateSlotV1,
    ) -> Result<CollateralStateV1, MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::StoreUnavailable)
    }
    fn commit(
        &mut self,
        _: MaPolicyTrustV1,
        _: &[u8; 48],
        _: CollateralStateSlotV1,
        _: u64,
        _: &[u8],
    ) -> Result<(), MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::StoreUnavailable)
    }
}

impl HistoricalTenantBindingProviderV1 for UnavailableOrderedCollateralServicesV1 {
    fn initial_ma_report_id(
        &self,
        _: &VerifiedTenantReportDeliveryV1,
    ) -> Result<[u8; 32], MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::HistoricalBindingMismatch)
    }
}

pub struct OrderedCollateralServicesV1<'a> {
    pub keys: &'a dyn CollateralKeyProviderV1,
    pub clock: &'a dyn MaPolicyTimeV1,
    pub store: &'a mut dyn OrderedCollateralStoreV1,
}

/// Sealed snapshot receipt. Revalidate it at use; it is not perpetual approval.
#[derive(Debug)]
pub struct VerifiedReleaseCollateralV1 {
    record: MaReleaseEndorsementV1,
    content_digest: [u8; 48],
    trust: MaPolicyTrustV1,
}

impl VerifiedReleaseCollateralV1 {
    pub fn verify(
        record: &MaReleaseEndorsementV1,
        trust: MaPolicyTrustV1,
        services: &mut OrderedCollateralServicesV1<'_>,
    ) -> Result<Self, MaPolicyErrorV1> {
        let encoded = record.encode_exact()?;
        verify_signature(
            &record.signature_message()?,
            &record.signature,
            record,
            trust,
            services,
        )?;
        let slot = CollateralStateSlotV1::ReleaseSnapshot;
        let state = services
            .store
            .load_authenticated(trust, &record.publisher_id, slot)?;
        if let Some(previous) = &state.record {
            let previous = MaReleaseEndorsementV1::decode_exact(previous)
                .map_err(|_| MaPolicyErrorV1::InvalidStoredState)?;
            if previous.publisher_id != record.publisher_id {
                return Err(MaPolicyErrorV1::InvalidStoredState);
            }
            compare_sequence(
                previous.sequence,
                previous.trust_epoch,
                &previous.signature_message()?,
                record.sequence,
                record.trust_epoch,
                &record.signature_message()?,
            )?;
            for old in &previous.mappings {
                let new = record
                    .mappings
                    .iter()
                    .find(|m| m.identity_digest == old.identity_digest)
                    .ok_or(MaPolicyErrorV1::ConflictingMapping)?;
                if new.combined_svn != old.combined_svn || (new.status as u16) < old.status as u16 {
                    return Err(MaPolicyErrorV1::ConflictingMapping);
                }
            }
        }
        services
            .store
            .commit(trust, &record.publisher_id, slot, state.revision, &encoded)?;
        Ok(Self {
            record: record.clone(),
            content_digest: sha384(&record.signature_message()?),
            trust,
        })
    }

    fn refresh(
        &self,
        services: &mut OrderedCollateralServicesV1<'_>,
    ) -> Result<(), MaPolicyErrorV1> {
        Self::verify(&self.record, self.trust, services).map(|_| ())
    }

    fn mapping(
        &self,
        identity: &[u8; 48],
        historical: bool,
    ) -> Result<&MaPolicyTcbMapping, MaPolicyErrorV1> {
        let m = self
            .record
            .mappings
            .iter()
            .find(|m| &m.identity_digest == identity)
            .ok_or(MaPolicyErrorV1::MissingMapping)?;
        match m.status {
            ReleaseStatusV1::Revoked => Err(MaPolicyErrorV1::ReleaseRevoked),
            ReleaseStatusV1::HistoricalOnly if !historical => Err(MaPolicyErrorV1::HistoricalOnly),
            _ => Ok(m),
        }
    }
}

#[derive(Debug)]
pub struct VerifiedOrderedReleaseV1 {
    pub(super) evidence: VerifiedMaPolicyEvidenceV1,
    publisher_id: [u8; 48],
    combined_svn: u32,
    minimum_svn: u32,
    snapshot_digest: [u8; 48],
}

impl VerifiedMaPolicyCollateral {
    pub fn verify_ordered(
        request: &MaPolicyVerificationRequestV1<'_>,
        policy: &VerifiedLmPolicyV1,
        snapshot: &VerifiedReleaseCollateralV1,
        verifier: &dyn SnpEvidenceVerifier,
        services: &mut OrderedCollateralServicesV1<'_>,
    ) -> Result<Self, MaPolicyErrorV1> {
        let MaPolicyReleaseRulesV1::OrderedReleaseV1 {
            publisher_id,
            minimum_svn,
        } = policy.release_rules
        else {
            return Err(MaPolicyErrorV1::UnsupportedProfile);
        };
        if publisher_id != snapshot.record.publisher_id || snapshot.trust != policy.trust {
            return Err(MaPolicyErrorV1::TrustMismatch);
        }
        let evidence = verify_policy_evidence(request, policy, verifier, services.clock)?;
        let mapping = snapshot.mapping(&evidence.identity_digest, false)?;
        if mapping.combined_svn < minimum_svn {
            return Err(MaPolicyErrorV1::ReleaseDowngrade);
        }
        snapshot.refresh(services)?;
        Ok(Self::OrderedReleaseV1(VerifiedOrderedReleaseV1 {
            evidence,
            publisher_id,
            combined_svn: mapping.combined_svn,
            minimum_svn,
            snapshot_digest: snapshot.content_digest,
        }))
    }
}

/// Cannot be constructed from a caller-selected initial report ID or unsigned history.
///
/// ```compile_fail
/// use pal::snp::ma_policy::ordered::VerifiedInitialMaAuthorizationV1;
/// let historical = VerifiedInitialMaAuthorizationV1 {};
/// ```
#[derive(Debug)]
pub struct VerifiedInitialMaAuthorizationV1 {
    record: InitialMaAuthorizationV1,
    tenant: VerifiedTenantReportDeliveryV1,
    snapshot_digest: [u8; 48],
    trust: MaPolicyTrustV1,
}

impl VerifiedInitialMaAuthorizationV1 {
    pub fn verify(
        record: &InitialMaAuthorizationV1,
        tenant: &VerifiedTenantReportDeliveryV1,
        binding: &dyn HistoricalTenantBindingProviderV1,
        snapshot: &VerifiedReleaseCollateralV1,
        services: &mut OrderedCollateralServicesV1<'_>,
    ) -> Result<Self, MaPolicyErrorV1> {
        let encoded = record.encode_exact()?;
        if record.publisher_id != snapshot.record.publisher_id
            || record.tenant_report_id != *tenant.identity().as_bytes()
            || record.initial_ma_report_id != binding.initial_ma_report_id(tenant)?
        {
            return Err(MaPolicyErrorV1::HistoricalBindingMismatch);
        }
        let mapping = snapshot.mapping(&record.identity_digest, true)?;
        if mapping.combined_svn != record.combined_svn {
            return Err(MaPolicyErrorV1::ConflictingMapping);
        }
        let now = services.clock.unix_seconds()?;
        check_validity(record.issued_at, record.expires_at, now)?;
        verify_key_signature(
            &record.signature_message()?,
            &record.signature,
            &CollateralKeyRequestV1 {
                publisher_id: record.publisher_id,
                key_id: record.signing_key_id,
                purpose: CollateralSignerPurposeV1::InitialAuthorization,
                trust: snapshot.trust,
                trust_epoch: record.trust_epoch,
                issued_at: record.issued_at,
                now,
            },
            services.keys,
        )?;
        snapshot.refresh(services)?;
        let slot = CollateralStateSlotV1::InitialAuthorization {
            tenant_report_id: record.tenant_report_id,
            initial_ma_report_id: record.initial_ma_report_id,
        };
        let state =
            services
                .store
                .load_authenticated(snapshot.trust, &record.publisher_id, slot)?;
        if let Some(old) = &state.record {
            let old = InitialMaAuthorizationV1::decode_exact(old)
                .map_err(|_| MaPolicyErrorV1::InvalidStoredState)?;
            if !record.same_history(&old) {
                return Err(MaPolicyErrorV1::HistoricalBindingMismatch);
            }
            compare_sequence(
                old.sequence,
                old.trust_epoch,
                &old.signature_message()?,
                record.sequence,
                record.trust_epoch,
                &record.signature_message()?,
            )?;
        }
        services.store.commit(
            snapshot.trust,
            &record.publisher_id,
            slot,
            state.revision,
            &encoded,
        )?;
        Ok(Self {
            record: record.clone(),
            tenant: tenant.clone(),
            snapshot_digest: snapshot.content_digest,
            trust: snapshot.trust,
        })
    }
}

/// Require a single current snapshot and exact tenant/history proof, not only
/// source/destination ranks. Receipts are operation-local; runtime must reverify
/// after session loss, trust changes, expiry or restart, and enforce durable replay.
pub fn admit_ordered_release_pair_v1(
    source: &VerifiedMaPolicyCollateral,
    destination: &VerifiedMaPolicyCollateral,
    initial: &VerifiedInitialMaAuthorizationV1,
    snapshot: &VerifiedReleaseCollateralV1,
    binding: &dyn HistoricalTenantBindingProviderV1,
    services: &mut OrderedCollateralServicesV1<'_>,
) -> Result<(), MaPolicyErrorV1> {
    let (
        VerifiedMaPolicyCollateral::OrderedReleaseV1(source),
        VerifiedMaPolicyCollateral::OrderedReleaseV1(destination),
    ) = (source, destination)
    else {
        return Err(MaPolicyErrorV1::UnsupportedProfile);
    };
    let src = &source.evidence;
    let dst = &destination.evidence;
    let a = &src.context;
    let b = &dst.context;
    let inter = a.role == SnpMaRoleV1::Source && b.role == SnpMaRoleV1::Destination;
    let handoff = a.role == SnpMaRoleV1::Outgoing && b.role == SnpMaRoleV1::Incoming;
    if !(inter || handoff)
        || a.evidence_purpose != b.evidence_purpose
        || a.request_id != b.request_id
        || a.th1 != b.th1
        || a.tenant_binding_id != b.tenant_binding_id
        || a.algorithm != b.algorithm
        || a.negotiated_migration_version != b.negotiated_migration_version
        || src.rules != dst.rules
        || source.minimum_svn != destination.minimum_svn
        || src.report_trust != dst.report_trust
        || src.authorization_trust != dst.authorization_trust
        || src.authorization_trust != initial.trust
        || source.publisher_id != destination.publisher_id
        || source.publisher_id != initial.record.publisher_id
        || source.snapshot_digest != destination.snapshot_digest
        || source.snapshot_digest != initial.snapshot_digest
        || source.snapshot_digest != snapshot.content_digest
        || src.report_id != *initial.tenant.report_id_ma()
        || src.report_trust != initial.tenant.trust()
        || a.request_id != initial.tenant.operation().request_id.value()
        || (inter && a.tenant_binding_id != *initial.tenant.identity().as_bytes())
    {
        return Err(MaPolicyErrorV1::ContextMismatch);
    }
    // Recheck expiry, current key authorization, snapshot sequence and the exact
    // retained historical record at final admission, not only receipt creation.
    let now = services.clock.unix_seconds()?;
    check_validity(src.policy_issued_at, src.policy_expires_at, now)?;
    check_validity(dst.policy_issued_at, dst.policy_expires_at, now)?;
    VerifiedInitialMaAuthorizationV1::verify(
        &initial.record,
        &initial.tenant,
        binding,
        snapshot,
        services,
    )?;
    if source.combined_svn < source.minimum_svn
        || destination.combined_svn < source.combined_svn
        || destination.combined_svn < initial.record.combined_svn
        || initial.record.combined_svn < source.minimum_svn
    {
        return Err(MaPolicyErrorV1::ReleaseDowngrade);
    }
    validate_platform(
        &dst.current_tcb,
        &dst.current_etcb,
        dst.current_mit_vector,
        &FixedReleaseAdmissionRulesV1 {
            minimum_current_tcb: src.current_tcb,
            minimum_current_etcb: src.current_etcb,
            minimum_current_mit_vector: src.rules.minimum_current_mit_vector
                | src.current_mit_vector,
        },
    )
}

fn header(w: &mut StrictWriter<'_>, magic: &[u8; 8], length: usize) -> SnpCodecResult<()> {
    w.write_bytes(magic)?;
    w.write_u16(1)?;
    w.write_u16(2)?;
    w.write_u32(length as u32)
}

fn read_header(r: &mut StrictReader<'_>, magic: &[u8; 8], length: usize) -> SnpCodecResult<()> {
    if &r.read_array::<8>()? != magic {
        return Err(SnpCodecError::InvalidMagic);
    }
    if r.read_u16()? != 1 || r.read_u16()? != 2 {
        return Err(SnpCodecError::UnsupportedVersion);
    }
    if r.read_u32()? as usize != length {
        return Err(SnpCodecError::InvalidLength);
    }
    Ok(())
}

fn signature_message(domain: &[u8], encoded: &[u8]) -> SnpCodecResult<Vec<u8>> {
    let signed = encoded
        .get(
            ..encoded
                .len()
                .checked_sub(96)
                .ok_or(SnpCodecError::InvalidLength)?,
        )
        .ok_or(SnpCodecError::InvalidLength)?;
    let mut message = domain.to_vec();
    message.extend_from_slice(signed);
    Ok(message)
}

fn verify_signature(
    message: &[u8],
    signature: &[u8; 96],
    record: &MaReleaseEndorsementV1,
    trust: MaPolicyTrustV1,
    services: &OrderedCollateralServicesV1<'_>,
) -> Result<(), MaPolicyErrorV1> {
    if trust == MaPolicyTrustV1::Production {
        return Err(MaPolicyErrorV1::ProductionProfileUnavailable);
    }
    let now = services.clock.unix_seconds()?;
    check_validity(record.issued_at, record.expires_at, now)?;
    verify_key_signature(
        message,
        signature,
        &CollateralKeyRequestV1 {
            publisher_id: record.publisher_id,
            key_id: record.signing_key_id,
            purpose: CollateralSignerPurposeV1::ReleaseSnapshot,
            trust,
            trust_epoch: record.trust_epoch,
            issued_at: record.issued_at,
            now,
        },
        services.keys,
    )
}

fn verify_key_signature(
    message: &[u8],
    signature: &[u8; 96],
    request: &CollateralKeyRequestV1,
    keys: &dyn CollateralKeyProviderV1,
) -> Result<(), MaPolicyErrorV1> {
    let key = keys.authorized_key(request)?;
    if key[0] != 4 || collateral_key_id_v1(&key) != request.key_id {
        return Err(MaPolicyErrorV1::InvalidSigner);
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P384_SHA384_FIXED, key)
        .verify(message, signature)
        .map_err(|_| MaPolicyErrorV1::InvalidSignature)
}

fn compare_sequence(
    previous: u64,
    previous_epoch: u64,
    old: &[u8],
    sequence: u64,
    epoch: u64,
    new: &[u8],
) -> Result<(), MaPolicyErrorV1> {
    if sequence < previous || epoch < previous_epoch {
        return Err(MaPolicyErrorV1::SequenceRollback);
    }
    if sequence == previous && old != new {
        return Err(MaPolicyErrorV1::SequenceContentConflict);
    }
    Ok(())
}
