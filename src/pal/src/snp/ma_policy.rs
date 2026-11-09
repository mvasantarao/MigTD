// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! P0.9 fixed/ordered collateral contracts and shared SNP evidence verification.
//! Production schema, PKI, trusted state and history providers remain unavailable.

use super::{
    collateral_set::{SnpCertificateRoleV1, SnpCollateralSetV1},
    evidence_header::{SnpEvidenceProfileV1, SnpTcbProfileV1},
    ma_evidence::SnpMaEvidenceV1,
    migration_data::{VeniceEtcbV1, VeniceTcbV1},
    purpose_binding::sha384,
    report_data_context::{ReportDataContextV1, SnpMaRoleV1},
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};
use crate::{
    snp_report::AuthenticatedSnpClaims,
    traits::SnpEvidenceVerifier,
    types::{
        MaEvidence, MaEvidenceBinding, SnpCollateralLeafKind, SnpVerificationCollateral,
        SnpVerificationError, SnpVerifierTrust, TcbStatus,
    },
};

const IDENTITY_DOMAIN: &[u8] = b"SNP-MA-POLICY-IDENTITY-v1";
const POLICY_DOMAIN: &[u8] = b"SNP-LM-POLICY-v1";
const SIGNER_DOMAIN: &[u8] = b"SNP-MA-AUTH-SIGNER-v1";
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_ISSUER_CERTIFICATES: usize = 8;

#[path = "ordered_collateral.rs"]
pub mod ordered;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaPolicyErrorV1 {
    Codec(SnpCodecError),
    Evidence(SnpVerificationError),
    PolicyUnavailable,
    InvalidPolicy,
    SignerUnavailable,
    InvalidSigner,
    InvalidSignature,
    TimeUnavailable,
    OutsideValidity,
    StoreUnavailable,
    StoreConflict,
    InvalidStoredState,
    SequenceRollback,
    SequenceContentConflict,
    TrustMismatch,
    ProductionProfileUnavailable,
    IdentityMismatch,
    ContextMismatch,
    CollateralMismatch,
    PlatformDowngrade,
    MitigationMissing,
    UnsupportedProfile,
    MissingMapping,
    ConflictingMapping,
    ReleaseRevoked,
    HistoricalOnly,
    ReleaseDowngrade,
    HistoricalBindingMismatch,
    LifecycleUnavailable,
}

impl From<SnpCodecError> for MaPolicyErrorV1 {
    fn from(error: SnpCodecError) -> Self {
        Self::Codec(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaPolicyTrustV1 {
    Fixture,
    Production,
}

impl MaPolicyTrustV1 {
    fn evidence_profile(self) -> SnpEvidenceProfileV1 {
        match self {
            Self::Fixture => SnpEvidenceProfileV1::Fixture,
            Self::Production => SnpEvidenceProfileV1::Production,
        }
    }
}

/// Fingerprint input, not an authorization receipt or an AMD report layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaPolicyIdentityInputV1 {
    pub measurement: [u8; 48],
    pub guest_svn: u32,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub host_data: [u8; 32],
    pub guest_policy: u64,
    pub lm_policy_digest: [u8; 48],
}

impl MaPolicyIdentityInputV1 {
    pub const ENCODED_SIZE: usize = 280;

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut bytes);
        writer.write_u16(1)?;
        writer.write_u16(1)?;
        writer.write_u32(6)?;
        writer.write_u32(0)?;
        writer.write_bytes(&self.measurement)?;
        writer.write_u32(self.guest_svn)?;
        writer.write_bytes(&self.family_id)?;
        writer.write_bytes(&self.image_id)?;
        writer.write_bytes(&self.id_key_digest)?;
        writer.write_bytes(&self.author_key_digest)?;
        writer.write_bytes(&self.host_data)?;
        writer.write_u64(self.guest_policy)?;
        writer.write_bytes(&self.lm_policy_digest)?;
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(bytes);
        if reader.read_u16()? != 1 || reader.read_u16()? != 1 || reader.read_u32()? != 6 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        reader.read_zeroes(4)?;
        let value = Self {
            measurement: reader.read_array()?,
            guest_svn: reader.read_u32()?,
            family_id: reader.read_array()?,
            image_id: reader.read_array()?,
            id_key_digest: reader.read_array()?,
            author_key_digest: reader.read_array()?,
            host_data: reader.read_array()?,
            guest_policy: reader.read_u64()?,
            lm_policy_digest: reader.read_array()?,
        };
        reader.finish()?;
        Ok(value)
    }

    pub fn digest(&self) -> SnpCodecResult<[u8; 48]> {
        Ok(hash_parts(&[IDENTITY_DOMAIN, &self.encode_exact()?]))
    }

    /// Project verifier-authenticated common claims into the frozen identity.
    /// This does not authenticate claims, approve policy, or admit migration.
    pub fn from_authenticated_claims(
        claims: &AuthenticatedSnpClaims,
        lm_policy_digest: [u8; 48],
    ) -> SnpCodecResult<Self> {
        if claims.report_version != 6 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        Ok(Self {
            measurement: claims.measurement,
            guest_svn: claims.guest_svn,
            family_id: claims.family_id,
            image_id: claims.image_id,
            id_key_digest: claims.id_key_digest,
            author_key_digest: claims.author_key_digest,
            host_data: claims.host_data,
            guest_policy: claims.policy,
            lm_policy_digest,
        })
    }

    fn from_authenticated_report(
        report: &[u8; 1184],
        lm_policy_digest: [u8; 48],
    ) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(&report[..0x140]);
        if reader.read_u32()? != 6 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        let guest_svn = reader.read_u32()?;
        let guest_policy = reader.read_u64()?;
        let family_id = reader.read_array()?;
        let image_id = reader.read_array()?;
        reader.take(0x60)?;
        Ok(Self {
            measurement: reader.read_array()?,
            guest_svn,
            family_id,
            image_id,
            host_data: reader.read_array()?,
            id_key_digest: reader.read_array()?,
            author_key_digest: reader.read_array()?,
            guest_policy,
            lm_policy_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedReleaseAllowlistV1 {
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub identity_digest: [u8; 48],
    pub release_id: [u8; 32],
    pub signer_id: [u8; 48],
    pub authorization_root_id: [u8; 48],
    pub signature: [u8; 96],
}

impl FixedReleaseAllowlistV1 {
    pub const ENCODED_SIZE: usize = 320;
    pub const SIGNED_SIZE: usize = 224;

    fn validate(&self) -> SnpCodecResult<()> {
        let end = self
            .release_id
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(32);
        if end == 0
            || self.release_id[..end]
                .iter()
                .any(|byte| !(0x20..=0x7e).contains(byte))
            || self.release_id[end..].iter().any(|byte| *byte != 0)
            || self.issued_at >= self.expires_at
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        self.validate()?;
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut bytes);
        writer.write_u16(1)?;
        writer.write_u16(1)?;
        writer.write_u32(Self::ENCODED_SIZE as u32)?;
        writer.write_u64(self.sequence)?;
        writer.write_u64(self.issued_at)?;
        writer.write_u64(self.expires_at)?;
        writer.write_u32(1)?;
        writer.write_u32(0)?;
        writer.write_bytes(&self.identity_digest)?;
        writer.write_bytes(&self.release_id)?;
        writer.write_bytes(&self.signer_id)?;
        writer.write_bytes(&self.authorization_root_id)?;
        writer.write_u16(1)?;
        writer.write_u16(1)?;
        writer.write_u16(1)?;
        writer.write_u16(0)?;
        writer.write_bytes(&self.signature)?;
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(bytes);
        if reader.read_u16()? != 1 || reader.read_u16()? != 1 {
            return Err(SnpCodecError::UnsupportedVersion);
        }
        if reader.read_u32()? != Self::ENCODED_SIZE as u32 {
            return Err(SnpCodecError::InvalidLength);
        }
        let sequence = reader.read_u64()?;
        let issued_at = reader.read_u64()?;
        let expires_at = reader.read_u64()?;
        if reader.read_u32()? != 1 {
            return Err(SnpCodecError::UnknownEnumValue);
        }
        reader.read_zeroes(4)?;
        let mut value = Self {
            sequence,
            issued_at,
            expires_at,
            identity_digest: reader.read_array()?,
            release_id: reader.read_array()?,
            signer_id: reader.read_array()?,
            authorization_root_id: reader.read_array()?,
            signature: [0; 96],
        };
        for _ in 0..3 {
            if reader.read_u16()? != 1 {
                return Err(SnpCodecError::UnknownEnumValue);
            }
        }
        reader.read_zeroes(2)?;
        value.signature = reader.read_array()?;
        reader.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug)]
pub struct MaPolicyIdentity {
    pub allowlist: FixedReleaseAllowlistV1,
}

#[derive(Debug)]
pub struct FixedReleaseCollateralV1 {
    pub identity: MaPolicyIdentity,
    /// Leaf first. Trust anchors are pinned by the provider, never by this bundle.
    pub identity_issuer_chain: Vec<Vec<u8>>,
}

/// One logical bundle, with non-interchangeable versioned authorization profiles.
#[derive(Debug)]
pub enum MaPolicyCollateral {
    FixedReleaseV1(FixedReleaseCollateralV1),
    OrderedReleaseV1(ordered::MaReleaseEndorsementV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedReleaseAdmissionRulesV1 {
    pub minimum_current_tcb: VeniceTcbV1,
    pub minimum_current_etcb: VeniceEtcbV1,
    pub minimum_current_mit_vector: u64,
}

/// Trusted-provider output. The provider must authenticate the policy and issuer
/// purpose, reject unknown schema fields and return RFC 8785 semantic bytes only.
/// Validity must include the effective policy AND signer-chain validity interval.
pub struct AuthenticatedLmPolicyV1 {
    pub canonical_semantic_bytes: Vec<u8>,
    pub rules: FixedReleaseAdmissionRulesV1,
    pub release_rules: MaPolicyReleaseRulesV1,
    pub trust: MaPolicyTrustV1,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaPolicyReleaseRulesV1 {
    FixedReleaseV1,
    OrderedReleaseV1 {
        publisher_id: [u8; 48],
        minimum_svn: u32,
    },
}

pub trait LmPolicyVerifierV1 {
    fn authenticate_and_canonicalize(
        &self,
        signed_policy: &[u8],
        issuer_chain: &[Vec<u8>],
        trust: MaPolicyTrustV1,
        now: u64,
    ) -> Result<AuthenticatedLmPolicyV1, MaPolicyErrorV1>;
}

/// Constructed only through the trusted schema/signature adapter:
///
/// ```compile_fail
/// use pal::snp::ma_policy::VerifiedLmPolicyV1;
/// let policy = VerifiedLmPolicyV1 { digest: [0; 48] };
/// ```
#[derive(Debug)]
pub struct VerifiedLmPolicyV1 {
    digest: [u8; 48],
    rules: FixedReleaseAdmissionRulesV1,
    release_rules: MaPolicyReleaseRulesV1,
    trust: MaPolicyTrustV1,
    issued_at: u64,
    expires_at: u64,
}

impl VerifiedLmPolicyV1 {
    pub fn verify(
        verifier: &dyn LmPolicyVerifierV1,
        clock: &dyn MaPolicyTimeV1,
        signed_policy: &[u8],
        issuer_chain: &[Vec<u8>],
        trust: MaPolicyTrustV1,
    ) -> Result<Self, MaPolicyErrorV1> {
        if signed_policy.is_empty() || signed_policy.len() > MAX_POLICY_BYTES {
            return Err(MaPolicyErrorV1::InvalidPolicy);
        }
        validate_chain_bounds(issuer_chain)?;
        let now = clock.unix_seconds()?;
        let authenticated =
            verifier.authenticate_and_canonicalize(signed_policy, issuer_chain, trust, now)?;
        if authenticated.trust != trust {
            return Err(MaPolicyErrorV1::TrustMismatch);
        }
        check_validity(authenticated.issued_at, authenticated.expires_at, now)?;
        let bytes = &authenticated.canonical_semantic_bytes;
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(MaPolicyErrorV1::InvalidPolicy);
        }
        Ok(Self {
            digest: hash_parts(&[POLICY_DOMAIN, &(bytes.len() as u32).to_le_bytes(), bytes]),
            rules: authenticated.rules,
            release_rules: authenticated.release_rules,
            trust,
            issued_at: authenticated.issued_at,
            expires_at: authenticated.expires_at,
        })
    }

    pub fn digest(&self) -> &[u8; 48] {
        &self.digest
    }
}

pub trait MaPolicyTimeV1 {
    fn unix_seconds(&self) -> Result<u64, MaPolicyErrorV1>;
}

/// Authenticated signer claims from the trusted PKI adapter, not peer metadata.
pub struct AuthorizationSignerV1 {
    pub root_spki_der: Vec<u8>,
    pub leaf_subject_der: Vec<u8>,
    pub public_key_sec1: Vec<u8>,
    pub trust: MaPolicyTrustV1,
}

/// Must validate the complete leaf-first chain at trusted time, pinned root,
/// CA/key constraints and the configured fixed-release signing EKU. Fixture
/// roots/EKU must be separate and rejected for Production. No OID is invented here.
pub trait MaPolicySignerVerifierV1 {
    fn verify_signer(
        &self,
        issuer_chain: &[Vec<u8>],
        trust: MaPolicyTrustV1,
        now: u64,
    ) -> Result<AuthorizationSignerV1, MaPolicyErrorV1>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistSnapshotV1 {
    pub revision: u64,
    pub accepted_record: Option<[u8; FixedReleaseAllowlistV1::ENCODED_SIZE]>,
}

/// Scoped by trust/root and FixedReleaseV1. Load authenticates bounded state
/// against an independent rollback anchor; None means explicitly provisioned
/// empty state, never missing/corrupt state. Commit is revision-CAS, atomic and
/// durable, advances the anchor and reports ambiguous effects as failure.
pub trait DurableAllowlistStoreV1 {
    fn load_authenticated(
        &mut self,
        trust: MaPolicyTrustV1,
        root_id: &[u8; 48],
    ) -> Result<AllowlistSnapshotV1, MaPolicyErrorV1>;

    fn commit(
        &mut self,
        trust: MaPolicyTrustV1,
        root_id: &[u8; 48],
        expected_revision: u64,
        record: &[u8; FixedReleaseAllowlistV1::ENCODED_SIZE],
    ) -> Result<(), MaPolicyErrorV1>;
}

pub struct UnavailableMaPolicyServicesV1;

impl LmPolicyVerifierV1 for UnavailableMaPolicyServicesV1 {
    fn authenticate_and_canonicalize(
        &self,
        _: &[u8],
        _: &[Vec<u8>],
        _: MaPolicyTrustV1,
        _: u64,
    ) -> Result<AuthenticatedLmPolicyV1, MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::PolicyUnavailable)
    }
}

impl MaPolicyTimeV1 for UnavailableMaPolicyServicesV1 {
    fn unix_seconds(&self) -> Result<u64, MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::TimeUnavailable)
    }
}

impl MaPolicySignerVerifierV1 for UnavailableMaPolicyServicesV1 {
    fn verify_signer(
        &self,
        _: &[Vec<u8>],
        _: MaPolicyTrustV1,
        _: u64,
    ) -> Result<AuthorizationSignerV1, MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::SignerUnavailable)
    }
}

impl DurableAllowlistStoreV1 for UnavailableMaPolicyServicesV1 {
    fn load_authenticated(
        &mut self,
        _: MaPolicyTrustV1,
        _: &[u8; 48],
    ) -> Result<AllowlistSnapshotV1, MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::StoreUnavailable)
    }

    fn commit(
        &mut self,
        _: MaPolicyTrustV1,
        _: &[u8; 48],
        _: u64,
        _: &[u8; 320],
    ) -> Result<(), MaPolicyErrorV1> {
        Err(MaPolicyErrorV1::StoreUnavailable)
    }
}

pub struct MaPolicyVerificationRequestV1<'a> {
    pub evidence: &'a SnpMaEvidenceV1,
    pub report_collateral: &'a SnpCollateralSetV1,
    /// Independently reconstructed from trusted operation state.
    pub expected_context: &'a ReportDataContextV1,
    /// FixedRelease-only selection by trusted deployment configuration. Ordered
    /// releases instead use the authenticated policy publisher/floor and mapping.
    pub selected_identity: &'a [u8; 48],
    pub expected_vmpl: u32,
    pub report_trust: SnpVerifierTrust,
    pub authorization_trust: MaPolicyTrustV1,
}

pub struct MaPolicyVerificationServicesV1<'a> {
    pub evidence_verifier: &'a dyn SnpEvidenceVerifier,
    pub signer_verifier: &'a dyn MaPolicySignerVerifierV1,
    pub clock: &'a dyn MaPolicyTimeV1,
    pub store: &'a mut dyn DurableAllowlistStoreV1,
}

#[derive(Debug)]
pub struct VerifiedMaPolicyEvidenceV1 {
    context: ReportDataContextV1,
    report_id: [u8; 32],
    report_digest: [u8; 48],
    report_collateral_digest: [u8; 48],
    identity_digest: [u8; 48],
    policy_digest: [u8; 48],
    policy_issued_at: u64,
    policy_expires_at: u64,
    rules: FixedReleaseAdmissionRulesV1,
    current_tcb: VeniceTcbV1,
    current_etcb: VeniceEtcbV1,
    current_mit_vector: u64,
    report_trust: SnpVerifierTrust,
    authorization_trust: MaPolicyTrustV1,
}

pub type VerifiedFixedReleaseV1 = VerifiedMaPolicyEvidenceV1;

/// Profile-specific approvals cannot be fabricated from decoded metadata.
///
/// ```compile_fail
/// use pal::snp::ma_policy::VerifiedFixedReleaseV1;
/// let approval = VerifiedFixedReleaseV1 {};
/// ```
#[derive(Debug)]
pub enum VerifiedMaPolicyCollateral {
    FixedReleaseV1(VerifiedFixedReleaseV1),
    OrderedReleaseV1(ordered::VerifiedOrderedReleaseV1),
}

impl VerifiedMaPolicyCollateral {
    fn evidence(&self) -> &VerifiedMaPolicyEvidenceV1 {
        match self {
            Self::FixedReleaseV1(value) => value,
            Self::OrderedReleaseV1(value) => &value.evidence,
        }
    }

    pub fn context(&self) -> &ReportDataContextV1 {
        &self.evidence().context
    }

    pub fn identity_digest(&self) -> &[u8; 48] {
        &self.evidence().identity_digest
    }

    pub fn policy_digest(&self) -> &[u8; 48] {
        &self.evidence().policy_digest
    }

    pub fn report_id(&self) -> &[u8; 32] {
        &self.evidence().report_id
    }

    pub fn report_digest(&self) -> &[u8; 48] {
        &self.evidence().report_digest
    }

    pub fn report_collateral_digest(&self) -> &[u8; 48] {
        &self.evidence().report_collateral_digest
    }

    pub fn verify_fixed(
        request: &MaPolicyVerificationRequestV1<'_>,
        policy: &VerifiedLmPolicyV1,
        collateral: &FixedReleaseCollateralV1,
        services: &mut MaPolicyVerificationServicesV1<'_>,
    ) -> Result<Self, MaPolicyErrorV1> {
        if policy.release_rules != MaPolicyReleaseRulesV1::FixedReleaseV1 {
            return Err(MaPolicyErrorV1::UnsupportedProfile);
        }
        let verified_evidence =
            verify_policy_evidence(request, policy, services.evidence_verifier, services.clock)?;
        let identity = verified_evidence.identity_digest;
        let allowlist = &collateral.identity.allowlist;
        let encoded_allowlist = allowlist.encode_exact()?;
        if identity != *request.selected_identity
            || identity != request.expected_context.ma_policy_identity_digest
            || identity != allowlist.identity_digest
        {
            return Err(MaPolicyErrorV1::IdentityMismatch);
        }
        let now = services.clock.unix_seconds()?;
        check_validity(policy.issued_at, policy.expires_at, now)?;
        check_validity(allowlist.issued_at, allowlist.expires_at, now)?;
        validate_chain_bounds(&collateral.identity_issuer_chain)?;
        let signer = services.signer_verifier.verify_signer(
            &collateral.identity_issuer_chain,
            request.authorization_trust,
            now,
        )?;
        if signer.trust != request.authorization_trust {
            return Err(MaPolicyErrorV1::TrustMismatch);
        }
        if signer.root_spki_der.is_empty()
            || signer.leaf_subject_der.is_empty()
            || signer.root_spki_der.len() > MAX_POLICY_BYTES
            || signer.leaf_subject_der.len() > MAX_POLICY_BYTES
            || signer.public_key_sec1.len() != 97
            || signer.public_key_sec1[0] != 4
        {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        let root_id = sha384(&signer.root_spki_der);
        let signer_id = hash_parts(&[
            SIGNER_DOMAIN,
            &root_id,
            &(signer.leaf_subject_der.len() as u32).to_le_bytes(),
            &signer.leaf_subject_der,
        ]);
        if root_id != allowlist.authorization_root_id || signer_id != allowlist.signer_id {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P384_SHA384_FIXED,
            &signer.public_key_sec1,
        )
        .verify(
            &encoded_allowlist[..FixedReleaseAllowlistV1::SIGNED_SIZE],
            &allowlist.signature,
        )
        .map_err(|_| MaPolicyErrorV1::InvalidSignature)?;
        let snapshot = services
            .store
            .load_authenticated(request.authorization_trust, &root_id)?;
        if let Some(previous) = snapshot.accepted_record {
            let old = FixedReleaseAllowlistV1::decode_exact(&previous)
                .map_err(|_| MaPolicyErrorV1::InvalidStoredState)?;
            if old.authorization_root_id != root_id {
                return Err(MaPolicyErrorV1::InvalidStoredState);
            }
            if allowlist.sequence < old.sequence {
                return Err(MaPolicyErrorV1::SequenceRollback);
            }
            if allowlist.sequence == old.sequence && previous[..224] != encoded_allowlist[..224] {
                return Err(MaPolicyErrorV1::SequenceContentConflict);
            }
        }
        // Even an identical retry must CAS: a concurrent replacement cannot be ignored.
        services.store.commit(
            request.authorization_trust,
            &root_id,
            snapshot.revision,
            &encoded_allowlist,
        )?;
        Ok(Self::FixedReleaseV1(verified_evidence))
    }
}

/// Checks current-platform forwarding, not tenant history or firmware readiness.
pub fn admit_fixed_release_pair_v1(
    source: &VerifiedMaPolicyCollateral,
    destination: &VerifiedMaPolicyCollateral,
) -> Result<(), MaPolicyErrorV1> {
    let (
        VerifiedMaPolicyCollateral::FixedReleaseV1(source),
        VerifiedMaPolicyCollateral::FixedReleaseV1(destination),
    ) = (source, destination)
    else {
        return Err(MaPolicyErrorV1::UnsupportedProfile);
    };
    let src = &source.context;
    let dst = &destination.context;
    let inter_node = src.role == SnpMaRoleV1::Source && dst.role == SnpMaRoleV1::Destination;
    let handoff = src.role == SnpMaRoleV1::Outgoing && dst.role == SnpMaRoleV1::Incoming;
    if !(inter_node || handoff)
        || src.evidence_purpose != dst.evidence_purpose
        || src.request_id != dst.request_id
        || src.tenant_binding_id != dst.tenant_binding_id
        || src.th1 != dst.th1
        || src.algorithm != dst.algorithm
        || src.negotiated_migration_version != dst.negotiated_migration_version
        || source.identity_digest != destination.identity_digest
        || source.policy_digest != destination.policy_digest
        || source.rules != destination.rules
        || source.report_trust != destination.report_trust
        || source.authorization_trust != destination.authorization_trust
    {
        return Err(MaPolicyErrorV1::ContextMismatch);
    }
    let forwarding = FixedReleaseAdmissionRulesV1 {
        minimum_current_tcb: source.current_tcb,
        minimum_current_etcb: source.current_etcb,
        minimum_current_mit_vector: source.rules.minimum_current_mit_vector
            | source.current_mit_vector,
    };
    validate_platform(
        &destination.current_tcb,
        &destination.current_etcb,
        destination.current_mit_vector,
        &forwarding,
    )
}

fn verify_policy_evidence(
    request: &MaPolicyVerificationRequestV1<'_>,
    policy: &VerifiedLmPolicyV1,
    verifier: &dyn SnpEvidenceVerifier,
    clock: &dyn MaPolicyTimeV1,
) -> Result<VerifiedMaPolicyEvidenceV1, MaPolicyErrorV1> {
    if request.authorization_trust == MaPolicyTrustV1::Production {
        return Err(MaPolicyErrorV1::ProductionProfileUnavailable);
    }
    let evidence = request.evidence;
    evidence.encode_exact()?;
    if evidence.report_data_context != *request.expected_context
        || evidence.header.tcb_profile != SnpTcbProfileV1::Venice
        || request.report_collateral.tcb_profile != SnpTcbProfileV1::Venice
        || evidence.policy_identity.policy_digest != *policy.digest()
    {
        return Err(MaPolicyErrorV1::ContextMismatch);
    }
    if policy.trust != request.authorization_trust
        || evidence.header.evidence_profile != request.authorization_trust.evidence_profile()
        || request.report_collateral.evidence_profile != evidence.header.evidence_profile
    {
        return Err(MaPolicyErrorV1::TrustMismatch);
    }
    if sha384(&request.report_collateral.encode_exact()?) != evidence.collateral_digest {
        return Err(MaPolicyErrorV1::CollateralMismatch);
    }
    let leaf_kind = match request.report_collateral.leaf_certificate.role {
        SnpCertificateRoleV1::Vcek => SnpCollateralLeafKind::Vcek,
        SnpCertificateRoleV1::Vlek => SnpCollateralLeafKind::Vlek,
        SnpCertificateRoleV1::Ask => return Err(MaPolicyErrorV1::CollateralMismatch),
    };
    let report_collateral = SnpVerificationCollateral::new_with_leaf(
        leaf_kind,
        request
            .report_collateral
            .leaf_certificate
            .certificate_der
            .clone(),
        request
            .report_collateral
            .ask_certificate
            .certificate_der
            .clone(),
    );
    let report = MaEvidence::new(evidence.ma_report, MaEvidenceBinding::RequestedReportData);
    let verified = request
        .expected_context
        .verify_ma_evidence(
            verifier,
            &report,
            &report_collateral,
            request.expected_vmpl,
            request.report_trust,
        )
        .map_err(MaPolicyErrorV1::Evidence)?;
    if verified.tcb_status != TcbStatus::UpToDate {
        return Err(MaPolicyErrorV1::PlatformDowngrade);
    }
    let mut key_info = StrictReader::new(&report.report()[0x48..0x4c]);
    let key_info = key_info.read_u32()?;
    let expected_key = match leaf_kind {
        SnpCollateralLeafKind::Vcek => 0,
        SnpCollateralLeafKind::Vlek => 1,
    };
    if key_info & !0x1f != 0
        || (key_info >> 2) & 7 != expected_key
        || (key_info & 1 == 0 && report.report()[0x110..0x140] != [0; 48])
    {
        return Err(MaPolicyErrorV1::Evidence(
            SnpVerificationError::InvalidEvidence,
        ));
    }
    let identity =
        MaPolicyIdentityInputV1::from_authenticated_report(report.report(), *policy.digest())?
            .digest()?;
    if identity != request.expected_context.ma_policy_identity_digest {
        return Err(MaPolicyErrorV1::IdentityMismatch);
    }
    check_validity(policy.issued_at, policy.expires_at, clock.unix_seconds()?)?;
    let current_tcb = VeniceTcbV1::decode_exact(&report.report()[0x38..0x40])?;
    let current_etcb = VeniceEtcbV1::from_report_bytes(&report.report()[0x220..0x240])?;
    let current_mit_vector = StrictReader::new(&report.report()[0x200..0x208]).read_u64()?;
    validate_platform(
        &current_tcb,
        &current_etcb,
        current_mit_vector,
        &policy.rules,
    )?;
    let mut report_id = [0; 32];
    report_id.copy_from_slice(&report.report()[0x140..0x160]);
    Ok(VerifiedMaPolicyEvidenceV1 {
        context: request.expected_context.clone(),
        report_id,
        report_digest: sha384(report.report()),
        report_collateral_digest: evidence.collateral_digest,
        identity_digest: identity,
        policy_digest: *policy.digest(),
        policy_issued_at: policy.issued_at,
        policy_expires_at: policy.expires_at,
        rules: policy.rules,
        current_tcb,
        current_etcb,
        current_mit_vector,
        report_trust: request.report_trust,
        authorization_trust: request.authorization_trust,
    })
}

fn validate_platform(
    current_tcb: &VeniceTcbV1,
    current_etcb: &VeniceEtcbV1,
    mit_vector: u64,
    rules: &FixedReleaseAdmissionRulesV1,
) -> Result<(), MaPolicyErrorV1> {
    if current_tcb.component_min(&rules.minimum_current_tcb) != rules.minimum_current_tcb
        || current_etcb.component_min(&rules.minimum_current_etcb) != rules.minimum_current_etcb
    {
        return Err(MaPolicyErrorV1::PlatformDowngrade);
    }
    if mit_vector & rules.minimum_current_mit_vector != rules.minimum_current_mit_vector {
        return Err(MaPolicyErrorV1::MitigationMissing);
    }
    Ok(())
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 48] {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA384);
    for part in parts {
        hash.update(part);
    }
    let mut result = [0; 48];
    result.copy_from_slice(hash.finish().as_ref());
    result
}

fn check_validity(issued: u64, expires: u64, now: u64) -> Result<(), MaPolicyErrorV1> {
    if issued <= now && now < expires {
        Ok(())
    } else {
        Err(MaPolicyErrorV1::OutsideValidity)
    }
}

fn validate_chain_bounds(chain: &[Vec<u8>]) -> Result<(), MaPolicyErrorV1> {
    if chain.is_empty()
        || chain.len() > MAX_ISSUER_CERTIFICATES
        || chain
            .iter()
            .any(|cert| cert.is_empty() || cert.len() > MAX_POLICY_BYTES)
    {
        Err(MaPolicyErrorV1::InvalidSigner)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "ma_policy_tests.rs"]
mod tests;
