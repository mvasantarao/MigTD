// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Direct-random V2 tenant association. No secret, commitment or KDF input.

use super::{
    purpose_binding::sha384,
    report_data_context::{
        ReportDataContextV1, SnpEvidencePurposeV1, SnpMaRoleV1, SnpMigrationAlgorithmV1,
    },
    wire::{SnpCodecError, StrictWriter},
};
use crate::{
    tenant_identity::VerifiedTenantReportDeliveryV1,
    tenant_replay::{VerifiedTenantAuthorizationV1, VerifiedTenantReplayBindingV1},
    traits::SnpEvidenceVerifier,
    types::{
        MaEvidence, SnpVerificationCollateral, SnpVerificationError, SnpVerifierTrust,
        SNP_ATTESTATION_REPORT_SIZE,
    },
};

/// Fingerprint only. Every supplement byte must already be authenticated;
/// the current verified delivery bridge mints receipts only for raw reports.
pub fn canonical_tenant_evidence_digest_v1(
    report: &[u8; SNP_ATTESTATION_REPORT_SIZE],
    supplement: Option<(&[u8; 220], &[u8; 96])>,
) -> [u8; 48] {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA384);
    hash.update(b"SNP-LM-TENANT-EVIDENCE-v1");
    let encoding: u16 = if supplement.is_some() { 2 } else { 1 };
    hash.update(&encoding.to_le_bytes());
    hash.update(&(SNP_ATTESTATION_REPORT_SIZE as u32).to_le_bytes());
    hash.update(report);
    match supplement {
        Some((bytes, signature)) => {
            hash.update(&220u32.to_le_bytes());
            hash.update(bytes);
            hash.update(&96u32.to_le_bytes());
            hash.update(signature);
        }
        None => {
            hash.update(&0u32.to_le_bytes());
            hash.update(&0u32.to_le_bytes());
        }
    }
    hash.finish().as_ref().try_into().expect("SHA384 size")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectAuthorizationErrorV2 {
    Codec(SnpCodecError),
    Verification(SnpVerificationError),
    ContextMismatch,
    SourceMaBindingMismatch,
    MaIdentityMismatch,
    MissingOrWrongRoleProof,
}

/// Reconstruct from the verified complete tenant delivery and actual SPDM TH1.
/// The role and MA/policy identity remain bound by the full REPORT_DATA context.
pub fn session_context_v2(
    mut context: ReportDataContextV1,
    tenant: &VerifiedTenantReportDeliveryV1,
) -> Result<ReportDataContextV1, DirectAuthorizationErrorV2> {
    if context.request_id != tenant.operation().request_id.value()
        || context.tenant_binding_id != *tenant.identity().as_bytes()
        || !matches!(context.role, SnpMaRoleV1::Source | SnpMaRoleV1::Destination)
        || context.algorithm != SnpMigrationAlgorithmV1::Aes256GcmMigrationV1
    {
        return Err(DirectAuthorizationErrorV2::ContextMismatch);
    }
    context.evidence_purpose = SnpEvidencePurposeV1::InterNodeSessionV2;
    let mut preimage = b"SNP-LM-SESSION-BIND-v2".to_vec();
    preimage.extend_from_slice(&context.request_id.to_le_bytes());
    preimage.extend_from_slice(&context.negotiated_migration_version.to_le_bytes());
    preimage.extend_from_slice(&(context.algorithm as u16).to_le_bytes());
    preimage.extend_from_slice(&context.tenant_binding_id);
    preimage.extend_from_slice(tenant.canonical_evidence_digest());
    preimage.extend_from_slice(&context.th1);
    context.purpose_binding_digest = sha384(&preimage);
    context
        .validate()
        .map_err(DirectAuthorizationErrorV2::Codec)?;
    Ok(context)
}

/// Cryptographic session evidence, not policy or durable replay authorization.
#[derive(Debug, Clone)]
pub struct VerifiedSessionMaV2 {
    context: ReportDataContextV1,
    report_id: [u8; 32],
    trust: SnpVerifierTrust,
}

impl VerifiedSessionMaV2 {
    pub fn verify(
        context: &ReportDataContextV1,
        tenant: &VerifiedTenantReportDeliveryV1,
        verifier: &dyn SnpEvidenceVerifier,
        evidence: &MaEvidence,
        collateral: &SnpVerificationCollateral,
        expected_vmpl: u32,
    ) -> Result<Self, DirectAuthorizationErrorV2> {
        if context != &session_context_v2(context.clone(), tenant)? {
            return Err(DirectAuthorizationErrorV2::ContextMismatch);
        }
        context
            .verify_ma_evidence(
                verifier,
                evidence,
                collateral,
                expected_vmpl,
                tenant.trust(),
            )
            .map_err(DirectAuthorizationErrorV2::Verification)?;
        Ok(Self {
            context: context.clone(),
            report_id: evidence.report()[0x140..0x160]
                .try_into()
                .expect("REPORT_ID size"),
            trust: tenant.trust(),
        })
    }
}

#[derive(Debug)]
pub struct TenantAuthorizationContextV2 {
    tenant: VerifiedTenantReportDeliveryV1,
    source: VerifiedSessionMaV2,
    destination: VerifiedSessionMaV2,
}

impl TenantAuthorizationContextV2 {
    pub const DOMAIN: &'static [u8] = b"SNP-LM-TENANT-AUTH-v2";
    pub const ENCODED_SIZE: usize = Self::DOMAIN.len() + 304;

    pub fn new(
        tenant: VerifiedTenantReportDeliveryV1,
        source: VerifiedSessionMaV2,
        destination: VerifiedSessionMaV2,
    ) -> Result<Self, DirectAuthorizationErrorV2> {
        if source.context.role != SnpMaRoleV1::Source
            || destination.context.role != SnpMaRoleV1::Destination
            || source.context != session_context_v2(source.context.clone(), &tenant)?
            || destination.context != session_context_v2(destination.context.clone(), &tenant)?
            || source.context.th1 != destination.context.th1
            || source.context.negotiated_migration_version
                != destination.context.negotiated_migration_version
            || source.trust != tenant.trust()
            || destination.trust != tenant.trust()
        {
            return Err(DirectAuthorizationErrorV2::ContextMismatch);
        }
        if tenant.report_id_ma() != &source.report_id {
            return Err(DirectAuthorizationErrorV2::SourceMaBindingMismatch);
        }
        Ok(Self {
            tenant,
            source,
            destination,
        })
    }

    pub fn encode_exact(&self) -> Result<[u8; Self::ENCODED_SIZE], DirectAuthorizationErrorV2> {
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut w = StrictWriter::new(&mut bytes);
        let encode = |w: &mut StrictWriter<'_>| {
            w.write_bytes(Self::DOMAIN)?;
            w.write_u16(2)?;
            w.write_u64(self.source.context.request_id)?;
            w.write_u16(self.source.context.negotiated_migration_version)?;
            w.write_u16(SnpMigrationAlgorithmV1::Aes256GcmMigrationV1 as u16)?;
            w.write_u8(SnpMaRoleV1::Source as u8)?;
            w.write_u8(SnpMaRoleV1::Destination as u8)?;
            w.write_bytes(self.tenant.identity().as_bytes())?;
            w.write_bytes(self.tenant.canonical_evidence_digest())?;
            w.write_bytes(&self.source.context.th1)?;
            w.write_bytes(&self.source.report_id)?;
            w.write_bytes(&self.destination.report_id)?;
            w.write_bytes(&self.source.context.ma_policy_identity_digest)?;
            w.write_bytes(&self.destination.context.ma_policy_identity_digest)
        };
        encode(&mut w).map_err(DirectAuthorizationErrorV2::Codec)?;
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<[u8; 48], DirectAuthorizationErrorV2> {
        Ok(sha384(&self.encode_exact()?))
    }

    pub fn session_context(
        &self,
        role: SnpMaRoleV1,
    ) -> Result<&ReportDataContextV1, DirectAuthorizationErrorV2> {
        match role {
            SnpMaRoleV1::Source => Ok(&self.source.context),
            SnpMaRoleV1::Destination => Ok(&self.destination.context),
            _ => Err(DirectAuthorizationErrorV2::ContextMismatch),
        }
    }

    pub fn report_data_context(
        &self,
        role: SnpMaRoleV1,
    ) -> Result<ReportDataContextV1, DirectAuthorizationErrorV2> {
        Ok(ReportDataContextV1 {
            evidence_purpose: SnpEvidencePurposeV1::InterNodeTenantAuthorizationV2,
            purpose_binding_digest: self.digest()?,
            ..self.session_context(role)?.clone()
        })
    }

    pub fn replay_binding(
        &self,
    ) -> Result<VerifiedTenantReplayBindingV1, DirectAuthorizationErrorV2> {
        Ok(VerifiedTenantReplayBindingV1::from_verified_context(
            &self.tenant,
            self.digest()?,
            self.source.report_id,
            self.destination.report_id,
        ))
    }

    pub fn verify_role_proof(
        &self,
        role: SnpMaRoleV1,
        verifier: &dyn SnpEvidenceVerifier,
        evidence: &MaEvidence,
        collateral: &SnpVerificationCollateral,
        expected_vmpl: u32,
    ) -> Result<VerifiedTenantAuthorizationRoleV2, DirectAuthorizationErrorV2> {
        self.report_data_context(role)?
            .verify_ma_evidence(
                verifier,
                evidence,
                collateral,
                expected_vmpl,
                self.tenant.trust(),
            )
            .map_err(DirectAuthorizationErrorV2::Verification)?;
        let expected = match role {
            SnpMaRoleV1::Source => self.source.report_id,
            SnpMaRoleV1::Destination => self.destination.report_id,
            _ => return Err(DirectAuthorizationErrorV2::ContextMismatch),
        };
        if evidence.report()[0x140..0x160] != expected {
            return Err(DirectAuthorizationErrorV2::MaIdentityMismatch);
        }
        Ok(VerifiedTenantAuthorizationRoleV2 {
            role,
            digest: self.digest()?,
        })
    }

    pub fn accept_both_roles(
        &self,
        source: VerifiedTenantAuthorizationRoleV2,
        destination: VerifiedTenantAuthorizationRoleV2,
    ) -> Result<VerifiedTenantAuthorizationV1, DirectAuthorizationErrorV2> {
        let digest = self.digest()?;
        if source.role != SnpMaRoleV1::Source
            || destination.role != SnpMaRoleV1::Destination
            || source.digest != digest
            || destination.digest != digest
        {
            return Err(DirectAuthorizationErrorV2::MissingOrWrongRoleProof);
        }
        Ok(VerifiedTenantAuthorizationV1::from_verified_roles(
            self.replay_binding()?,
        ))
    }
}

/// No decoded peer fields can mint a successful purpose-7 proof.
///
/// ```compile_fail
/// use pal::snp::direct_authorization::VerifiedTenantAuthorizationRoleV2;
/// let forged = VerifiedTenantAuthorizationRoleV2 {};
/// ```
#[derive(Debug)]
pub struct VerifiedTenantAuthorizationRoleV2 {
    role: SnpMaRoleV1,
    digest: [u8; 48],
}

#[cfg(test)]
mod tests;
