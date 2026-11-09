// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Superseded, test-only P0.6 contribution-bound V1 authorization.

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
    types::{MaEvidence, SnpVerificationCollateral, SnpVerificationError, SnpVerifierTrust},
};

pub use super::direct_authorization::canonical_tenant_evidence_digest_v1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantAuthorizationErrorV1 {
    Codec(SnpCodecError),
    Verification(SnpVerificationError),
    ContextMismatch,
    SourceMaBindingMismatch,
    MaIdentityMismatch,
    MissingOrWrongRoleProof,
}

/// Cryptographic purpose-1 proof, not software-allowlist or migration policy
/// approval. The runtime must complete Task 7 policy checks before using it.
#[derive(Debug, Clone)]
pub struct VerifiedContributionMaV1 {
    context: ReportDataContextV1,
    report_id: [u8; 32],
    trust: SnpVerifierTrust,
}

impl VerifiedContributionMaV1 {
    /// `context` must be reconstructed from trusted local session state.
    pub fn verify(
        context: &ReportDataContextV1,
        verifier: &dyn SnpEvidenceVerifier,
        evidence: &MaEvidence,
        collateral: &SnpVerificationCollateral,
        expected_vmpl: u32,
        trust: SnpVerifierTrust,
    ) -> Result<Self, TenantAuthorizationErrorV1> {
        if context.evidence_purpose != SnpEvidencePurposeV1::InterNodeKeyContribution
            || !matches!(context.role, SnpMaRoleV1::Source | SnpMaRoleV1::Destination)
        {
            return Err(TenantAuthorizationErrorV1::ContextMismatch);
        }
        context
            .verify_ma_evidence(verifier, evidence, collateral, expected_vmpl, trust)
            .map_err(TenantAuthorizationErrorV1::Verification)?;
        let mut report_id = [0; 32];
        report_id.copy_from_slice(&evidence.report()[0x140..0x160]);
        Ok(Self {
            context: context.clone(),
            report_id,
            trust,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TenantAuthorizationContextV1 {
    tenant: VerifiedTenantReportDeliveryV1,
    source: VerifiedContributionMaV1,
    destination: VerifiedContributionMaV1,
}

impl TenantAuthorizationContextV1 {
    pub const DOMAIN: &'static [u8] = b"SNP-LM-TENANT-AUTH-v1";
    pub const ENCODED_SIZE: usize = Self::DOMAIN.len() + 400;

    pub fn new(
        tenant: VerifiedTenantReportDeliveryV1,
        source: VerifiedContributionMaV1,
        destination: VerifiedContributionMaV1,
    ) -> Result<Self, TenantAuthorizationErrorV1> {
        let src = &source.context;
        let dst = &destination.context;
        if src.role != SnpMaRoleV1::Source
            || dst.role != SnpMaRoleV1::Destination
            || src.request_id != tenant.operation().request_id.value()
            || src.request_id != dst.request_id
            || src.tenant_binding_id != *tenant.identity().as_bytes()
            || src.tenant_binding_id != dst.tenant_binding_id
            || src.th1 != dst.th1
            || src.negotiated_migration_version != dst.negotiated_migration_version
            || source.trust != tenant.trust()
            || source.trust != destination.trust
        {
            return Err(TenantAuthorizationErrorV1::ContextMismatch);
        }
        if tenant.report_id_ma() != &source.report_id {
            return Err(TenantAuthorizationErrorV1::SourceMaBindingMismatch);
        }
        Ok(Self {
            tenant,
            source,
            destination,
        })
    }

    pub fn encode_exact(&self) -> Result<[u8; Self::ENCODED_SIZE], TenantAuthorizationErrorV1> {
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut bytes);
        let encode = |writer: &mut StrictWriter<'_>| {
            writer.write_bytes(Self::DOMAIN)?;
            writer.write_u16(1)?;
            writer.write_u64(self.source.context.request_id)?;
            writer.write_u16(self.source.context.negotiated_migration_version)?;
            writer.write_u16(SnpMigrationAlgorithmV1::Aes256GcmMigrationV1 as u16)?;
            writer.write_u8(SnpMaRoleV1::Source as u8)?;
            writer.write_u8(SnpMaRoleV1::Destination as u8)?;
            writer.write_bytes(self.tenant.identity().as_bytes())?;
            writer.write_bytes(self.tenant.canonical_evidence_digest())?;
            writer.write_bytes(&self.source.context.th1)?;
            writer.write_bytes(&self.source.report_id)?;
            writer.write_bytes(&self.destination.report_id)?;
            writer.write_bytes(&self.source.context.ma_policy_identity_digest)?;
            writer.write_bytes(&self.destination.context.ma_policy_identity_digest)?;
            writer.write_bytes(&self.source.context.purpose_binding_digest)?;
            writer.write_bytes(&self.destination.context.purpose_binding_digest)
        };
        encode(&mut writer).map_err(TenantAuthorizationErrorV1::Codec)?;
        if writer.written() != Self::ENCODED_SIZE {
            return Err(TenantAuthorizationErrorV1::Codec(
                SnpCodecError::NonCanonicalEncoding,
            ));
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<[u8; 48], TenantAuthorizationErrorV1> {
        Ok(sha384(&self.encode_exact()?))
    }

    pub fn contribution_context(
        &self,
        role: SnpMaRoleV1,
    ) -> Result<&ReportDataContextV1, TenantAuthorizationErrorV1> {
        match role {
            SnpMaRoleV1::Source => Ok(&self.source.context),
            SnpMaRoleV1::Destination => Ok(&self.destination.context),
            _ => Err(TenantAuthorizationErrorV1::ContextMismatch),
        }
    }

    pub fn report_data_context(
        &self,
        role: SnpMaRoleV1,
    ) -> Result<ReportDataContextV1, TenantAuthorizationErrorV1> {
        let contribution = match role {
            SnpMaRoleV1::Source => &self.source,
            SnpMaRoleV1::Destination => &self.destination,
            _ => return Err(TenantAuthorizationErrorV1::ContextMismatch),
        };
        let context = ReportDataContextV1 {
            evidence_purpose: SnpEvidencePurposeV1::InterNodeTenantAuthorization,
            purpose_binding_digest: self.digest()?,
            ..contribution.context.clone()
        };
        context
            .validate()
            .map_err(TenantAuthorizationErrorV1::Codec)?;
        Ok(context)
    }

    pub fn replay_binding(
        &self,
    ) -> Result<VerifiedTenantReplayBindingV1, TenantAuthorizationErrorV1> {
        Ok(VerifiedTenantReplayBindingV1::from_verified_context(
            &self.tenant,
            self.digest()?,
            self.source.report_id,
            self.destination.report_id,
        ))
    }

    pub fn verify_role_evidence(
        &self,
        role: SnpMaRoleV1,
        verifier: &dyn SnpEvidenceVerifier,
        evidence: &MaEvidence,
        collateral: &SnpVerificationCollateral,
        expected_vmpl: u32,
    ) -> Result<VerifiedTenantAuthorizationRoleV1, TenantAuthorizationErrorV1> {
        let context = self.report_data_context(role)?;
        context
            .verify_ma_evidence(
                verifier,
                evidence,
                collateral,
                expected_vmpl,
                self.tenant.trust(),
            )
            .map_err(TenantAuthorizationErrorV1::Verification)?;
        let expected_id = match role {
            SnpMaRoleV1::Source => self.source.report_id,
            SnpMaRoleV1::Destination => self.destination.report_id,
            _ => return Err(TenantAuthorizationErrorV1::ContextMismatch),
        };
        if evidence.report()[0x140..0x160] != expected_id {
            return Err(TenantAuthorizationErrorV1::MaIdentityMismatch);
        }
        Ok(VerifiedTenantAuthorizationRoleV1 {
            role,
            authorization_digest: self.digest()?,
        })
    }

    pub fn accept_both_roles(
        &self,
        source: VerifiedTenantAuthorizationRoleV1,
        destination: VerifiedTenantAuthorizationRoleV1,
    ) -> Result<VerifiedTenantAuthorizationV1, TenantAuthorizationErrorV1> {
        let digest = self.digest()?;
        if source.role != SnpMaRoleV1::Source
            || destination.role != SnpMaRoleV1::Destination
            || source.authorization_digest != digest
            || destination.authorization_digest != digest
        {
            return Err(TenantAuthorizationErrorV1::MissingOrWrongRoleProof);
        }
        Ok(VerifiedTenantAuthorizationV1::from_verified_roles(
            self.replay_binding()?,
        ))
    }
}

#[derive(Debug)]
/// No decoded peer fields can construct a successful role proof.
///
/// ```compile_fail
/// use pal::snp::{tenant_authorization::VerifiedTenantAuthorizationRoleV1,
///     report_data_context::SnpMaRoleV1};
/// let proof = VerifiedTenantAuthorizationRoleV1 {
///     role: SnpMaRoleV1::Source, authorization_digest: [0; 48],
/// };
/// ```
pub struct VerifiedTenantAuthorizationRoleV1 {
    role: SnpMaRoleV1,
    authorization_digest: [u8; 48],
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        tenant_identity::{
            HostPushedTenantReportV1, PrepareMigrationRequestV1, TenantReportDeliveryV1,
        },
        tenant_replay::{
            TenantReplayErrorV1, TenantReplayJournalV1, UnavailableTenantFirmwareStateV1,
            UnavailableTenantReplayStoreV1,
        },
        types::{
            HostRequestId, MaEvidenceBinding, ManagedGuestHandle, MigrationId, MigrationRole,
            SnpEvidenceVerificationRequest, SnpOperationContext, SnpReportRequestKind, TcbStatus,
            VerifiedSnpEvidence,
        },
    };
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    pub(crate) struct TestVerifier {
        calls: RefCell<Vec<SnpReportRequestKind>>,
        pub(crate) fail: Cell<bool>,
        pub(crate) trust: Cell<Option<SnpVerifierTrust>>,
        pub(crate) binding: Cell<Option<MaEvidenceBinding>>,
    }

    impl SnpEvidenceVerifier for TestVerifier {
        fn verify_evidence(
            &self,
            request: &SnpEvidenceVerificationRequest<'_>,
        ) -> Result<VerifiedSnpEvidence, SnpVerificationError> {
            self.calls.borrow_mut().push(request.report_request);
            if self.fail.get() {
                return Err(SnpVerificationError::CryptographicVerification);
            }
            Ok(VerifiedSnpEvidence {
                binding: self.binding.get().unwrap_or(request.evidence.binding()),
                tcb_status: TcbStatus::UpToDate,
                platform_tcb: None,
                trust: self.trust.get().unwrap_or(request.trust),
            })
        }
    }

    pub(crate) fn tenant_bytes() -> [u8; 1184] {
        let mut bytes = [0; 1184];
        bytes[..4].copy_from_slice(&6u32.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[0x140..0x160].fill(0x33);
        bytes[0x160..0x180].fill(0x11);
        bytes
    }

    pub(crate) fn tenant(
        verifier: &TestVerifier,
        role: MigrationRole,
        bytes: &[u8],
    ) -> VerifiedTenantReportDeliveryV1 {
        let operation = SnpOperationContext::new(
            HostRequestId::new(0x0102_0304_0506_0708),
            MigrationId::new(2),
            role,
            ManagedGuestHandle::new(3),
        );
        PrepareMigrationRequestV1::new(
            operation,
            TenantReportDeliveryV1::Inline(HostPushedTenantReportV1::from_bytes(bytes).unwrap()),
        )
        .verify_tenant_report(
            verifier,
            &collateral(),
            SnpVerifierTrust::PinnedMilanArkTest,
            None,
        )
        .unwrap()
    }

    pub(crate) fn collateral() -> SnpVerificationCollateral {
        SnpVerificationCollateral::new(vec![], vec![])
    }

    pub(crate) fn contribution_context(role: SnpMaRoleV1) -> ReportDataContextV1 {
        ReportDataContextV1 {
            evidence_purpose: SnpEvidencePurposeV1::InterNodeKeyContribution,
            role,
            request_id: 0x0102_0304_0506_0708,
            negotiated_migration_version: 1,
            algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            tenant_binding_id: [0x33; 32],
            th1: [0x44; 48],
            purpose_binding_digest: if role == SnpMaRoleV1::Source {
                [0x55; 48]
            } else {
                [0x66; 48]
            },
            ma_policy_identity_digest: if role == SnpMaRoleV1::Source {
                [0x77; 48]
            } else {
                [0x88; 48]
            },
        }
    }

    pub(crate) fn ma_report(context: &ReportDataContextV1) -> MaEvidence {
        let mut bytes = [0; 1184];
        bytes[..4].copy_from_slice(&6u32.to_le_bytes());
        bytes[0x50..0x90].copy_from_slice(&context.expected_report_data().unwrap());
        bytes[0x140..0x160].fill(if context.role == SnpMaRoleV1::Source {
            0x11
        } else {
            0x22
        });
        MaEvidence::new(bytes, MaEvidenceBinding::RequestedReportData)
    }

    fn contribution(verifier: &TestVerifier, role: SnpMaRoleV1) -> VerifiedContributionMaV1 {
        let context = contribution_context(role);
        VerifiedContributionMaV1::verify(
            &context,
            verifier,
            &ma_report(&context),
            &collateral(),
            0,
            SnpVerifierTrust::PinnedMilanArkTest,
        )
        .unwrap()
    }

    fn authorization_context(verifier: &TestVerifier) -> TenantAuthorizationContextV1 {
        let tenant = tenant(verifier, MigrationRole::Source, &tenant_bytes());
        let source = contribution(verifier, SnpMaRoleV1::Source);
        let destination = contribution(verifier, SnpMaRoleV1::Destination);
        TenantAuthorizationContextV1::new(tenant, source, destination).unwrap()
    }

    fn role_proof(
        context: &TenantAuthorizationContextV1,
        verifier: &TestVerifier,
        role: SnpMaRoleV1,
    ) -> VerifiedTenantAuthorizationRoleV1 {
        let expected = context.report_data_context(role).unwrap();
        context
            .verify_role_evidence(role, verifier, &ma_report(&expected), &collateral(), 0)
            .unwrap()
    }

    fn hex_digest(hex: &str) -> [u8; 48] {
        assert_eq!(hex.len(), 96);
        let mut bytes = [0; 48];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        bytes
    }

    #[test]
    fn independent_python_vectors_freeze_raw_composite_and_authorization_shapes() {
        let verifier = TestVerifier::default();
        let context = authorization_context(&verifier);
        let raw_digest = hex_digest("788d3a6487ccce4313d85ca043911b1faf6f43656568398e2078969781157c12b47c361b5e79b24667e1bc90f61f19bd");
        assert_eq!(
            canonical_tenant_evidence_digest_v1(&tenant_bytes(), None),
            raw_digest
        );
        assert_eq!(context.tenant.canonical_evidence_digest(), &raw_digest);
        assert_ne!(context.tenant.report_digest(), &raw_digest);
        assert_eq!(
            canonical_tenant_evidence_digest_v1(&tenant_bytes(), Some((&[0x99; 220], &[0xaa; 96]))),
            hex_digest("97470f8e891fdc2aa0b0ae66a667a4f9d1007c631a2712a4ce509bd72370ef19043d4b03c7827957072bc9f2bd7b0e46")
        );
        let encoded = context.encode_exact().unwrap();
        assert_eq!(encoded.len(), 421);
        assert_eq!(&encoded[..21], b"SNP-LM-TENANT-AUTH-v1");
        assert_eq!(&encoded[21..23], &1u16.to_le_bytes());
        assert_eq!(&encoded[23..31], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&encoded[35..37], &[0, 1]);
        assert_eq!(context.digest().unwrap(), hex_digest("45e7c0798149a61921f87a87d868236aad002a66557132577ca88c1b4dbff5d0afdea7627cd056a3058609e173d40b97"));
    }

    #[test]
    fn every_report_supplement_and_signature_byte_participates_in_the_digest() {
        let report = tenant_bytes();
        let supplement = [0x99; 220];
        let signature = [0xaa; 96];
        let raw = canonical_tenant_evidence_digest_v1(&report, None);
        let composite =
            canonical_tenant_evidence_digest_v1(&report, Some((&supplement, &signature)));
        assert_ne!(raw, composite);
        for index in 0..1184 {
            let mut changed = report;
            changed[index] ^= 1;
            assert_ne!(canonical_tenant_evidence_digest_v1(&changed, None), raw);
            assert_ne!(
                canonical_tenant_evidence_digest_v1(&changed, Some((&supplement, &signature))),
                composite
            );
        }
        for index in 0..220 {
            let mut changed = supplement;
            changed[index] ^= 1;
            assert_ne!(
                canonical_tenant_evidence_digest_v1(&report, Some((&changed, &signature))),
                composite
            );
        }
        for index in 0..96 {
            let mut changed = signature;
            changed[index] ^= 1;
            assert_ne!(
                canonical_tenant_evidence_digest_v1(&report, Some((&supplement, &changed))),
                composite
            );
        }
    }

    #[test]
    fn tenant_ma_binding_uses_authenticated_source_ma_identity() {
        let verifier = TestVerifier::default();
        let mut report = tenant_bytes();
        report[0x160] ^= 1;
        let wrong_binding = tenant(&verifier, MigrationRole::Source, &report);
        assert_eq!(
            TenantAuthorizationContextV1::new(
                wrong_binding,
                contribution(&verifier, SnpMaRoleV1::Source),
                contribution(&verifier, SnpMaRoleV1::Destination)
            )
            .unwrap_err(),
            TenantAuthorizationErrorV1::SourceMaBindingMismatch
        );
        let context = contribution_context(SnpMaRoleV1::Source);
        verifier.fail.set(true);
        assert_eq!(
            VerifiedContributionMaV1::verify(
                &context,
                &verifier,
                &ma_report(&context),
                &collateral(),
                0,
                SnpVerifierTrust::PinnedMilanArkTest
            )
            .unwrap_err(),
            TenantAuthorizationErrorV1::Verification(
                SnpVerificationError::CryptographicVerification
            )
        );
    }

    #[test]
    fn swapped_roles_or_disagreeing_request_tenant_session_version_or_trust_fail() {
        let verifier = TestVerifier::default();
        let baseline = authorization_context(&verifier);
        for field in 0..7 {
            let source = baseline.source.clone();
            let mut destination = baseline.destination.clone();
            match field {
                0 => destination.context.role = SnpMaRoleV1::Source,
                1 => destination.context.request_id ^= 1,
                2 => destination.context.tenant_binding_id[0] ^= 1,
                3 => destination.context.th1[0] ^= 1,
                4 => destination.context.negotiated_migration_version += 1,
                5 => destination.trust = SnpVerifierTrust::AzureProduction,
                _ => destination.context.role = SnpMaRoleV1::Incoming,
            }
            assert_eq!(
                TenantAuthorizationContextV1::new(baseline.tenant.clone(), source, destination)
                    .unwrap_err(),
                TenantAuthorizationErrorV1::ContextMismatch
            );
        }
        assert_eq!(
            TenantAuthorizationContextV1::new(
                baseline.tenant.clone(),
                baseline.destination,
                baseline.source
            )
            .unwrap_err(),
            TenantAuthorizationErrorV1::ContextMismatch
        );
    }

    #[test]
    fn each_policy_and_already_attested_commitment_changes_authorization_binding() {
        let context = authorization_context(&TestVerifier::default());
        let original = context.digest().unwrap();
        for field in 0..4 {
            let mut changed = context.clone();
            match field {
                0 => changed.source.context.ma_policy_identity_digest[47] ^= 1,
                1 => changed.destination.context.ma_policy_identity_digest[47] ^= 1,
                2 => changed.source.context.purpose_binding_digest[47] ^= 1,
                _ => changed.destination.context.purpose_binding_digest[47] ^= 1,
            }
            assert_ne!(changed.digest().unwrap(), original);
            assert_ne!(
                changed.replay_binding().unwrap(),
                context.replay_binding().unwrap()
            );
        }
    }

    #[test]
    fn both_local_roles_reconstruct_the_same_common_context_but_pin_distinct_local_operations() {
        let verifier = TestVerifier::default();
        let source_local = authorization_context(&verifier);
        let destination_local = TenantAuthorizationContextV1::new(
            tenant(&verifier, MigrationRole::Destination, &tenant_bytes()),
            source_local.source.clone(),
            source_local.destination.clone(),
        )
        .unwrap();
        assert_eq!(
            source_local.encode_exact().unwrap(),
            destination_local.encode_exact().unwrap()
        );
        assert_ne!(
            source_local.replay_binding().unwrap(),
            destination_local.replay_binding().unwrap()
        );
    }

    #[test]
    fn reciprocal_purpose_two_evidence_is_required_before_creating_an_authorization_capability() {
        let verifier = TestVerifier::default();
        let context = authorization_context(&verifier);
        assert_eq!(verifier.calls.borrow().len(), 3);
        assert_eq!(
            verifier.calls.borrow()[0],
            SnpReportRequestKind::HostRequestedTenant
        );
        let source = role_proof(&context, &verifier, SnpMaRoleV1::Source);
        let destination = role_proof(&context, &verifier, SnpMaRoleV1::Destination);
        let proof = context.accept_both_roles(source, destination).unwrap();
        assert_eq!(verifier.calls.borrow().len(), 5);
        assert_eq!(
            proof.binding().as_stored().tenant_evidence_digest,
            *context.tenant.canonical_evidence_digest()
        );
        let mut journal = TenantReplayJournalV1::new(UnavailableTenantReplayStoreV1, 2).unwrap();
        assert_eq!(
            journal.authorize(&proof, &mut UnavailableTenantFirmwareStateV1),
            Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
        );
    }

    #[test]
    fn duplicate_swapped_or_another_contexts_role_proofs_are_rejected() {
        let verifier = TestVerifier::default();
        let context = authorization_context(&verifier);
        assert_eq!(
            context
                .accept_both_roles(
                    role_proof(&context, &verifier, SnpMaRoleV1::Destination),
                    role_proof(&context, &verifier, SnpMaRoleV1::Source)
                )
                .unwrap_err(),
            TenantAuthorizationErrorV1::MissingOrWrongRoleProof
        );
        assert_eq!(
            context
                .accept_both_roles(
                    role_proof(&context, &verifier, SnpMaRoleV1::Source),
                    role_proof(&context, &verifier, SnpMaRoleV1::Source)
                )
                .unwrap_err(),
            TenantAuthorizationErrorV1::MissingOrWrongRoleProof
        );
        let mut other = context.clone();
        other.destination.context.ma_policy_identity_digest[0] ^= 1;
        assert_eq!(
            context
                .accept_both_roles(
                    role_proof(&context, &verifier, SnpMaRoleV1::Source),
                    role_proof(&other, &verifier, SnpMaRoleV1::Destination)
                )
                .unwrap_err(),
            TenantAuthorizationErrorV1::MissingOrWrongRoleProof
        );
    }

    #[test]
    fn stale_wrong_purpose_nonzero_padding_or_changed_ma_identity_evidence_fails() {
        let verifier = TestVerifier::default();
        let context = authorization_context(&verifier);
        let role = SnpMaRoleV1::Source;
        let expected = context.report_data_context(role).unwrap();
        let mut wrong_identity = *ma_report(&expected).report();
        wrong_identity[0x140] ^= 1;
        assert_eq!(
            context
                .verify_role_evidence(
                    role,
                    &verifier,
                    &MaEvidence::new(wrong_identity, MaEvidenceBinding::RequestedReportData),
                    &collateral(),
                    0
                )
                .unwrap_err(),
            TenantAuthorizationErrorV1::MaIdentityMismatch
        );
        let mut wrong_padding = *ma_report(&expected).report();
        wrong_padding[0x8f] = 1;
        for evidence in [
            ma_report(&contribution_context(role)),
            MaEvidence::new(wrong_padding, MaEvidenceBinding::RequestedReportData),
            MaEvidence::new(
                *ma_report(&expected).report(),
                MaEvidenceBinding::CapturedFixture,
            ),
        ] {
            assert!(matches!(
                context.verify_role_evidence(role, &verifier, &evidence, &collateral(), 0),
                Err(TenantAuthorizationErrorV1::Verification(_))
            ));
        }
        assert_eq!(
            context
                .report_data_context(SnpMaRoleV1::Incoming)
                .unwrap_err(),
            TenantAuthorizationErrorV1::ContextMismatch
        );
        verifier.fail.set(true);
        assert_eq!(
            context
                .verify_role_evidence(role, &verifier, &ma_report(&expected), &collateral(), 0)
                .unwrap_err(),
            TenantAuthorizationErrorV1::Verification(
                SnpVerificationError::CryptographicVerification
            )
        );
    }

    #[test]
    fn ma_verifier_metadata_must_match_local_trust_and_live_binding_selection() {
        let verifier = TestVerifier::default();
        let context = contribution_context(SnpMaRoleV1::Source);
        verifier.trust.set(Some(SnpVerifierTrust::AzureProduction));
        assert_eq!(
            VerifiedContributionMaV1::verify(
                &context,
                &verifier,
                &ma_report(&context),
                &collateral(),
                0,
                SnpVerifierTrust::PinnedMilanArkTest
            )
            .unwrap_err(),
            TenantAuthorizationErrorV1::Verification(SnpVerificationError::UnsupportedTrust)
        );
        verifier.trust.set(None);
        verifier
            .binding
            .set(Some(MaEvidenceBinding::CapturedFixture));
        assert_eq!(
            VerifiedContributionMaV1::verify(
                &context,
                &verifier,
                &ma_report(&context),
                &collateral(),
                0,
                SnpVerifierTrust::PinnedMilanArkTest
            )
            .unwrap_err(),
            TenantAuthorizationErrorV1::Verification(SnpVerificationError::InvalidEvidence)
        );
    }

    mod p07 {
        use super::*;
        use crate::snp::{
            contribution_exchange::{
                ContributionCommitmentErrorV1, ContributionCommitmentVerifierV1,
                ContributionDirectionV1, ContributionExchangeErrorV1, ContributionExchangeStateV1,
                ContributionExchangeV1, UnavailableContributionCommitmentVerifierV1,
            },
            key_contribution::SnpKeyContributionV1,
        };
        use zeroize::Zeroizing;

        // A state-machine oracle only; deliberately not a commitment algorithm.
        #[derive(Default)]
        struct TestCommitments(Cell<usize>);

        impl ContributionCommitmentVerifierV1 for TestCommitments {
            fn verify(
                &self,
                expected: &ReportDataContextV1,
                contribution: &[u8; 32],
            ) -> Result<(), ContributionCommitmentErrorV1> {
                self.0.set(self.0.get() + 1);
                let expected_secret = match expected.role {
                    SnpMaRoleV1::Source => [0xa5; 32],
                    SnpMaRoleV1::Destination => [0x5a; 32],
                    _ => panic!("non-migration role reached commitment verifier"),
                };
                if contribution == &expected_secret {
                    Ok(())
                } else {
                    Err(ContributionCommitmentErrorV1::Mismatch)
                }
            }
        }

        fn setup() -> (TenantAuthorizationContextV1, VerifiedTenantAuthorizationV1) {
            let verifier = TestVerifier::default();
            let context = authorization_context(&verifier);
            let proof = context
                .accept_both_roles(
                    role_proof(&context, &verifier, SnpMaRoleV1::Source),
                    role_proof(&context, &verifier, SnpMaRoleV1::Destination),
                )
                .unwrap();
            (context, proof)
        }

        fn encoded(
            context: &TenantAuthorizationContextV1,
            direction: ContributionDirectionV1,
        ) -> Zeroizing<[u8; 272]> {
            let (role, secret) = match direction {
                ContributionDirectionV1::SourceRequest => (SnpMaRoleV1::Source, [0xa5; 32]),
                ContributionDirectionV1::DestinationResponse => {
                    (SnpMaRoleV1::Destination, [0x5a; 32])
                }
            };
            SnpKeyContributionV1::new(
                context.contribution_context(role).unwrap().clone(),
                Zeroizing::new(secret),
            )
            .unwrap()
            .encode_exact()
            .unwrap()
        }

        fn accept(
            exchange: &mut ContributionExchangeV1,
            context: &TenantAuthorizationContextV1,
            direction: ContributionDirectionV1,
            verifier: &dyn ContributionCommitmentVerifierV1,
        ) -> Result<(), ContributionExchangeErrorV1> {
            let mut payload = encoded(context, direction);
            let result = exchange.accept_encoded(direction, payload.as_mut(), verifier);
            assert!(payload.iter().all(|byte| *byte == 0));
            result
        }

        #[test]
        fn complete_transcript_exposes_only_one_ordered_consumption() {
            let (context, proof) = setup();
            let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
            let verifier = TestCommitments::default();
            assert_eq!(
                exchange.state(),
                ContributionExchangeStateV1::AwaitingSource
            );
            accept(
                &mut exchange,
                &context,
                ContributionDirectionV1::SourceRequest,
                &verifier,
            )
            .unwrap();
            assert_eq!(
                exchange.state(),
                ContributionExchangeStateV1::AwaitingDestination
            );
            accept(
                &mut exchange,
                &context,
                ContributionDirectionV1::DestinationResponse,
                &verifier,
            )
            .unwrap();
            assert_eq!(exchange.state(), ContributionExchangeStateV1::Complete);
            assert_eq!(verifier.0.get(), 2);
            let pair = exchange.finish().unwrap();
            assert_eq!(
                pair.authorization_context_digest(),
                &context.digest().unwrap()
            );
            assert_eq!(
                format!("{pair:?}"),
                "VerifiedContributionPairV1 { contributions: \"<redacted>\" }"
            );
            let result: Result<(), ()> = pair.consume(|source, destination| {
                assert_eq!(source, &[0xa5; 32]);
                assert_eq!(destination, &[0x5a; 32]);
                Err(())
            });
            assert_eq!(result, Err(()));
        }

        #[test]
        fn independent_source_and_destination_wire_vectors_match() {
            let (context, _) = setup();
            for (direction, expected) in [
                (
                    ContributionDirectionV1::SourceRequest,
                    "413df1b1c1ddde9c0314384e72031612729103fd2ee71c67e8e4da0a6d7501b824afa0d0d2ba2e0a06980068a824caf4",
                ),
                (
                    ContributionDirectionV1::DestinationResponse,
                    "a773d55abbbf6d62b4b3b929128f1422124172c59278d6be2bef7b78206566f49565e0b4696da30b0f6f59e28fd07ff7",
                ),
            ] {
                let bytes = encoded(&context, direction);
                assert_eq!(bytes.len(), 272);
                assert_eq!(sha384(bytes.as_ref()), hex_digest(expected));
            }
        }

        #[test]
        fn other_authorization_context_proof_cannot_start_exchange() {
            let (mut context, proof) = setup();
            context.destination.context.ma_policy_identity_digest[0] ^= 1;
            assert_eq!(
                ContributionExchangeV1::new(&context, &proof).unwrap_err(),
                ContributionExchangeErrorV1::AuthorizationMismatch
            );
        }

        #[test]
        fn same_digest_but_different_local_operation_cannot_reuse_proof() {
            let (context, proof) = setup();
            let other = TenantAuthorizationContextV1::new(
                tenant(
                    &TestVerifier::default(),
                    MigrationRole::Destination,
                    &tenant_bytes(),
                ),
                context.source.clone(),
                context.destination.clone(),
            )
            .unwrap();
            assert_eq!(context.digest().unwrap(), other.digest().unwrap());
            assert_eq!(
                ContributionExchangeV1::new(&other, &proof).unwrap_err(),
                ContributionExchangeErrorV1::AuthorizationMismatch
            );
        }

        #[test]
        fn full_context_mismatches_fail_before_commitment_verification() {
            let (context, proof) = setup();
            for offset in [50, 51, 52, 60, 62, 64, 96, 144, 192] {
                let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
                let verifier = TestCommitments::default();
                let mut payload = encoded(&context, ContributionDirectionV1::SourceRequest);
                payload[offset] ^= 1;
                assert!(exchange
                    .accept_encoded(
                        ContributionDirectionV1::SourceRequest,
                        payload.as_mut(),
                        &verifier
                    )
                    .is_err());
                assert!(payload.iter().all(|byte| *byte == 0));
                assert_eq!(exchange.state(), ContributionExchangeStateV1::Aborted);
                assert_eq!(verifier.0.get(), 0);
                assert!(exchange.finish().is_err());
            }
        }

        #[test]
        fn matching_reference_does_not_accept_a_changed_secret() {
            let (context, proof) = setup();
            for direction in [
                ContributionDirectionV1::SourceRequest,
                ContributionDirectionV1::DestinationResponse,
            ] {
                let verifier = TestCommitments::default();
                let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
                if direction == ContributionDirectionV1::DestinationResponse {
                    accept(
                        &mut exchange,
                        &context,
                        ContributionDirectionV1::SourceRequest,
                        &verifier,
                    )
                    .unwrap();
                }
                let mut payload = encoded(&context, direction);
                payload[240] ^= 1;
                assert_eq!(
                    exchange.accept_encoded(direction, payload.as_mut(), &verifier),
                    Err(ContributionExchangeErrorV1::Commitment(
                        ContributionCommitmentErrorV1::Mismatch
                    ))
                );
                assert!(payload.iter().all(|byte| *byte == 0));
                assert_eq!(exchange.state(), ContributionExchangeStateV1::Aborted);
                assert!(exchange.finish().is_err());
            }
        }

        #[test]
        fn unavailable_commitment_construction_fails_closed() {
            let (context, proof) = setup();
            let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
            let error = accept(
                &mut exchange,
                &context,
                ContributionDirectionV1::SourceRequest,
                &UnavailableContributionCommitmentVerifierV1,
            )
            .unwrap_err();
            assert_eq!(
                error,
                ContributionExchangeErrorV1::Commitment(
                    ContributionCommitmentErrorV1::ConstructionUnavailable
                )
            );
            assert_eq!(
                error.protocol_failure(),
                crate::snp::authorization_result::SnpAuthorizationFailureV1::InternalError
            );
            assert!(exchange.finish().is_err());
        }

        #[test]
        fn destination_first_and_wrong_direction_are_terminal_errors() {
            let (context, proof) = setup();
            let verifier = TestCommitments::default();
            for direction in [
                ContributionDirectionV1::SourceRequest,
                ContributionDirectionV1::DestinationResponse,
            ] {
                let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
                let mut payload = encoded(&context, ContributionDirectionV1::DestinationResponse);
                assert!(exchange
                    .accept_encoded(direction, payload.as_mut(), &verifier)
                    .is_err());
                assert!(payload.iter().all(|byte| *byte == 0));
                assert_eq!(exchange.state(), ContributionExchangeStateV1::Aborted);
            }
            assert_eq!(verifier.0.get(), 0);
        }

        #[test]
        fn duplicate_at_either_stage_aborts_and_cannot_resume() {
            let (context, proof) = setup();
            for duplicate in [
                ContributionDirectionV1::SourceRequest,
                ContributionDirectionV1::DestinationResponse,
            ] {
                let verifier = TestCommitments::default();
                let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
                accept(
                    &mut exchange,
                    &context,
                    ContributionDirectionV1::SourceRequest,
                    &verifier,
                )
                .unwrap();
                if duplicate == ContributionDirectionV1::DestinationResponse {
                    accept(&mut exchange, &context, duplicate, &verifier).unwrap();
                }
                let calls = verifier.0.get();
                assert_eq!(
                    accept(&mut exchange, &context, duplicate, &verifier),
                    Err(ContributionExchangeErrorV1::ProtocolStateViolation)
                );
                assert!(accept(
                    &mut exchange,
                    &context,
                    ContributionDirectionV1::DestinationResponse,
                    &verifier
                )
                .is_err());
                assert_eq!(verifier.0.get(), calls);
                assert_eq!(exchange.state(), ContributionExchangeStateV1::Aborted);
                assert!(exchange.finish().is_err());
            }
        }

        #[test]
        fn every_truncation_and_trailing_byte_is_erased_and_rejected() {
            let (context, proof) = setup();
            let verifier = TestCommitments::default();
            let template = encoded(&context, ContributionDirectionV1::SourceRequest);
            for length in (0..272).chain([273]) {
                let mut payload = Zeroizing::new(template.to_vec());
                payload.resize(length, 0xa5);
                let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
                assert!(exchange
                    .accept_encoded(
                        ContributionDirectionV1::SourceRequest,
                        payload.as_mut(),
                        &verifier
                    )
                    .is_err());
                assert!(payload.iter().all(|byte| *byte == 0));
                assert_eq!(exchange.state(), ContributionExchangeStateV1::Aborted);
            }
            assert_eq!(verifier.0.get(), 0);
        }

        #[test]
        fn malformed_second_message_cancels_the_whole_transcript() {
            let (context, proof) = setup();
            let verifier = TestCommitments::default();
            let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
            accept(
                &mut exchange,
                &context,
                ContributionDirectionV1::SourceRequest,
                &verifier,
            )
            .unwrap();
            let mut payload = encoded(&context, ContributionDirectionV1::DestinationResponse);
            payload[0] ^= 1;
            assert!(exchange
                .accept_encoded(
                    ContributionDirectionV1::DestinationResponse,
                    payload.as_mut(),
                    &verifier
                )
                .is_err());
            assert!(payload.iter().all(|byte| *byte == 0));
            assert_eq!(verifier.0.get(), 1);
            assert!(exchange.finish().is_err());
        }

        #[test]
        fn cancellation_and_incomplete_transcripts_never_yield_a_pair() {
            let (context, proof) = setup();
            let verifier = TestCommitments::default();
            for count in 0..=2 {
                let mut exchange = ContributionExchangeV1::new(&context, &proof).unwrap();
                if count >= 1 {
                    accept(
                        &mut exchange,
                        &context,
                        ContributionDirectionV1::SourceRequest,
                        &verifier,
                    )
                    .unwrap();
                }
                if count == 2 {
                    accept(
                        &mut exchange,
                        &context,
                        ContributionDirectionV1::DestinationResponse,
                        &verifier,
                    )
                    .unwrap();
                    exchange.abort();
                    exchange.abort();
                    assert_eq!(exchange.state(), ContributionExchangeStateV1::Aborted);
                }
                assert_eq!(
                    exchange.finish().unwrap_err(),
                    ContributionExchangeErrorV1::Incomplete
                );
            }
        }

        #[test]
        fn local_handoff_roles_are_not_contribution_contexts() {
            let (context, _) = setup();
            for role in [SnpMaRoleV1::Outgoing, SnpMaRoleV1::Incoming] {
                assert_eq!(
                    context.contribution_context(role).unwrap_err(),
                    TenantAuthorizationErrorV1::ContextMismatch
                );
            }
        }
    }
}
