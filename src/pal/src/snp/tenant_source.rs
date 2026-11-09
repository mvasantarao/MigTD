// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! T4.9 host-push boundary. A receipt authenticates evidence, not migration.

use super::{
    collateral_set::{SnpCertificateRoleV1, SnpCollateralSetV1},
    direct_authorization::canonical_tenant_evidence_digest_v1,
    evidence_header::{SnpEvidenceProfileV1, SnpTcbProfileV1},
    limits::MAX_SNP_CERTIFICATE_SIZE,
    purpose_binding::sha384,
};
use crate::{
    snp_report::*,
    tenant_identity::{
        PrepareMigrationRequestV1, TenantReportDeliveryV1, VerifiedTenantIdentity,
        VerifiedTenantReportDeliveryV1,
    },
    tenant_replay::{
        CurrentTenantFirmwareStateV1, DurableTenantReplayStoreV1, ReplayTerminalResultV1,
        TenantReplayAdmissionV1, TenantReplayAuthorizationV1, TenantReplayErrorV1,
        TenantReplayJournalV1, TenantReplayStateV1, VerifiedTenantAuthorizationV1,
        VerifiedTenantReplayBindingV1,
    },
    types::{SnpOperationContext, SnpVerifierTrust},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantEvidenceBinding {
    HostRequestedZeroReportData,
    GuestProvidedReportData {
        expected_vmpl: u32,
        expected_report_data: [u8; 64],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantEvidenceError {
    ProviderUnavailable,
    UnsupportedBinding,
    InvalidState,
    InvalidReport(SnpReportVerificationError),
    IdentityMismatch,
    ReplayDetected(TenantReplayErrorV1),
    ProductionReplayStateUnavailable,
    Replay(TenantReplayErrorV1),
}

impl From<SnpReportVerificationError> for TenantEvidenceError {
    fn from(error: SnpReportVerificationError) -> Self {
        match error {
            SnpReportVerificationError::ProviderUnavailable => Self::ProviderUnavailable,
            _ => Self::InvalidReport(error),
        }
    }
}

impl From<TenantReplayErrorV1> for TenantEvidenceError {
    fn from(error: TenantReplayErrorV1) -> Self {
        match error {
            TenantReplayErrorV1::ProductionReplayStateUnavailable => {
                Self::ProductionReplayStateUnavailable
            }
            TenantReplayErrorV1::ConflictingReuse
            | TenantReplayErrorV1::TerminalOperation
            | TenantReplayErrorV1::RollbackDetected => Self::ReplayDetected(error),
            _ => Self::Replay(error),
        }
    }
}

/// Owned BASE-pushed bytes, not a verification result or a new wire envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantEvidencePackage {
    evidence: SnpEvidenceInput,
    collateral: SnpCollateralSetV1,
    collateral_digest: [u8; 48],
}

impl TenantEvidencePackage {
    pub fn new(
        evidence: SnpEvidenceInput,
        collateral: SnpCollateralSetV1,
    ) -> Result<Self, TenantEvidenceError> {
        let encoded = collateral
            .encode_exact()
            .map_err(|_| SnpReportVerificationError::MalformedCollateral)?;
        let expected_profile = match &evidence {
            SnpEvidenceInput::EmulatorV1(_) => SnpEvidenceProfileV1::Fixture,
            SnpEvidenceInput::RawAmdReport { .. } => SnpEvidenceProfileV1::Production,
        };
        if collateral.evidence_profile != expected_profile
            || collateral.tcb_profile != SnpTcbProfileV1::Venice
        {
            return Err(SnpReportVerificationError::CollateralTrustDomainMismatch.into());
        }
        Ok(Self {
            evidence,
            collateral,
            collateral_digest: sha384(&encoded),
        })
    }

    pub const fn evidence(&self) -> &SnpEvidenceInput {
        &self.evidence
    }

    pub const fn collateral(&self) -> &SnpCollateralSetV1 {
        &self.collateral
    }
}

/// Binding expectations and expected identity come from local operation state,
/// not from the untrusted report. The package must already be pushed by BASE.
pub struct TenantEvidenceRequest<'a> {
    pub prepare: &'a PrepareMigrationRequestV1,
    pub package: &'a TenantEvidencePackage,
    pub binding: TenantEvidenceBinding,
    pub expected_identity: Option<&'a VerifiedTenantIdentity>,
}

/// No public constructor: a decoded package or hash cannot mint this receipt.
///
/// ```compile_fail
/// use pal::snp::tenant_source::TenantEvidence;
/// let receipt = TenantEvidence {};
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantEvidence {
    delivery: VerifiedTenantReportDeliveryV1,
    claims: AuthenticatedSnpClaims,
    package: TenantEvidencePackage,
    binding: TenantEvidenceBinding,
}

impl TenantEvidence {
    pub const fn identity(&self) -> &VerifiedTenantIdentity {
        self.delivery.identity()
    }

    pub const fn claims(&self) -> &AuthenticatedSnpClaims {
        &self.claims
    }

    pub const fn binding(&self) -> TenantEvidenceBinding {
        self.binding
    }

    pub const fn collateral_digest(&self) -> &[u8; 48] {
        &self.package.collateral_digest
    }

    pub const fn package(&self) -> &TenantEvidencePackage {
        &self.package
    }

    /// Only the selected host-zero delivery may enter V2 session/authorization.
    pub fn verified_delivery(
        &self,
    ) -> Result<&VerifiedTenantReportDeliveryV1, TenantEvidenceError> {
        if self.binding != TenantEvidenceBinding::HostRequestedZeroReportData {
            return Err(TenantEvidenceError::UnsupportedBinding);
        }
        Ok(&self.delivery)
    }
}

pub trait TenantEvidenceSource {
    fn evidence(
        &mut self,
        request: TenantEvidenceRequest<'_>,
    ) -> Result<&TenantEvidence, TenantEvidenceError>;
}

/// One operation-local owner, including its receipt, replay journal and current
/// firmware provider. No store, verifier, root, clock or firmware default exists.
pub struct HostPushedTenantEvidenceSource<'a, S, F> {
    operation: SnpOperationContext,
    verifier: &'a dyn SnpReportVerifier,
    collateral: SnpCollateralInput,
    receipt: Option<TenantEvidence>,
    journal: TenantReplayJournalV1<S>,
    firmware: F,
    terminal: bool,
}

impl<'a, S: DurableTenantReplayStoreV1, F: CurrentTenantFirmwareStateV1>
    HostPushedTenantEvidenceSource<'a, S, F>
{
    pub fn new(
        operation: SnpOperationContext,
        verifier: &'a dyn SnpReportVerifier,
        collateral: SnpCollateralInput,
        store: S,
        firmware: F,
        maximum_replay_records: usize,
    ) -> Result<Self, TenantEvidenceError> {
        for der in [
            &collateral.leaf_certificate_der,
            &collateral.intermediate_certificate_der,
            &collateral.root_certificate_der,
        ] {
            if der.is_empty() {
                return Err(SnpReportVerificationError::MissingCollateral.into());
            }
            if der.len() > MAX_SNP_CERTIFICATE_SIZE {
                return Err(SnpReportVerificationError::CollateralTooLarge.into());
            }
        }
        if collateral.verification_time_unix_seconds == 0 {
            return Err(SnpReportVerificationError::InvalidVerificationTime.into());
        }
        match (&collateral.expected_trust_domain, &collateral.revocation) {
            (SnpTrustDomain::Fixture, SnpRevocationInput::FixtureNotApplicable) => {}
            (SnpTrustDomain::ProductionAmd, SnpRevocationInput::AmdCrlsDer(crls))
                if !crls.is_empty() && crls.iter().all(|crl| !crl.is_empty()) => {}
            _ => return Err(SnpReportVerificationError::MissingRevocationCollateral.into()),
        }
        Ok(Self {
            operation,
            verifier,
            collateral,
            receipt: None,
            journal: TenantReplayJournalV1::new(store, maximum_replay_records)?,
            firmware,
            terminal: false,
        })
    }

    fn check_binding(
        &self,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<(), TenantEvidenceError> {
        let receipt = self
            .receipt
            .as_ref()
            .ok_or(TenantEvidenceError::InvalidState)?;
        let delivery = receipt.verified_delivery()?;
        let stored = binding.as_stored();
        if stored.operation != self.operation
            || stored.tenant_report_id != *delivery.identity().as_bytes()
            || stored.tenant_evidence_digest != *delivery.canonical_evidence_digest()
            || stored.source_ma_report_id != *delivery.report_id_ma()
            || stored.trust != delivery.trust()
        {
            return Err(TenantEvidenceError::IdentityMismatch);
        }
        Ok(())
    }

    /// Requires the existing sealed binding constructed after both session-MA
    /// proofs. Evidence delivery never calls reserve or invents this binding.
    pub fn reserve_after_ma_proofs(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<TenantReplayAdmissionV1, TenantEvidenceError> {
        self.check_binding(binding)?;
        Ok(self.journal.reserve(binding)?)
    }

    pub fn received_evidence(&self) -> Option<&TenantEvidence> {
        self.receipt.as_ref()
    }

    /// Authenticated diagnostic recovery, not proof reconstruction or admission.
    pub fn query_operation(
        &mut self,
        operation: &SnpOperationContext,
    ) -> Result<Option<TenantReplayStateV1>, TenantEvidenceError> {
        if operation != &self.operation {
            return Err(TenantEvidenceError::IdentityMismatch);
        }
        Ok(self.journal.query_operation(operation)?)
    }

    /// Performs P0.6 replay/current-firmware admission only. The runtime must
    /// independently complete policy approval before invoking this handoff.
    pub fn authorize_after_role_proofs(
        &mut self,
        authorization: &VerifiedTenantAuthorizationV1,
    ) -> Result<TenantReplayAuthorizationV1, TenantEvidenceError> {
        self.check_binding(authorization.binding())?;
        Ok(self.journal.authorize(authorization, &mut self.firmware)?)
    }

    pub fn finish(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
        result: ReplayTerminalResultV1,
    ) -> Result<(), TenantEvidenceError> {
        self.check_binding(binding)?;
        self.journal.finish(binding, result)?;
        self.terminal = true;
        Ok(())
    }

    pub fn query(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<Option<TenantReplayStateV1>, TenantEvidenceError> {
        self.check_binding(binding)?;
        Ok(self.journal.query(binding)?)
    }
}

fn chain_digest(collateral: &SnpCollateralInput) -> [u8; 48] {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA384);
    hash.update(b"SNP-CERT-CHAIN-v1");
    for der in [
        &collateral.leaf_certificate_der,
        &collateral.intermediate_certificate_der,
        &collateral.root_certificate_der,
    ] {
        hash.update(&(der.len() as u32).to_le_bytes());
        hash.update(der);
    }
    let mut digest = [0; 48];
    digest.copy_from_slice(hash.finish().as_ref());
    digest
}

fn validate_claims(
    claims: &AuthenticatedSnpClaims,
    evidence: &SnpEmulatorEvidenceV1,
    collateral: &SnpCollateralInput,
    binding: TenantEvidenceBinding,
) -> Result<(), SnpReportVerificationError> {
    let provenance = &claims.provenance;
    if provenance.evidence_profile != SnpEvidenceProfile::SnpEmulatorV1
        || provenance.trust_domain != SnpTrustDomain::Fixture
        || provenance.report_sha384 != sha384(&evidence.report)
        || provenance.supplement_sha384 != Some(sha384(&evidence.supplement))
    {
        return Err(SnpReportVerificationError::SupplementReportDigestMismatch);
    }
    if claims.report_version != 6 || evidence.report[..4] != 6u32.to_le_bytes() {
        return Err(SnpReportVerificationError::UnsupportedReportVersion);
    }
    let (vmpl, report_data) = match binding {
        TenantEvidenceBinding::HostRequestedZeroReportData => (u32::MAX, [0; 64]),
        TenantEvidenceBinding::GuestProvidedReportData {
            expected_vmpl,
            expected_report_data,
        } => (expected_vmpl, expected_report_data),
    };
    if claims.vmpl != vmpl || evidence.report[0x30..0x34] != vmpl.to_le_bytes() {
        return Err(SnpReportVerificationError::UnexpectedVmpl);
    }
    if claims.report_data != report_data || evidence.report[0x50..0x90] != report_data {
        return Err(SnpReportVerificationError::ReportDataMismatch);
    }
    if evidence.report[0x140..0x160] != claims.report_id
        || evidence.report[0x160..0x180] != claims.report_id_ma
    {
        return Err(SnpReportVerificationError::MalformedReport);
    }
    if [
        claims.current_tcb,
        claims.reported_tcb,
        claims.committed_tcb,
        claims.launch_tcb,
    ]
    .iter()
    .any(|tcb| !matches!(tcb, AuthenticatedTcb::Venice { .. }))
    {
        return Err(SnpReportVerificationError::InvalidTcbEncoding);
    }
    let supplement = &evidence.supplement;
    if supplement[..2] != 1u16.to_le_bytes()
        || supplement[2..4] != 1u16.to_le_bytes()
        || supplement[149..156] != [0; 7]
        || evidence.report[0x48] & 0x20 != 0
    {
        return Err(SnpReportVerificationError::InvalidSupplementReservedBits);
    }
    if supplement[4..52] != provenance.report_sha384 {
        return Err(SnpReportVerificationError::SupplementReportDigestMismatch);
    }
    for (claim, start, base) in [
        (&claims.current_etcb, 52, 0x220),
        (&claims.launch_etcb, 84, 0x240),
        (&claims.committed_etcb, 116, 0x260),
    ] {
        if claim.raw[14..] != [0; 18] {
            return Err(SnpReportVerificationError::InvalidEtcbEncoding);
        }
        if supplement[start..start + 32] != claim.raw
            || evidence.report[base..base + 32] != claim.raw
        {
            return Err(SnpReportVerificationError::SupplementEtcbMismatch);
        }
    }
    if supplement[148] > 1
        || claims.migration_data_valid != (supplement[148] == 1)
        || supplement[156..] != claims.migration_data
        || (!claims.migration_data_valid && claims.migration_data != [0; 64])
    {
        return Err(SnpReportVerificationError::InvalidSupplementMigrationData);
    }
    let status = &claims.collateral_status;
    if status.trust_domain != SnpTrustDomain::Fixture
        || status.leaf_certificate_sha384 != sha384(&collateral.leaf_certificate_der)
        || status.certificate_chain_sha384 != chain_digest(collateral)
        || status.verification_time_unix_seconds != collateral.verification_time_unix_seconds
        || status.revocation != SnpRevocationStatus::FixtureNotApplicable
        || claims.signing_key_kind != SnpSigningKeyKind::Vcek
    {
        return Err(SnpReportVerificationError::CollateralTrustDomainMismatch);
    }
    Ok(())
}

impl<S: DurableTenantReplayStoreV1, F: CurrentTenantFirmwareStateV1> TenantEvidenceSource
    for HostPushedTenantEvidenceSource<'_, S, F>
{
    fn evidence(
        &mut self,
        request: TenantEvidenceRequest<'_>,
    ) -> Result<&TenantEvidence, TenantEvidenceError> {
        if self.terminal {
            return Err(TenantEvidenceError::ReplayDetected(
                TenantReplayErrorV1::TerminalOperation,
            ));
        }
        if request.prepare.operation() != &self.operation {
            return Err(TenantEvidenceError::InvalidState);
        }
        if let TenantEvidenceBinding::GuestProvidedReportData { expected_vmpl, .. } =
            request.binding
        {
            if expected_vmpl > 3 || self.collateral.expected_trust_domain != SnpTrustDomain::Fixture
            {
                return Err(TenantEvidenceError::UnsupportedBinding);
            }
        }
        let package = request.package;
        let report = package.evidence.report();
        if report[..4] != 6u32.to_le_bytes() {
            return Err(SnpReportVerificationError::UnsupportedReportVersion.into());
        }
        match request.prepare.delivery() {
            TenantReportDeliveryV1::Inline(inline) if inline.as_bytes() == report => {}
            TenantReportDeliveryV1::Reference(reference)
                if reference.sha384() == &sha384(report) => {}
            _ => return Err(TenantEvidenceError::IdentityMismatch),
        }
        let evidence = match (&package.evidence, self.collateral.expected_trust_domain) {
            (SnpEvidenceInput::EmulatorV1(_), SnpTrustDomain::ProductionAmd) => {
                return Err(SnpReportVerificationError::FixtureEvidenceInProduction.into());
            }
            (SnpEvidenceInput::RawAmdReport { .. }, SnpTrustDomain::ProductionAmd) => {
                return Err(SnpReportVerificationError::ConflictingAbiLayout.into());
            }
            (SnpEvidenceInput::RawAmdReport { .. }, SnpTrustDomain::Fixture) => {
                return Err(SnpReportVerificationError::CollateralTrustDomainMismatch.into());
            }
            (SnpEvidenceInput::EmulatorV1(evidence), SnpTrustDomain::Fixture) => evidence,
        };
        if package.collateral.leaf_certificate.role != SnpCertificateRoleV1::Vcek
            || package.collateral.leaf_certificate.certificate_der
                != self.collateral.leaf_certificate_der
            || package.collateral.ask_certificate.certificate_der
                != self.collateral.intermediate_certificate_der
        {
            return Err(SnpReportVerificationError::CollateralTrustDomainMismatch.into());
        }
        if let Some(accepted) = &self.receipt {
            if accepted.package != *package || accepted.binding != request.binding {
                return Err(TenantEvidenceError::InvalidState);
            }
            if request
                .expected_identity
                .is_some_and(|id| id != accepted.identity())
            {
                return Err(TenantEvidenceError::IdentityMismatch);
            }
        } else {
            let verification = match request.binding {
                TenantEvidenceBinding::HostRequestedZeroReportData => {
                    SnpReportVerificationRequest::HostRequestedTenant {
                        evidence: &package.evidence,
                        collateral: &self.collateral,
                    }
                }
                TenantEvidenceBinding::GuestProvidedReportData {
                    expected_vmpl,
                    expected_report_data,
                } => SnpReportVerificationRequest::GuestRequestedTenant {
                    evidence: &package.evidence,
                    collateral: &self.collateral,
                    expected_vmpl,
                    expected_report_data,
                },
            };
            let claims = self.verifier.verify(verification)?;
            validate_claims(&claims, evidence, &self.collateral, request.binding)?;
            let identity = VerifiedTenantIdentity::from_verified_report_id(claims.report_id);
            if request.expected_identity.is_some_and(|id| id != &identity) {
                return Err(TenantEvidenceError::IdentityMismatch);
            }
            let delivery = VerifiedTenantReportDeliveryV1::from_verified_report(
                self.operation,
                identity,
                sha384(report),
                // Preserve P0.6's fixture tag; actual root selection/validation
                // belongs to the new verifier, not this legacy enum name.
                SnpVerifierTrust::PinnedMilanArkTest,
                claims.report_id_ma,
                canonical_tenant_evidence_digest_v1(
                    report,
                    Some((&evidence.supplement, &evidence.supplement_signature)),
                ),
            );
            self.receipt = Some(TenantEvidence {
                delivery,
                claims,
                package: package.clone(),
                binding: request.binding,
            });
        }
        self.receipt
            .as_ref()
            .ok_or(TenantEvidenceError::InvalidState)
    }
}

#[cfg(test)]
mod tests;
