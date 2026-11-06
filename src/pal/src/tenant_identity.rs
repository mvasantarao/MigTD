// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Shared P0.5 logical delivery contract, not host-control wire framing.
//! Report correlation is neither authorization nor a durable replay journal.

use crate::types::{
    ManagedGuestHandle, SnpOperationContext, SnpVerificationError, SnpVerifierTrust,
    SNP_ATTESTATION_REPORT_SIZE,
};

/// BASE owns the handle-to-GCTX mapping; this identity is only a routing hint.
///
/// ```compile_fail
/// use pal::tenant_identity::{ProvisionalTenantIdentity, VerifiedTenantIdentity};
/// use pal::types::ManagedGuestHandle;
/// fn authorize(_: &VerifiedTenantIdentity) {}
/// authorize(&ProvisionalTenantIdentity::new(ManagedGuestHandle::new(1)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalTenantIdentity(ManagedGuestHandle);

impl ProvisionalTenantIdentity {
    pub const fn new(handle: ManagedGuestHandle) -> Self {
        Self(handle)
    }

    pub const fn managed_guest(self) -> ManagedGuestHandle {
        self.0
    }
}

/// A report's authenticated REPORT_ID, not proof of migration authorization.
///
/// ```compile_fail
/// use pal::tenant_identity::VerifiedTenantIdentity;
/// let identity = VerifiedTenantIdentity([0u8; 32]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantIdentity([u8; 32]);

impl VerifiedTenantIdentity {
    #[cfg(any(feature = "snp-core", test))]
    pub(crate) fn from_verified_report_id(id: [u8; 32]) -> Self {
        Self(id)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantDeliveryErrorV1 {
    InvalidReportLength { actual: usize },
    MissingCachedReport,
    UnexpectedCachedReport,
    ReferenceDigestMismatch,
    RequestCorrelationMismatch,
    ConflictingDelivery,
    Verification(SnpVerificationError),
}

/// Still untrusted until signature verification and identity extraction succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPushedTenantReportV1(Box<[u8; SNP_ATTESTATION_REPORT_SIZE]>);

impl HostPushedTenantReportV1 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TenantDeliveryErrorV1> {
        let report: [u8; SNP_ATTESTATION_REPORT_SIZE] =
            bytes
                .try_into()
                .map_err(|_| TenantDeliveryErrorV1::InvalidReportLength {
                    actual: bytes.len(),
                })?;
        Ok(Self(Box::new(report)))
    }

    pub fn as_bytes(&self) -> &[u8; SNP_ATTESTATION_REPORT_SIZE] {
        &self.0
    }
}

/// SHA384 of the exact 1184 base-report bytes, not a trust anchor or freshness
/// proof. Only a BASE-pushed cache entry may satisfy this lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantReportReferenceV1([u8; 48]);

impl TenantReportReferenceV1 {
    pub const fn new(sha384: [u8; 48]) -> Self {
        Self(sha384)
    }

    pub const fn sha384(&self) -> &[u8; 48] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantReportDeliveryV1 {
    Inline(HostPushedTenantReportV1),
    Reference(TenantReportReferenceV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareMigrationRequestV1 {
    operation: SnpOperationContext,
    delivery: TenantReportDeliveryV1,
}

impl PrepareMigrationRequestV1 {
    pub const fn new(operation: SnpOperationContext, delivery: TenantReportDeliveryV1) -> Self {
        Self {
            operation,
            delivery,
        }
    }

    pub const fn operation(&self) -> &SnpOperationContext {
        &self.operation
    }

    pub const fn provisional_identity(&self) -> ProvisionalTenantIdentity {
        ProvisionalTenantIdentity::new(self.operation.managed_guest)
    }

    pub const fn delivery(&self) -> &TenantReportDeliveryV1 {
        &self.delivery
    }
}

/// Immutable result of verifying this exact request's base report. Supplement
/// claims, session freshness, tenant-to-MA binding and policy are separate gates.
///
/// ```compile_fail
/// use pal::tenant_identity::{VerifiedTenantIdentity, VerifiedTenantReportDeliveryV1};
/// use pal::types::{SnpOperationContext, SnpVerifierTrust};
/// fn forge(operation: SnpOperationContext, id: VerifiedTenantIdentity) {
///     VerifiedTenantReportDeliveryV1::from_verified_report(
///         operation, id, [0; 48], SnpVerifierTrust::AzureProduction,
///         [0; 32], [0; 48]);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantReportDeliveryV1 {
    operation: SnpOperationContext,
    identity: VerifiedTenantIdentity,
    report_digest: [u8; 48],
    trust: SnpVerifierTrust,
    report_id_ma: [u8; 32],
    canonical_evidence_digest: [u8; 48],
}

impl VerifiedTenantReportDeliveryV1 {
    #[cfg(any(feature = "snp-core", test))]
    pub(crate) fn from_verified_report(
        operation: SnpOperationContext,
        identity: VerifiedTenantIdentity,
        report_digest: [u8; 48],
        trust: SnpVerifierTrust,
        report_id_ma: [u8; 32],
        canonical_evidence_digest: [u8; 48],
    ) -> Self {
        Self {
            operation,
            identity,
            report_digest,
            trust,
            report_id_ma,
            canonical_evidence_digest,
        }
    }

    pub const fn operation(&self) -> &SnpOperationContext {
        &self.operation
    }

    pub const fn identity(&self) -> &VerifiedTenantIdentity {
        &self.identity
    }

    pub const fn report_digest(&self) -> &[u8; 48] {
        &self.report_digest
    }

    pub const fn report_id_ma(&self) -> &[u8; 32] {
        &self.report_id_ma
    }

    pub const fn canonical_evidence_digest(&self) -> &[u8; 48] {
        &self.canonical_evidence_digest
    }

    pub const fn trust(&self) -> SnpVerifierTrust {
        self.trust
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantDeliveryOutcomeV1 {
    FirstDelivery,
    IdempotentRetry,
}

/// One operation-local slot; callers must retain it across delivery retries.
/// P0.6 owns durable replay, rollback, terminal-state and restart protection.
#[derive(Debug)]
pub struct TenantReportCorrelationV1 {
    operation: SnpOperationContext,
    accepted: Option<VerifiedTenantReportDeliveryV1>,
}

impl TenantReportCorrelationV1 {
    pub const fn new(operation: SnpOperationContext) -> Self {
        Self {
            operation,
            accepted: None,
        }
    }

    pub fn verified_identity(&self) -> Option<&VerifiedTenantIdentity> {
        self.accepted.as_ref().map(|report| report.identity())
    }

    pub fn accept_verified(
        &mut self,
        report: VerifiedTenantReportDeliveryV1,
    ) -> Result<TenantDeliveryOutcomeV1, TenantDeliveryErrorV1> {
        if report.operation != self.operation {
            return Err(TenantDeliveryErrorV1::RequestCorrelationMismatch);
        }
        if let Some(accepted) = &self.accepted {
            if accepted != &report {
                return Err(TenantDeliveryErrorV1::ConflictingDelivery);
            }
            return Ok(TenantDeliveryOutcomeV1::IdempotentRetry);
        }
        self.accepted = Some(report);
        Ok(TenantDeliveryOutcomeV1::FirstDelivery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        HostRequestId, MigrationId, MigrationRole, PeerRoutingReference, PolicyIdentity,
        ProtocolVersion,
    };

    fn operation() -> SnpOperationContext {
        SnpOperationContext::new(
            HostRequestId::new(1),
            MigrationId::new(2),
            MigrationRole::Source,
            ManagedGuestHandle::new(3),
        )
    }

    fn receipt(operation: SnpOperationContext) -> VerifiedTenantReportDeliveryV1 {
        VerifiedTenantReportDeliveryV1::from_verified_report(
            operation,
            VerifiedTenantIdentity::from_verified_report_id([4; 32]),
            [5; 48],
            SnpVerifierTrust::PinnedMilanArkTest,
            [6; 32],
            [7; 48],
        )
    }

    #[test]
    fn raw_report_length_is_exact_including_no_trailing_bytes() {
        for length in [0, 1183, 1185, 1500] {
            assert_eq!(
                HostPushedTenantReportV1::from_bytes(&vec![0; length]),
                Err(TenantDeliveryErrorV1::InvalidReportLength { actual: length })
            );
        }
        assert_eq!(
            HostPushedTenantReportV1::from_bytes(&[7; 1184])
                .unwrap()
                .as_bytes(),
            &[7; 1184]
        );
    }

    #[test]
    fn provisional_identity_is_the_request_handle_not_an_asserted_report_id() {
        let request = PrepareMigrationRequestV1::new(
            operation(),
            TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new([8; 48])),
        );
        assert_eq!(
            request.provisional_identity().managed_guest(),
            operation().managed_guest
        );
        assert_eq!(request.operation(), &operation());
    }

    #[test]
    fn first_delivery_and_exact_retry_preserve_one_verified_identity() {
        let mut slot = TenantReportCorrelationV1::new(operation());
        assert_eq!(slot.verified_identity(), None);
        let report = receipt(operation());
        assert_eq!(
            slot.accept_verified(report.clone()),
            Ok(TenantDeliveryOutcomeV1::FirstDelivery)
        );
        assert_eq!(
            slot.accept_verified(report),
            Ok(TenantDeliveryOutcomeV1::IdempotentRetry)
        );
        assert_eq!(slot.verified_identity().unwrap().as_bytes(), &[4; 32]);
    }

    #[test]
    fn every_operation_field_is_correlated_before_first_delivery_and_on_retry() {
        let op = operation();
        let alternatives = [
            SnpOperationContext {
                request_id: HostRequestId::new(9),
                ..op
            },
            SnpOperationContext {
                migration_id: MigrationId::new(9),
                ..op
            },
            SnpOperationContext {
                role: MigrationRole::Destination,
                ..op
            },
            SnpOperationContext {
                managed_guest: ManagedGuestHandle::new(9),
                ..op
            },
            SnpOperationContext {
                peer: Some(PeerRoutingReference::new(9)),
                ..op
            },
            SnpOperationContext {
                protocol_version: Some(ProtocolVersion::new(1, 0)),
                ..op
            },
            SnpOperationContext {
                policy: Some(PolicyIdentity::new(9)),
                ..op
            },
        ];
        let mut slot = TenantReportCorrelationV1::new(op);
        for alternative in alternatives {
            assert_eq!(
                slot.accept_verified(receipt(alternative)),
                Err(TenantDeliveryErrorV1::RequestCorrelationMismatch)
            );
            assert_eq!(slot.verified_identity(), None);
        }
        slot.accept_verified(receipt(op)).unwrap();
        for alternative in alternatives {
            assert_eq!(
                slot.accept_verified(receipt(alternative)),
                Err(TenantDeliveryErrorV1::RequestCorrelationMismatch)
            );
        }
        assert_eq!(
            slot.accept_verified(receipt(op)),
            Ok(TenantDeliveryOutcomeV1::IdempotentRetry)
        );
    }

    #[test]
    fn changed_report_identity_digest_or_trust_cannot_replace_accepted_delivery() {
        let original = receipt(operation());
        let mut slot = TenantReportCorrelationV1::new(operation());
        slot.accept_verified(original.clone()).unwrap();
        let mut changed_id = original.clone();
        changed_id.identity = VerifiedTenantIdentity::from_verified_report_id([9; 32]);
        let mut changed_digest = original.clone();
        changed_digest.report_digest[47] ^= 1;
        let mut changed_trust = original.clone();
        changed_trust.trust = SnpVerifierTrust::AzureProduction;
        let mut changed_ma = original.clone();
        changed_ma.report_id_ma[31] ^= 1;
        let mut changed_complete_digest = original.clone();
        changed_complete_digest.canonical_evidence_digest[47] ^= 1;
        for changed in [
            changed_id,
            changed_digest,
            changed_trust,
            changed_ma,
            changed_complete_digest,
        ] {
            assert_eq!(
                slot.accept_verified(changed),
                Err(TenantDeliveryErrorV1::ConflictingDelivery)
            );
        }
        assert_eq!(
            slot.accept_verified(original),
            Ok(TenantDeliveryOutcomeV1::IdempotentRetry)
        );
    }
}
