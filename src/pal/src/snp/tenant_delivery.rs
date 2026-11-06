// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Current base-report verifier bridge for the shared P0.5 contract.

use super::purpose_binding::{sha384, VerifiedTenantReportIdV1};
use crate::{
    tenant_identity::{
        HostPushedTenantReportV1, PrepareMigrationRequestV1, TenantDeliveryErrorV1,
        TenantReportDeliveryV1, VerifiedTenantReportDeliveryV1,
    },
    traits::SnpEvidenceVerifier,
    types::{
        MaEvidence, MaEvidenceBinding, SnpEvidenceVerificationRequest, SnpReportRequestKind,
        SnpVerificationCollateral, SnpVerifierTrust,
    },
};

impl PrepareMigrationRequestV1 {
    /// `cached_report` must already have been pushed by BASE; no acquisition or
    /// resolver callback is invoked. Local verifier/trust selection is not a
    /// field controlled by the host request.
    pub fn verify_tenant_report(
        &self,
        verifier: &dyn SnpEvidenceVerifier,
        collateral: &SnpVerificationCollateral,
        trust: SnpVerifierTrust,
        cached_report: Option<&HostPushedTenantReportV1>,
    ) -> Result<VerifiedTenantReportDeliveryV1, TenantDeliveryErrorV1> {
        let report = match (self.delivery(), cached_report) {
            (TenantReportDeliveryV1::Inline(report), None) => report,
            (TenantReportDeliveryV1::Inline(_), Some(_)) => {
                return Err(TenantDeliveryErrorV1::UnexpectedCachedReport);
            }
            (TenantReportDeliveryV1::Reference(_), None) => {
                return Err(TenantDeliveryErrorV1::MissingCachedReport);
            }
            (TenantReportDeliveryV1::Reference(reference), Some(report)) => {
                if &sha384(report.as_bytes()) != reference.sha384() {
                    return Err(TenantDeliveryErrorV1::ReferenceDigestMismatch);
                }
                report
            }
        };
        // MaEvidence is only the existing verifier's fixed-report carrier here;
        // HostRequestedTenant selects tenant semantics, never MA acquisition.
        let evidence = MaEvidence::new(*report.as_bytes(), MaEvidenceBinding::RequestedReportData);
        let request = SnpEvidenceVerificationRequest {
            evidence: &evidence,
            collateral,
            expected_report_data: &[0; 48],
            report_request: SnpReportRequestKind::HostRequestedTenant,
            trust,
        };
        let identity = VerifiedTenantReportIdV1::verify(verifier, &request)
            .map_err(TenantDeliveryErrorV1::Verification)?;
        let mut report_id_ma = [0; 32];
        report_id_ma.copy_from_slice(&report.as_bytes()[0x160..0x180]);
        Ok(VerifiedTenantReportDeliveryV1::from_verified_report(
            *self.operation(),
            identity,
            sha384(report.as_bytes()),
            trust,
            report_id_ma,
            super::direct_authorization::canonical_tenant_evidence_digest_v1(
                report.as_bytes(),
                None,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tenant_identity::{
            TenantDeliveryOutcomeV1, TenantReportCorrelationV1, TenantReportReferenceV1,
        },
        types::{
            HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, SnpOperationContext,
            SnpVerificationError, TcbStatus, VerifiedSnpEvidence,
        },
    };
    use std::cell::Cell;

    struct TestVerifier {
        calls: Cell<usize>,
        error: Option<SnpVerificationError>,
        wrong_trust: bool,
        wrong_binding: bool,
    }

    impl TestVerifier {
        fn new(error: Option<SnpVerificationError>) -> Self {
            Self {
                calls: Cell::new(0),
                error,
                wrong_trust: false,
                wrong_binding: false,
            }
        }
    }

    impl SnpEvidenceVerifier for TestVerifier {
        fn verify_evidence(
            &self,
            request: &SnpEvidenceVerificationRequest<'_>,
        ) -> Result<VerifiedSnpEvidence, SnpVerificationError> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(
                request.report_request,
                SnpReportRequestKind::HostRequestedTenant
            );
            assert_eq!(request.expected_report_data, &[0; 48]);
            assert_eq!(
                request.evidence.binding(),
                MaEvidenceBinding::RequestedReportData
            );
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(VerifiedSnpEvidence {
                binding: if self.wrong_binding {
                    MaEvidenceBinding::CapturedFixture
                } else {
                    request.evidence.binding()
                },
                tcb_status: TcbStatus::UpToDate,
                platform_tcb: None,
                trust: if self.wrong_trust {
                    SnpVerifierTrust::AzureProduction
                } else {
                    request.trust
                },
            })
        }
    }

    fn operation() -> SnpOperationContext {
        SnpOperationContext::new(
            HostRequestId::new(1),
            MigrationId::new(2),
            MigrationRole::Source,
            ManagedGuestHandle::new(3),
        )
    }

    fn report() -> HostPushedTenantReportV1 {
        let mut bytes = [0; 1184];
        bytes[..4].copy_from_slice(&6u32.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[0x140..0x160].fill(0x42);
        HostPushedTenantReportV1::from_bytes(&bytes).unwrap()
    }

    fn verify(
        request: &PrepareMigrationRequestV1,
        verifier: &TestVerifier,
        cached_report: Option<&HostPushedTenantReportV1>,
    ) -> Result<VerifiedTenantReportDeliveryV1, TenantDeliveryErrorV1> {
        request.verify_tenant_report(
            verifier,
            &SnpVerificationCollateral::new(vec![], vec![]),
            SnpVerifierTrust::PinnedMilanArkTest,
            cached_report,
        )
    }

    #[test]
    fn inline_and_reference_delivery_authenticate_the_same_identity_and_exact_report() {
        let report = report();
        let inline = PrepareMigrationRequestV1::new(
            operation(),
            TenantReportDeliveryV1::Inline(report.clone()),
        );
        let reference = PrepareMigrationRequestV1::new(
            operation(),
            TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new(sha384(
                report.as_bytes(),
            ))),
        );
        let verifier = TestVerifier::new(None);
        let first = verify(&inline, &verifier, None).unwrap();
        let retry = verify(&reference, &verifier, Some(&report)).unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.identity().as_bytes(), &[0x42; 32]);
        assert_eq!(first.report_digest(), &sha384(report.as_bytes()));
        assert_eq!(first.operation(), &operation());
        assert_eq!(verifier.calls.get(), 2);
        let mut slot = TenantReportCorrelationV1::new(operation());
        assert_eq!(
            slot.accept_verified(first),
            Ok(TenantDeliveryOutcomeV1::FirstDelivery)
        );
        assert_eq!(
            slot.accept_verified(retry),
            Ok(TenantDeliveryOutcomeV1::IdempotentRetry)
        );
    }

    #[test]
    fn report_reference_matches_independent_python_sha384_vector() {
        let expected = [
            0x73, 0x2a, 0xaa, 0x1f, 0xfd, 0x34, 0x61, 0x3d, 0xfc, 0x2e, 0x2b, 0x9d, 0x10, 0x04,
            0xd5, 0xaa, 0xc7, 0x13, 0xad, 0xb8, 0xc8, 0x1d, 0x71, 0x88, 0xa9, 0xf6, 0x9e, 0x9c,
            0x5c, 0x2a, 0x70, 0x33, 0x85, 0x7d, 0x73, 0xca, 0x5b, 0x35, 0x4b, 0xc4, 0x36, 0x86,
            0x05, 0x90, 0x99, 0x1c, 0x1e, 0xb7,
        ];
        let cached = report();
        let request = PrepareMigrationRequestV1::new(
            operation(),
            TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new(expected)),
        );
        assert_eq!(
            verify(&request, &TestVerifier::new(None), Some(&cached))
                .unwrap()
                .report_digest(),
            &expected
        );
    }

    #[test]
    fn missing_wrong_or_extraneous_cache_input_fails_without_verifier_dispatch() {
        let report = report();
        let inline = PrepareMigrationRequestV1::new(
            operation(),
            TenantReportDeliveryV1::Inline(report.clone()),
        );
        let reference = PrepareMigrationRequestV1::new(
            operation(),
            TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new([0; 48])),
        );
        let verifier = TestVerifier::new(None);
        assert_eq!(
            verify(&inline, &verifier, Some(&report)),
            Err(TenantDeliveryErrorV1::UnexpectedCachedReport)
        );
        assert_eq!(
            verify(&reference, &verifier, None),
            Err(TenantDeliveryErrorV1::MissingCachedReport)
        );
        assert_eq!(
            verify(&reference, &verifier, Some(&report)),
            Err(TenantDeliveryErrorV1::ReferenceDigestMismatch)
        );
        assert_eq!(verifier.calls.get(), 0);
    }

    #[test]
    fn cache_reference_is_not_a_substitute_for_cryptographic_verification() {
        let report = report();
        let reference = PrepareMigrationRequestV1::new(
            operation(),
            TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new(sha384(
                report.as_bytes(),
            ))),
        );
        let verifier = TestVerifier::new(Some(SnpVerificationError::CryptographicVerification));
        assert_eq!(
            verify(&reference, &verifier, Some(&report)),
            Err(TenantDeliveryErrorV1::Verification(
                SnpVerificationError::CryptographicVerification
            ))
        );
        assert_eq!(verifier.calls.get(), 1);
    }

    #[test]
    fn malformed_host_semantics_never_dispatch_to_the_cryptographic_verifier() {
        let original = *report().as_bytes();
        let mut wrong_version = original;
        wrong_version[..4].copy_from_slice(&5u32.to_le_bytes());
        let mut wrong_vmpl = original;
        wrong_vmpl[0x30..0x34].fill(0);
        let mut nonzero_data = original;
        nonzero_data[0x50] = 1;
        let mut nonzero_padding = original;
        nonzero_padding[0x8f] = 1;
        for bytes in [wrong_version, wrong_vmpl, nonzero_data, nonzero_padding] {
            let request = PrepareMigrationRequestV1::new(
                operation(),
                TenantReportDeliveryV1::Inline(
                    HostPushedTenantReportV1::from_bytes(&bytes).unwrap(),
                ),
            );
            let verifier = TestVerifier::new(None);
            assert_eq!(
                verify(&request, &verifier, None),
                Err(TenantDeliveryErrorV1::Verification(
                    SnpVerificationError::InvalidEvidence
                ))
            );
            assert_eq!(verifier.calls.get(), 0);
        }
    }

    #[test]
    fn verifier_failures_propagate_without_an_identity_or_correlated_delivery() {
        let request =
            PrepareMigrationRequestV1::new(operation(), TenantReportDeliveryV1::Inline(report()));
        let slot = TenantReportCorrelationV1::new(operation());
        for error in [
            SnpVerificationError::InvalidEvidence,
            SnpVerificationError::InvalidCollateral,
            SnpVerificationError::UnsupportedTrust,
            SnpVerificationError::CryptographicVerification,
            SnpVerificationError::ReportDataBinding,
        ] {
            assert_eq!(
                verify(&request, &TestVerifier::new(Some(error)), None),
                Err(TenantDeliveryErrorV1::Verification(error))
            );
            assert_eq!(slot.verified_identity(), None);
        }
    }

    #[test]
    fn inconsistent_verifier_metadata_cannot_promote_identity() {
        let request =
            PrepareMigrationRequestV1::new(operation(), TenantReportDeliveryV1::Inline(report()));
        let mut verifier = TestVerifier::new(None);
        verifier.wrong_trust = true;
        assert_eq!(
            verify(&request, &verifier, None),
            Err(TenantDeliveryErrorV1::Verification(
                SnpVerificationError::UnsupportedTrust
            ))
        );
        verifier.wrong_trust = false;
        verifier.wrong_binding = true;
        assert_eq!(
            verify(&request, &verifier, None),
            Err(TenantDeliveryErrorV1::Verification(
                SnpVerificationError::InvalidEvidence
            ))
        );
    }

    #[test]
    fn changed_report_with_the_same_report_id_is_a_conflicting_retry() {
        let original = report();
        let mut changed = *original.as_bytes();
        changed[0x90] ^= 1;
        let changed = HostPushedTenantReportV1::from_bytes(&changed).unwrap();
        let verifier = TestVerifier::new(None);
        let mut slot = TenantReportCorrelationV1::new(operation());
        for (report, expected) in [
            (original, Ok(TenantDeliveryOutcomeV1::FirstDelivery)),
            (changed, Err(TenantDeliveryErrorV1::ConflictingDelivery)),
        ] {
            let request =
                PrepareMigrationRequestV1::new(operation(), TenantReportDeliveryV1::Inline(report));
            let verified = verify(&request, &verifier, None).unwrap();
            assert_eq!(verified.identity().as_bytes(), &[0x42; 32]);
            assert_eq!(slot.accept_verified(verified), expected);
        }
    }

    #[test]
    fn private_snapshot_prevents_mutation_of_the_input_buffer_after_construction() {
        let mut bytes = *report().as_bytes();
        let snapshot = HostPushedTenantReportV1::from_bytes(&bytes).unwrap();
        bytes[0x140] ^= 1;
        let request =
            PrepareMigrationRequestV1::new(operation(), TenantReportDeliveryV1::Inline(snapshot));
        assert_eq!(
            verify(&request, &TestVerifier::new(None), None)
                .unwrap()
                .identity()
                .as_bytes(),
            &[0x42; 32]
        );
        assert_ne!(bytes[0x140], 0x42);
    }
}
