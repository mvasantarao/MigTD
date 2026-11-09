// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Legacy captured-fixture verification through the local AAS library only.
//! This is not the common Version 6 claims adapter.

use crate::snp::qvl::validate::{validate, AttestationVerificationParams};
use crate::traits::{PalError, QvlLibrary, SnpEvidenceVerifier};
use crate::types::{
    MaEvidence, MaEvidenceBinding, QvlResult, SnpEvidenceVerificationRequest,
    SnpVerificationCollateral, SnpVerificationError, SnpVerifierTrust, VerifiedSnpEvidence,
};
#[cfg(feature = "snp-aas-verify")]
use crate::types::{SnpCollateralLeafKind, SnpReportRequestKind, TcbStatus};

pub struct SnpQvl;

#[cfg(not(feature = "snp-aas-verify"))]
impl SnpEvidenceVerifier for SnpQvl {
    fn verify_evidence(
        &self,
        _request: &SnpEvidenceVerificationRequest<'_>,
    ) -> Result<VerifiedSnpEvidence, SnpVerificationError> {
        log::error!("local SNP AAS verifier unavailable");
        Err(SnpVerificationError::ProviderUnavailable)
    }
}

#[cfg(feature = "snp-aas-verify")]
impl SnpEvidenceVerifier for SnpQvl {
    fn verify_evidence(
        &self,
        request: &SnpEvidenceVerificationRequest<'_>,
    ) -> Result<VerifiedSnpEvidence, SnpVerificationError> {
        if request.trust != SnpVerifierTrust::AzureProduction {
            return Err(SnpVerificationError::UnsupportedTrust);
        }
        if request.report_request != SnpReportRequestKind::LegacyCapturedFixture {
            log::error!("Version 6 verification requires the unavailable common AAS adapter");
            return Err(SnpVerificationError::ProviderUnavailable);
        }
        if request.collateral.leaf_kind() != SnpCollateralLeafKind::Vcek {
            return Err(SnpVerificationError::UnsupportedCollateral {
                leaf_kind: request.collateral.leaf_kind(),
            });
        }

        let cert_chain = vec![
            request.collateral.leaf_der().to_vec(),
            request.collateral.ask_der().to_vec(),
        ];
        let chain_pem = super::azure::der_chain_to_pem(&cert_chain)
            .map_err(|_| SnpVerificationError::InvalidCollateral)?;
        let result = azure_guest_attestation_sdk::verify::verify_snp_report(
            request.evidence.report(),
            &chain_pem,
            &Default::default(),
        )
        .map_err(|_| SnpVerificationError::CryptographicVerification)?;

        if request.report_request == SnpReportRequestKind::LegacyCapturedFixture
            && request.evidence.binding() != MaEvidenceBinding::CapturedFixture
        {
            return Err(SnpVerificationError::InvalidEvidence);
        }
        let params = AttestationVerificationParams::for_request(
            request.evidence.report(),
            request.expected_report_data,
            request.report_request,
        );
        validate(&params).map_err(|_| SnpVerificationError::ReportDataBinding)?;

        Ok(VerifiedSnpEvidence {
            binding: request.evidence.binding(),
            tcb_status: TcbStatus::UpToDate,
            platform_tcb: Some(result.measurements.reported_tcb.to_le_bytes()),
            trust: request.trust,
        })
    }
}

impl QvlLibrary for SnpQvl {
    fn verify(
        &self,
        params: &AttestationVerificationParams<'_>,
        cert_chain: &[Vec<u8>],
    ) -> Result<QvlResult, PalError> {
        if cert_chain.len() < 2 {
            return Err(PalError::InvalidInput);
        }
        let evidence =
            MaEvidence::from_report_bytes(params.report, MaEvidenceBinding::CapturedFixture)
                .map_err(|_| PalError::InvalidInput)?;
        let collateral =
            SnpVerificationCollateral::new(cert_chain[0].clone(), cert_chain[1].clone());
        let trust = SnpVerifierTrust::AzureProduction;
        let verified = self
            .verify_evidence(&SnpEvidenceVerificationRequest {
                evidence: &evidence,
                collateral: &collateral,
                expected_report_data: params.expected_report_data,
                report_request: params.report_request,
                trust,
            })
            .map_err(|error| PalError::VerificationFailed(format!("{error:?}")))?;

        validate(params)?;

        Ok(QvlResult {
            platform: crate::types::PlatformType::AmdSnp,
            tcb_status: verified.tcb_status,
            platform_tcb: verified.platform_tcb,
        })
    }
}

#[cfg(all(test, feature = "snp-aas-verify"))]
mod tests {
    use super::*;

    #[test]
    fn live_reports_cannot_use_the_legacy_fixture_verifier() {
        let evidence = MaEvidence::new(
            [0; crate::types::SNP_ATTESTATION_REPORT_SIZE],
            MaEvidenceBinding::RequestedReportData,
        );
        let collateral = SnpVerificationCollateral::new(vec![], vec![]);
        assert_eq!(
            SnpQvl.verify_evidence(&SnpEvidenceVerificationRequest {
                evidence: &evidence,
                collateral: &collateral,
                expected_report_data: &[0; 48],
                report_request: SnpReportRequestKind::GuestRequestedMa { expected_vmpl: 1 },
                trust: SnpVerifierTrust::AzureProduction,
            }),
            Err(SnpVerificationError::ProviderUnavailable)
        );
    }

    #[test]
    fn verifier_rejects_trust_for_the_other_backend() {
        let evidence = MaEvidence::new(
            [0u8; crate::types::SNP_ATTESTATION_REPORT_SIZE],
            MaEvidenceBinding::CapturedFixture,
        );
        let collateral = SnpVerificationCollateral::new(Vec::new(), Vec::new());
        let trust = SnpVerifierTrust::PinnedMilanArkTest;

        assert_eq!(
            SnpQvl.verify_evidence(&SnpEvidenceVerificationRequest {
                evidence: &evidence,
                collateral: &collateral,
                expected_report_data: &[0u8; 48],
                report_request: SnpReportRequestKind::LegacyCapturedFixture,
                trust,
            }),
            Err(SnpVerificationError::UnsupportedTrust)
        );
    }

    #[cfg(all(test, not(feature = "snp-aas-verify")))]
    mod unavailable_tests {
        use super::*;

        #[test]
        fn fixture_capability_without_aas_has_no_verifier_fallback() {
            let evidence = MaEvidence::new(
                [0; crate::types::SNP_ATTESTATION_REPORT_SIZE],
                MaEvidenceBinding::CapturedFixture,
            );
            let collateral = SnpVerificationCollateral::new(vec![], vec![]);
            assert_eq!(
                SnpQvl.verify_evidence(&SnpEvidenceVerificationRequest {
                    evidence: &evidence,
                    collateral: &collateral,
                    expected_report_data: &[0; 48],
                    report_request: crate::types::SnpReportRequestKind::LegacyCapturedFixture,
                    trust: SnpVerifierTrust::AzureProduction,
                }),
                Err(SnpVerificationError::ProviderUnavailable)
            );
        }
    }

    #[test]
    fn verifier_rejects_missing_collateral() {
        let evidence = MaEvidence::new(
            [0u8; crate::types::SNP_ATTESTATION_REPORT_SIZE],
            MaEvidenceBinding::CapturedFixture,
        );
        let collateral = SnpVerificationCollateral::new(Vec::new(), Vec::new());
        let trust = SnpVerifierTrust::AzureProduction;

        assert_eq!(
            SnpQvl.verify_evidence(&SnpEvidenceVerificationRequest {
                evidence: &evidence,
                collateral: &collateral,
                expected_report_data: &[0u8; 48],
                report_request: SnpReportRequestKind::LegacyCapturedFixture,
                trust,
            }),
            Err(SnpVerificationError::InvalidCollateral)
        );
    }

    #[test]
    fn verifier_rejects_unsupported_vlek_collateral() {
        let evidence = MaEvidence::new(
            [0u8; crate::types::SNP_ATTESTATION_REPORT_SIZE],
            MaEvidenceBinding::CapturedFixture,
        );
        let collateral =
            SnpVerificationCollateral::new_with_leaf(SnpCollateralLeafKind::Vlek, vec![1], vec![2]);
        let trust = SnpVerifierTrust::AzureProduction;

        assert_eq!(
            SnpQvl.verify_evidence(&SnpEvidenceVerificationRequest {
                evidence: &evidence,
                collateral: &collateral,
                expected_report_data: &[0u8; 48],
                report_request: SnpReportRequestKind::LegacyCapturedFixture,
                trust,
            }),
            Err(SnpVerificationError::UnsupportedCollateral {
                leaf_kind: SnpCollateralLeafKind::Vlek,
            })
        );
    }
}
