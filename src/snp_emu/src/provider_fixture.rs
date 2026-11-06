// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Fixture-backed MA evidence provider.
//!
//! `MaEvidenceProvider` returns only the captured AMD SNP report and marks that
//! the requested report data was not freshly bound. `SnpCollateralProvider`
//! returns the captured VCEK and ASK explicitly. `AttestationProvider` remains
//! as a compatibility adapter for the current combined blob.

use pal::snp::limits::MAX_SNP_CERTIFICATE_SIZE;
use pal::traits::{AttestationProvider, MaEvidenceProvider, PalError, SnpCollateralProvider};
use pal::types::{
    AttestationBundle, MaEvidence, MaEvidenceBinding, MaEvidenceError, MaEvidenceRequest,
    SnpCollateralCertificateRole, SnpCollateralError, SnpCollateralLeafKind, SnpCollateralRequest,
    SnpVerificationCollateral,
};

use crate::report_emu::{
    build_fixture_blob, fixture_ask_der, fixture_report_bytes, fixture_vcek_der,
};

pub struct SnpFixtureProvider;

impl MaEvidenceProvider for SnpFixtureProvider {
    fn acquire_ma_evidence(
        &self,
        _request: &MaEvidenceRequest,
    ) -> Result<MaEvidence, MaEvidenceError> {
        MaEvidence::from_report_bytes(fixture_report_bytes(), MaEvidenceBinding::CapturedFixture)
    }
}

fn validate_fixture_certificate(
    role: SnpCollateralCertificateRole,
    certificate: &[u8],
) -> Result<(), SnpCollateralError> {
    if certificate.is_empty() {
        return Err(SnpCollateralError::MissingCertificate { role });
    }
    if certificate.len() > MAX_SNP_CERTIFICATE_SIZE {
        return Err(SnpCollateralError::CertificateTooLarge {
            role,
            actual: certificate.len(),
        });
    }
    Ok(())
}

impl SnpCollateralProvider for SnpFixtureProvider {
    fn acquire_snp_collateral(
        &self,
        _request: &SnpCollateralRequest<'_>,
    ) -> Result<SnpVerificationCollateral, SnpCollateralError> {
        let vcek_der = fixture_vcek_der();
        let ask_der = fixture_ask_der();
        validate_fixture_certificate(SnpCollateralCertificateRole::Vcek, vcek_der)?;
        validate_fixture_certificate(SnpCollateralCertificateRole::Ask, ask_der)?;

        Ok(SnpVerificationCollateral::new_with_leaf(
            SnpCollateralLeafKind::Vcek,
            vcek_der.to_vec(),
            ask_der.to_vec(),
        ))
    }
}

impl AttestationProvider for SnpFixtureProvider {
    fn get_report(&self, _report_data: &[u8; 64]) -> Result<AttestationBundle, PalError> {
        // _report_data accepted but NOT injected into the fixture.
        // The fixture report carries the report_data from its original capture time.
        // TH1 binding failure is an accepted Phase 1 limitation (resolved in Phase 3
        // when real AMD hardware generates a fresh report per session).
        Ok(AttestationBundle {
            ma_report_blob: build_fixture_blob()?,
            tenant_report: None, // Phase 3: Some(tenant_cvm_report)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal::types::{
        SnpCollateralCertificateRole, SNP_ATTESTATION_REPORT_SIZE, SNP_REPORT_DATA_SIZE,
    };

    #[test]
    fn fixture_provider_returns_typed_ma_evidence() {
        let evidence = SnpFixtureProvider
            .acquire_ma_evidence(&MaEvidenceRequest::new([0xA5; SNP_REPORT_DATA_SIZE]))
            .unwrap();

        assert_eq!(evidence.report().len(), SNP_ATTESTATION_REPORT_SIZE);
        assert_eq!(evidence.report(), fixture_report_bytes());
        assert_eq!(evidence.binding(), MaEvidenceBinding::CapturedFixture);
    }

    #[test]
    fn compatibility_bundle_starts_with_typed_ma_evidence() {
        let request = MaEvidenceRequest::new([0u8; SNP_REPORT_DATA_SIZE]);
        let evidence = SnpFixtureProvider.acquire_ma_evidence(&request).unwrap();
        let bundle = SnpFixtureProvider
            .get_report(request.report_data())
            .unwrap();

        assert_eq!(
            &bundle.ma_report_blob[..SNP_ATTESTATION_REPORT_SIZE],
            evidence.report()
        );
    }

    #[test]
    fn fixture_provider_returns_typed_collateral() {
        let evidence = SnpFixtureProvider
            .acquire_ma_evidence(&MaEvidenceRequest::new([0u8; SNP_REPORT_DATA_SIZE]))
            .unwrap();
        let collateral = SnpFixtureProvider
            .acquire_snp_collateral(&SnpCollateralRequest::new(&evidence))
            .unwrap();

        assert_eq!(collateral.leaf_kind(), SnpCollateralLeafKind::Vcek);
        assert_eq!(collateral.leaf_der(), fixture_vcek_der());
        assert_eq!(collateral.ask_der(), fixture_ask_der());
    }

    #[test]
    fn fixture_certificate_validation_rejects_empty_and_oversized_der() {
        assert_eq!(
            validate_fixture_certificate(SnpCollateralCertificateRole::Ask, &[]),
            Err(SnpCollateralError::MissingCertificate {
                role: SnpCollateralCertificateRole::Ask,
            })
        );

        let oversized = vec![0u8; MAX_SNP_CERTIFICATE_SIZE + 1];
        assert_eq!(
            validate_fixture_certificate(SnpCollateralCertificateRole::Vcek, &oversized),
            Err(SnpCollateralError::CertificateTooLarge {
                role: SnpCollateralCertificateRole::Vcek,
                actual: oversized.len(),
            })
        );
    }
}
