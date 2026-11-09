// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MigTD-owned P0.12A/A1 verifier contract. No backend or raw parser is selected.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpEvidenceProfile {
    SnpEmulatorV1,
    FirmwareAbi159V6,
    ArgAbi120MigrationOverlayV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpTrustDomain {
    Fixture,
    ProductionAmd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpEmulatorEvidenceV1 {
    pub report: [u8; 1184],
    pub supplement: [u8; 220],
    pub supplement_signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnpEvidenceInput {
    EmulatorV1(Box<SnpEmulatorEvidenceV1>),
    RawAmdReport { report: Box<[u8; 1184]> },
}

impl SnpEvidenceInput {
    pub fn report(&self) -> &[u8; 1184] {
        match self {
            Self::EmulatorV1(evidence) => &evidence.report,
            Self::RawAmdReport { report } => report,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnpRevocationInput {
    FixtureNotApplicable,
    AmdCrlsDer(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpCollateralInput {
    pub expected_trust_domain: SnpTrustDomain,
    pub leaf_certificate_der: Vec<u8>,
    pub intermediate_certificate_der: Vec<u8>,
    pub root_certificate_der: Vec<u8>,
    pub revocation: SnpRevocationInput,
    pub verification_time_unix_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedTcb {
    MilanGenoa {
        boot_loader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
    },
    Turin {
        fmc: u8,
        boot_loader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
    },
    Venice {
        fmc: u8,
        tee: u8,
        snp: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedEtcb {
    pub raw: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpSigningKeyKind {
    Vcek,
    Vlek,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpRevocationStatus {
    FixtureNotApplicable,
    CheckedNotRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpCollateralStatus {
    pub trust_domain: SnpTrustDomain,
    pub leaf_certificate_sha384: [u8; 48],
    pub certificate_chain_sha384: [u8; 48],
    pub verification_time_unix_seconds: u64,
    pub revocation: SnpRevocationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpClaimProvenance {
    pub evidence_profile: SnpEvidenceProfile,
    pub trust_domain: SnpTrustDomain,
    pub report_sha384: [u8; 48],
    pub supplement_sha384: Option<[u8; 48]>,
}

/// Output of the composition-selected trusted verifier, not policy admission.
/// Implementers must authenticate every field before returning success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSnpClaims {
    pub provenance: SnpClaimProvenance,
    pub report_version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub author_key_en: bool,
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: AuthenticatedTcb,
    pub current_tcb: AuthenticatedTcb,
    pub committed_tcb: AuthenticatedTcb,
    pub launch_tcb: AuthenticatedTcb,
    pub current_etcb: AuthenticatedEtcb,
    pub committed_etcb: AuthenticatedEtcb,
    pub launch_etcb: AuthenticatedEtcb,
    pub current_mitigation_vector: u64,
    pub launch_mitigation_vector: u64,
    pub migration_data_valid: bool,
    pub migration_data: [u8; 64],
    pub signing_key_kind: SnpSigningKeyKind,
    pub collateral_status: SnpCollateralStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpReportVerificationError {
    ProviderUnavailable,
    InvalidReportLength,
    UnsupportedReportVersion,
    MalformedReport,
    InvalidReservedBits,
    UnsupportedSigningKey,
    SignatureVerificationFailed,
    MissingCollateral,
    MalformedCollateral,
    CollateralTooLarge,
    CollateralTrustDomainMismatch,
    MissingRevocationCollateral,
    UntrustedCertificateChain,
    ExpiredCollateral,
    RevokedCollateral,
    InvalidVerificationTime,
    UnexpectedVmpl,
    ReportDataMismatch,
    InvalidTcbEncoding,
    InvalidEtcbEncoding,
    InvalidMitigationVector,
    InvalidSupplementLength,
    InvalidSupplementReservedBits,
    SupplementSignatureFailed,
    SupplementReportDigestMismatch,
    SupplementEtcbMismatch,
    InvalidSupplementMigrationData,
    FixtureEvidenceInProduction,
    UnsupportedVersion6Layout,
    ConflictingAbiLayout,
}

pub enum SnpReportVerificationRequest<'a> {
    GuestRequestedMa {
        evidence: &'a SnpEvidenceInput,
        collateral: &'a SnpCollateralInput,
        expected_vmpl: u32,
        expected_report_data: [u8; 64],
    },
    HostRequestedTenant {
        evidence: &'a SnpEvidenceInput,
        collateral: &'a SnpCollateralInput,
    },
    /// Fixture/emulator verification only; not active V1 host-push migration.
    GuestRequestedTenant {
        evidence: &'a SnpEvidenceInput,
        collateral: &'a SnpCollateralInput,
        expected_vmpl: u32,
        expected_report_data: [u8; 64],
    },
}

/// A locally selected trusted adapter, never selected by a host request.
pub trait SnpReportVerifier {
    fn verify(
        &self,
        request: SnpReportVerificationRequest<'_>,
    ) -> Result<AuthenticatedSnpClaims, SnpReportVerificationError>;
}

pub struct UnavailableSnpReportVerifier;

impl SnpReportVerifier for UnavailableSnpReportVerifier {
    fn verify(
        &self,
        _request: SnpReportVerificationRequest<'_>,
    ) -> Result<AuthenticatedSnpClaims, SnpReportVerificationError> {
        Err(SnpReportVerificationError::ProviderUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_adapter_never_returns_claims_for_any_request_kind() {
        let evidence = SnpEvidenceInput::RawAmdReport {
            report: Box::new([0; 1184]),
        };
        let collateral = SnpCollateralInput {
            expected_trust_domain: SnpTrustDomain::Fixture,
            leaf_certificate_der: vec![],
            intermediate_certificate_der: vec![],
            root_certificate_der: vec![],
            revocation: SnpRevocationInput::FixtureNotApplicable,
            verification_time_unix_seconds: 0,
        };
        for request in [
            SnpReportVerificationRequest::HostRequestedTenant {
                evidence: &evidence,
                collateral: &collateral,
            },
            SnpReportVerificationRequest::GuestRequestedTenant {
                evidence: &evidence,
                collateral: &collateral,
                expected_vmpl: 1,
                expected_report_data: [1; 64],
            },
            SnpReportVerificationRequest::GuestRequestedMa {
                evidence: &evidence,
                collateral: &collateral,
                expected_vmpl: 1,
                expected_report_data: [1; 64],
            },
        ] {
            assert_eq!(
                UnavailableSnpReportVerifier.verify(request),
                Err(SnpReportVerificationError::ProviderUnavailable)
            );
        }
    }
}
