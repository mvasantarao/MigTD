// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformType {
    Tdx,
    AmdSnp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct QvlResult {
    pub platform: PlatformType,
    pub tcb_status: TcbStatus,
    /// Phase 2 (P2-07): platform TCB from VCEK OID extensions (1.3.6.1.4.1.3704.1.x).
    /// Raw 8 bytes matching the TcbVersionMilanGenoa wire layout.
    /// None if cert does not carry AMD OID extensions (test/mock certs).
    pub platform_tcb: Option<[u8; 8]>,
}

/// Bundle returned by AttestationProvider::get_report().
/// Phase 1: only ma_report_blob is populated (tenant_report = None).
/// Phase 3: tenant_report also populated (real tenant CVM SNP report).
#[derive(Debug, Clone)]
pub struct AttestationBundle {
    /// MA's own SNP REPORT (1184 bytes) + cert chain DERs concatenated:
    /// report[1184] || vcek_len[4LE] || vcek || ask_len[4LE] || ask
    pub ma_report_blob: Vec<u8>,
    /// Tenant CVM's SNP report, when supplied by the platform integration.
    pub tenant_report: Option<Vec<u8>>,
}

pub const SNP_ATTESTATION_REPORT_SIZE: usize = 1_184;
pub const SNP_REPORT_DATA_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaEvidenceRequest {
    report_data: [u8; SNP_REPORT_DATA_SIZE],
}

impl MaEvidenceRequest {
    pub const fn new(report_data: [u8; SNP_REPORT_DATA_SIZE]) -> Self {
        Self { report_data }
    }

    pub const fn report_data(&self) -> &[u8; SNP_REPORT_DATA_SIZE] {
        &self.report_data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaEvidenceBinding {
    RequestedReportData,
    CapturedFixture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaEvidence {
    report: [u8; SNP_ATTESTATION_REPORT_SIZE],
    binding: MaEvidenceBinding,
}

impl MaEvidence {
    pub const fn new(
        report: [u8; SNP_ATTESTATION_REPORT_SIZE],
        binding: MaEvidenceBinding,
    ) -> Self {
        Self { report, binding }
    }

    pub fn from_report_bytes(
        report: &[u8],
        binding: MaEvidenceBinding,
    ) -> Result<Self, MaEvidenceError> {
        if report.len() != SNP_ATTESTATION_REPORT_SIZE {
            return Err(MaEvidenceError::InvalidReportLength {
                actual: report.len(),
            });
        }
        let mut fixed_report = [0u8; SNP_ATTESTATION_REPORT_SIZE];
        fixed_report.copy_from_slice(report);
        Ok(Self::new(fixed_report, binding))
    }

    pub const fn report(&self) -> &[u8; SNP_ATTESTATION_REPORT_SIZE] {
        &self.report
    }

    pub const fn binding(&self) -> MaEvidenceBinding {
        self.binding
    }

    pub fn into_report(self) -> [u8; SNP_ATTESTATION_REPORT_SIZE] {
        self.report
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaEvidenceError {
    InvalidReportLength { actual: usize },
    ProviderUnavailable,
    DeviceIo,
    FirmwareRejected { status: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpVerificationCollateral {
    leaf_kind: SnpCollateralLeafKind,
    leaf_der: Vec<u8>,
    ask_der: Vec<u8>,
}

impl SnpVerificationCollateral {
    pub fn new(vcek_der: Vec<u8>, ask_der: Vec<u8>) -> Self {
        Self::new_with_leaf(SnpCollateralLeafKind::Vcek, vcek_der, ask_der)
    }

    pub fn new_with_leaf(
        leaf_kind: SnpCollateralLeafKind,
        leaf_der: Vec<u8>,
        ask_der: Vec<u8>,
    ) -> Self {
        Self {
            leaf_kind,
            leaf_der,
            ask_der,
        }
    }

    pub const fn leaf_kind(&self) -> SnpCollateralLeafKind {
        self.leaf_kind
    }

    pub fn leaf_der(&self) -> &[u8] {
        &self.leaf_der
    }

    pub fn ask_der(&self) -> &[u8] {
        &self.ask_der
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpCollateralLeafKind {
    Vcek,
    Vlek,
}

#[derive(Debug, Clone, Copy)]
pub struct SnpCollateralRequest<'a> {
    evidence: &'a MaEvidence,
}

impl<'a> SnpCollateralRequest<'a> {
    pub const fn new(evidence: &'a MaEvidence) -> Self {
        Self { evidence }
    }

    pub const fn evidence(&self) -> &'a MaEvidence {
        self.evidence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpCollateralCertificateRole {
    Vcek,
    Vlek,
    Ask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpCollateralError {
    MissingCertificate {
        role: SnpCollateralCertificateRole,
    },
    CertificateTooLarge {
        role: SnpCollateralCertificateRole,
        actual: usize,
    },
    UnsupportedLeafCertificate {
        kind: SnpCollateralLeafKind,
    },
    ProviderUnavailable,
    DeviceIo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpVerifierTrust {
    AzureProduction,
    PinnedMilanArkTest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpReportRequestKind {
    GuestRequestedMa {
        expected_vmpl: u32,
    },
    HostRequestedTenant,
    /// Compatibility for the captured pre-Version-1 fixture, not a live LM report.
    LegacyCapturedFixture,
}

pub struct SnpEvidenceVerificationRequest<'a> {
    pub evidence: &'a MaEvidence,
    pub collateral: &'a SnpVerificationCollateral,
    pub expected_report_data: &'a [u8; 48],
    pub report_request: SnpReportRequestKind,
    pub trust: SnpVerifierTrust,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnpEvidence {
    pub binding: MaEvidenceBinding,
    pub tcb_status: TcbStatus,
    pub platform_tcb: Option<[u8; 8]>,
    pub trust: SnpVerifierTrust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpVerificationError {
    ProviderUnavailable,
    InvalidEvidence,
    InvalidCollateral,
    UnsupportedCollateral { leaf_kind: SnpCollateralLeafKind },
    UnsupportedTrust,
    CryptographicVerification,
    ReportDataBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationRole {
    Source,
    Destination,
}

impl MigrationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMigrationRole {
    value: u8,
}

impl InvalidMigrationRole {
    pub const fn value(self) -> u8 {
        self.value
    }
}

impl TryFrom<u8> for MigrationRole {
    type Error = InvalidMigrationRole;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Destination),
            1 => Ok(Self::Source),
            value => Err(InvalidMigrationRole { value }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRequestId(u64);

impl HostRequestId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationId(u64);

impl MigrationId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedGuestHandle(u64);

impl ManagedGuestHandle {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRoutingReference(u64);

impl PeerRoutingReference {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyIdentity(u64);

impl PolicyIdentity {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnpOperationContext {
    pub request_id: HostRequestId,
    pub migration_id: MigrationId,
    pub role: MigrationRole,
    pub managed_guest: ManagedGuestHandle,
    pub peer: Option<PeerRoutingReference>,
    pub protocol_version: Option<ProtocolVersion>,
    pub policy: Option<PolicyIdentity>,
}

impl SnpOperationContext {
    pub const fn new(
        request_id: HostRequestId,
        migration_id: MigrationId,
        role: MigrationRole,
        managed_guest: ManagedGuestHandle,
    ) -> Self {
        Self {
            request_id,
            migration_id,
            role,
            managed_guest,
            peer: None,
            protocol_version: None,
            policy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ma_evidence_requires_an_exact_report() {
        assert_eq!(
            MaEvidence::from_report_bytes(
                &[0u8; SNP_ATTESTATION_REPORT_SIZE - 1],
                MaEvidenceBinding::CapturedFixture,
            ),
            Err(MaEvidenceError::InvalidReportLength {
                actual: SNP_ATTESTATION_REPORT_SIZE - 1,
            })
        );
    }

    #[test]
    fn ma_evidence_preserves_binding_status() {
        let evidence = MaEvidence::new(
            [0xA5; SNP_ATTESTATION_REPORT_SIZE],
            MaEvidenceBinding::RequestedReportData,
        );

        assert_eq!(evidence.report()[0], 0xA5);
        assert_eq!(evidence.binding(), MaEvidenceBinding::RequestedReportData);
    }

    #[test]
    fn migration_role_rejects_unknown_values() {
        assert_eq!(MigrationRole::try_from(0), Ok(MigrationRole::Destination));
        assert_eq!(MigrationRole::try_from(1), Ok(MigrationRole::Source));
        assert_eq!(MigrationRole::try_from(2).unwrap_err().value(), 2);
    }

    #[test]
    fn operation_context_keeps_logical_identities_distinct() {
        let context = SnpOperationContext::new(
            HostRequestId::new(7),
            MigrationId::new(8),
            MigrationRole::Source,
            ManagedGuestHandle::new(9),
        );

        assert_eq!(context.request_id.value(), 7);
        assert_eq!(context.migration_id.value(), 8);
        assert_eq!(context.managed_guest.value(), 9);
        assert_eq!(context.peer, None);
        assert_eq!(context.protocol_version, None);
        assert_eq!(context.policy, None);
    }
}
