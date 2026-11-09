// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! P0.7 contribution transcript conformance, not a transport driver or KDF.
//! Task 10 must additionally enforce policy, durable admission, the current
//! authenticated encrypted SPDM session, and cross-session replay prevention.

use core::fmt;

use super::{
    authorization_result::SnpAuthorizationFailureV1,
    key_contribution::{SnpKeyContributionV1, SNP_KEY_CONTRIBUTION_SIZE},
    report_data_context::{ReportDataContextV1, SnpMaRoleV1},
    tenant_authorization::{TenantAuthorizationContextV1, TenantAuthorizationErrorV1},
    wire::SnpCodecError,
};
use crate::tenant_replay::VerifiedTenantAuthorizationV1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionCommitmentErrorV1 {
    ConstructionUnavailable,
    Mismatch,
}

/// Trusted composition must implement the approved P0.10 inter-node V1 recipe,
/// recomputing the commitment from the actual secret and trusted context.
/// Comparing commitment references or trusting the peer is insufficient.
pub trait ContributionCommitmentVerifierV1 {
    fn verify(
        &self,
        expected: &ReportDataContextV1,
        contribution: &[u8; SNP_KEY_CONTRIBUTION_SIZE],
    ) -> Result<(), ContributionCommitmentErrorV1>;
}

#[derive(Debug)]
pub struct UnavailableContributionCommitmentVerifierV1;

impl ContributionCommitmentVerifierV1 for UnavailableContributionCommitmentVerifierV1 {
    fn verify(
        &self,
        _expected: &ReportDataContextV1,
        _contribution: &[u8; SNP_KEY_CONTRIBUTION_SIZE],
    ) -> Result<(), ContributionCommitmentErrorV1> {
        Err(ContributionCommitmentErrorV1::ConstructionUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionExchangeErrorV1 {
    Authorization(TenantAuthorizationErrorV1),
    AuthorizationMismatch,
    Codec(SnpCodecError),
    Context(SnpAuthorizationFailureV1),
    Commitment(ContributionCommitmentErrorV1),
    ProtocolStateViolation,
    Incomplete,
}

impl ContributionExchangeErrorV1 {
    pub fn protocol_failure(self) -> SnpAuthorizationFailureV1 {
        match self {
            Self::Codec(error) => SnpKeyContributionV1::codec_failure(error),
            Self::Context(SnpAuthorizationFailureV1::None) => {
                SnpAuthorizationFailureV1::InternalError
            }
            Self::Context(error) => error,
            Self::Commitment(ContributionCommitmentErrorV1::Mismatch) => {
                SnpAuthorizationFailureV1::ReportDataBindingFailed
            }
            Self::Commitment(ContributionCommitmentErrorV1::ConstructionUnavailable) => {
                SnpAuthorizationFailureV1::InternalError
            }
            Self::Authorization(_) | Self::AuthorizationMismatch => {
                SnpAuthorizationFailureV1::IdentityBindingFailed
            }
            Self::ProtocolStateViolation | Self::Incomplete => {
                SnpAuthorizationFailureV1::ProtocolStateViolation
            }
        }
    }
}

/// Selected by the trusted workflow/opcode, never inferred from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionDirectionV1 {
    SourceRequest,
    DestinationResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionExchangeStateV1 {
    AwaitingSource,
    AwaitingDestination,
    Complete,
    Aborted,
}

/// Records both local and remote messages in canonical wire order. Neither
/// construction nor completion proves policy approval, durable admission or
/// current SPDM authentication. Those remain mandatory runtime gates.
pub struct ContributionExchangeV1 {
    source_context: ReportDataContextV1,
    destination_context: ReportDataContextV1,
    authorization_context_digest: [u8; 48],
    source: Option<SnpKeyContributionV1>,
    destination: Option<SnpKeyContributionV1>,
    state: ContributionExchangeStateV1,
}

impl fmt::Debug for ContributionExchangeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContributionExchangeV1")
            .field("state", &self.state)
            .field("contributions", &"<redacted>")
            .finish()
    }
}

impl ContributionExchangeV1 {
    pub fn new(
        context: &TenantAuthorizationContextV1,
        authorization: &VerifiedTenantAuthorizationV1,
    ) -> Result<Self, ContributionExchangeErrorV1> {
        let binding = context
            .replay_binding()
            .map_err(ContributionExchangeErrorV1::Authorization)?;
        if &binding != authorization.binding() {
            return Err(ContributionExchangeErrorV1::AuthorizationMismatch);
        }
        Ok(Self {
            source_context: context
                .contribution_context(SnpMaRoleV1::Source)
                .map_err(ContributionExchangeErrorV1::Authorization)?
                .clone(),
            destination_context: context
                .contribution_context(SnpMaRoleV1::Destination)
                .map_err(ContributionExchangeErrorV1::Authorization)?
                .clone(),
            authorization_context_digest: binding.as_stored().authorization_context_digest,
            source: None,
            destination: None,
            state: ContributionExchangeStateV1::AwaitingSource,
        })
    }

    pub const fn state(&self) -> ContributionExchangeStateV1 {
        self.state
    }

    /// Always erases this payload. The caller must separately erase transport
    /// copies, and call `abort` or drop on timeout/cancellation/session loss.
    pub fn accept_encoded(
        &mut self,
        direction: ContributionDirectionV1,
        payload: &mut [u8],
        verifier: &dyn ContributionCommitmentVerifierV1,
    ) -> Result<(), ContributionExchangeErrorV1> {
        let result = SnpKeyContributionV1::decode_exact(payload)
            .map_err(ContributionExchangeErrorV1::Codec)
            .and_then(|record| self.accept_record(direction, record, verifier));
        if result.is_err() {
            self.abort();
        }
        result
    }

    fn accept_record(
        &mut self,
        direction: ContributionDirectionV1,
        mut record: SnpKeyContributionV1,
        verifier: &dyn ContributionCommitmentVerifierV1,
    ) -> Result<(), ContributionExchangeErrorV1> {
        let expected = match (self.state, direction) {
            (
                ContributionExchangeStateV1::AwaitingSource,
                ContributionDirectionV1::SourceRequest,
            ) => &self.source_context,
            (
                ContributionExchangeStateV1::AwaitingDestination,
                ContributionDirectionV1::DestinationResponse,
            ) => &self.destination_context,
            _ => return Err(ContributionExchangeErrorV1::ProtocolStateViolation),
        };
        record
            .validate_context(expected)
            .map_err(ContributionExchangeErrorV1::Context)?;
        verifier
            .verify(expected, record.contribution())
            .map_err(ContributionExchangeErrorV1::Commitment)?;
        match direction {
            ContributionDirectionV1::SourceRequest => {
                self.source = Some(record);
                self.state = ContributionExchangeStateV1::AwaitingDestination;
            }
            ContributionDirectionV1::DestinationResponse => {
                self.destination = Some(record);
                self.state = ContributionExchangeStateV1::Complete;
            }
        }
        Ok(())
    }

    pub fn abort(&mut self) {
        if let Some(record) = self.source.as_mut() {
            record.clear_contribution();
        }
        if let Some(record) = self.destination.as_mut() {
            record.clear_contribution();
        }
        self.state = ContributionExchangeStateV1::Aborted;
    }

    pub fn finish(mut self) -> Result<VerifiedContributionPairV1, ContributionExchangeErrorV1> {
        if self.state != ContributionExchangeStateV1::Complete {
            return Err(ContributionExchangeErrorV1::Incomplete);
        }
        let source = self
            .source
            .take()
            .ok_or(ContributionExchangeErrorV1::Incomplete)?;
        let destination = self
            .destination
            .take()
            .ok_or(ContributionExchangeErrorV1::Incomplete)?;
        Ok(VerifiedContributionPairV1 {
            source,
            destination,
            authorization_context_digest: self.authorization_context_digest,
        })
    }
}

/// One-shot access in source/destination order, not a derived key or permission
/// to install one. Owned secrets are wiped on return, error or unwind. Copies
/// made by the consumer and its derived outputs are its responsibility.
///
/// ```compile_fail
/// use pal::snp::contribution_exchange::VerifiedContributionPairV1;
/// fn duplicate(pair: VerifiedContributionPairV1) { let _ = pair.clone(); }
/// ```
///
/// ```compile_fail
/// use pal::snp::contribution_exchange::VerifiedContributionPairV1;
/// fn reuse(pair: VerifiedContributionPairV1) {
///     pair.consume(|_, _| ());
///     pair.consume(|_, _| ());
/// }
/// ```
///
/// ```compile_fail
/// use pal::snp::contribution_exchange::VerifiedContributionPairV1;
/// use pal::snp::key_contribution::SnpKeyContributionV1;
/// fn forge(source: SnpKeyContributionV1, destination: SnpKeyContributionV1) {
///     VerifiedContributionPairV1 {
///         source, destination, authorization_context_digest: [0; 48],
///     };
/// }
/// ```
pub struct VerifiedContributionPairV1 {
    source: SnpKeyContributionV1,
    destination: SnpKeyContributionV1,
    authorization_context_digest: [u8; 48],
}

impl fmt::Debug for VerifiedContributionPairV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedContributionPairV1")
            .field("contributions", &"<redacted>")
            .finish()
    }
}

impl VerifiedContributionPairV1 {
    pub const fn authorization_context_digest(&self) -> &[u8; 48] {
        &self.authorization_context_digest
    }

    pub fn consume<R>(
        self,
        consumer: impl FnOnce(&[u8; SNP_KEY_CONTRIBUTION_SIZE], &[u8; SNP_KEY_CONTRIBUTION_SIZE]) -> R,
    ) -> R {
        consumer(self.source.contribution(), self.destination.contribution())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp::report_data_context::{SnpEvidencePurposeV1, SnpMigrationAlgorithmV1};
    use zeroize::Zeroizing;

    #[test]
    fn every_error_has_an_explicit_non_success_protocol_mapping() {
        use SnpAuthorizationFailureV1 as Failure;
        for (error, expected) in [
            (
                ContributionExchangeErrorV1::Codec(SnpCodecError::UnsupportedVersion),
                Failure::UnsupportedVersion,
            ),
            (
                ContributionExchangeErrorV1::Codec(SnpCodecError::Truncated),
                Failure::MalformedMessage,
            ),
            (
                ContributionExchangeErrorV1::Context(Failure::IdentityBindingFailed),
                Failure::IdentityBindingFailed,
            ),
            (
                ContributionExchangeErrorV1::Context(Failure::None),
                Failure::InternalError,
            ),
            (
                ContributionExchangeErrorV1::Commitment(ContributionCommitmentErrorV1::Mismatch),
                Failure::ReportDataBindingFailed,
            ),
            (
                ContributionExchangeErrorV1::Commitment(
                    ContributionCommitmentErrorV1::ConstructionUnavailable,
                ),
                Failure::InternalError,
            ),
            (
                ContributionExchangeErrorV1::Authorization(
                    TenantAuthorizationErrorV1::ContextMismatch,
                ),
                Failure::IdentityBindingFailed,
            ),
            (
                ContributionExchangeErrorV1::AuthorizationMismatch,
                Failure::IdentityBindingFailed,
            ),
            (
                ContributionExchangeErrorV1::ProtocolStateViolation,
                Failure::ProtocolStateViolation,
            ),
            (
                ContributionExchangeErrorV1::Incomplete,
                Failure::ProtocolStateViolation,
            ),
        ] {
            assert_eq!(error.protocol_failure(), expected);
            assert_ne!(expected, Failure::None);
        }
    }

    #[test]
    fn abort_explicitly_erases_both_retained_secrets() {
        let source_context = ReportDataContextV1 {
            evidence_purpose: SnpEvidencePurposeV1::InterNodeKeyContribution,
            role: SnpMaRoleV1::Source,
            request_id: 1,
            negotiated_migration_version: 1,
            algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
            tenant_binding_id: [0x11; 32],
            th1: [0x22; 48],
            purpose_binding_digest: [0x33; 48],
            ma_policy_identity_digest: [0x44; 48],
        };
        let destination_context = ReportDataContextV1 {
            role: SnpMaRoleV1::Destination,
            ..source_context.clone()
        };
        let mut exchange = ContributionExchangeV1 {
            source: Some(
                SnpKeyContributionV1::new(source_context.clone(), Zeroizing::new([0xa5; 32]))
                    .unwrap(),
            ),
            destination: Some(
                SnpKeyContributionV1::new(destination_context.clone(), Zeroizing::new([0x5a; 32]))
                    .unwrap(),
            ),
            source_context,
            destination_context,
            authorization_context_digest: [0x55; 48],
            state: ContributionExchangeStateV1::Complete,
        };
        assert_eq!(
            exchange.source.as_ref().unwrap().contribution(),
            &[0xa5; 32]
        );
        assert_eq!(
            exchange.destination.as_ref().unwrap().contribution(),
            &[0x5a; 32]
        );
        exchange.abort();
        assert_eq!(exchange.source.as_ref().unwrap().contribution(), &[0; 32]);
        assert_eq!(
            exchange.destination.as_ref().unwrap().contribution(),
            &[0; 32]
        );
        assert_eq!(exchange.state(), ContributionExchangeStateV1::Aborted);
    }
}
