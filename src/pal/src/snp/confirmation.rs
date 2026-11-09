// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! P0.8 record/state conformance, not a KDF, SPDM driver or readiness gate.

use super::{
    authorization_result::SnpAuthorizationFailureV1,
    evidence_header::SnpRecordTypeV1,
    key_contribution::SnpKeyContributionV1,
    report_data_context::SnpMaRoleV1,
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};

/// Data, not an authorization token. Task 10 must reconstruct this reference
/// from trusted local state using the authoritative canonical session recipe.
/// It is not the P0.6 authorization-context digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpSessionReferenceV1 {
    pub request_id: u64,
    pub session_context_digest: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnpConfirmationDirectionV1 {
    SourceToDestination = 0,
    DestinationToSource = 1,
}

impl SnpConfirmationDirectionV1 {
    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u8()? {
            0 => Ok(Self::SourceToDestination),
            1 => Ok(Self::DestinationToSource),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }

    fn validate_role(self, role: SnpMaRoleV1) -> SnpCodecResult<()> {
        if matches!(
            (role, self),
            (SnpMaRoleV1::Source, Self::SourceToDestination)
                | (SnpMaRoleV1::Destination, Self::DestinationToSource)
        ) {
            Ok(())
        } else {
            Err(SnpCodecError::NonCanonicalEncoding)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SnpConfirmationStatusV1 {
    Confirmed = 1,
    Rejected = 2,
}

impl SnpConfirmationStatusV1 {
    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u16()? {
            1 => Ok(Self::Confirmed),
            2 => Ok(Self::Rejected),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }
}

fn encode_header(
    writer: &mut StrictWriter<'_>,
    magic: &[u8; 8],
    record_type: SnpRecordTypeV1,
    length: u32,
) -> SnpCodecResult<()> {
    writer.write_bytes(magic)?;
    writer.write_u8(1)?;
    writer.write_u8(0)?;
    record_type.encode(writer)?;
    writer.write_u32(length)
}

fn decode_header(
    reader: &mut StrictReader<'_>,
    magic: &[u8; 8],
    record_type: SnpRecordTypeV1,
    length: u32,
) -> SnpCodecResult<()> {
    if &reader.read_array::<8>()? != magic {
        return Err(SnpCodecError::InvalidMagic);
    }
    if reader.read_u8()? != 1 || reader.read_u8()? != 0 {
        return Err(SnpCodecError::UnsupportedVersion);
    }
    if SnpRecordTypeV1::decode(reader)? != record_type {
        return Err(SnpCodecError::UnknownRecordType);
    }
    if reader.read_u32()? != length {
        return Err(SnpCodecError::InvalidLength);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpConfirmationV1 {
    pub session: SnpSessionReferenceV1,
    pub role: SnpMaRoleV1,
    pub direction: SnpConfirmationDirectionV1,
    pub status: SnpConfirmationStatusV1,
    pub tag: [u8; 48],
}

impl SnpConfirmationV1 {
    pub const MAGIC: [u8; 8] = *b"SNP-LM-C";
    pub const ENCODED_SIZE: usize = 128;

    fn validate(&self) -> SnpCodecResult<()> {
        self.direction.validate_role(self.role)?;
        if self.status == SnpConfirmationStatusV1::Rejected && self.tag != [0; 48] {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        self.validate()?;
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut bytes);
        encode_header(
            &mut writer,
            &Self::MAGIC,
            SnpRecordTypeV1::Confirmation,
            Self::ENCODED_SIZE as u32,
        )?;
        writer.write_u64(self.session.request_id)?;
        self.role.encode(&mut writer)?;
        writer.write_u8(self.direction as u8)?;
        writer.write_u16(self.status as u16)?;
        writer.write_bytes(&self.session.session_context_digest)?;
        writer.write_bytes(&self.tag)?;
        writer.write_zeroes(4)?;
        if writer.written() != Self::ENCODED_SIZE {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(bytes);
        decode_header(
            &mut reader,
            &Self::MAGIC,
            SnpRecordTypeV1::Confirmation,
            Self::ENCODED_SIZE as u32,
        )?;
        let request_id = reader.read_u64()?;
        let role = SnpMaRoleV1::decode(&mut reader)?;
        let direction = SnpConfirmationDirectionV1::decode(&mut reader)?;
        let status = SnpConfirmationStatusV1::decode(&mut reader)?;
        let value = Self {
            session: SnpSessionReferenceV1 {
                request_id,
                session_context_digest: reader.read_array()?,
            },
            role,
            direction,
            status,
            tag: reader.read_array()?,
        };
        reader.read_zeroes(4)?;
        reader.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SnpInstallationOutcomeV1 {
    Succeeded = 1,
    Failed = 2,
    Aborted = 3,
    Indeterminate = 4,
}

impl SnpInstallationOutcomeV1 {
    fn decode(reader: &mut StrictReader<'_>) -> SnpCodecResult<Self> {
        match reader.read_u16()? {
            1 => Ok(Self::Succeeded),
            2 => Ok(Self::Failed),
            3 => Ok(Self::Aborted),
            4 => Ok(Self::Indeterminate),
            _ => Err(SnpCodecError::UnknownEnumValue),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpInstallationResultV1 {
    pub session: SnpSessionReferenceV1,
    pub role: SnpMaRoleV1,
    pub direction: SnpConfirmationDirectionV1,
    pub outcome: SnpInstallationOutcomeV1,
    pub raw_firmware_status: Option<u32>,
    pub installation_result_digest: [u8; 48],
}

impl SnpInstallationResultV1 {
    pub const MAGIC: [u8; 8] = *b"SNP-LM-I";
    pub const ENCODED_SIZE: usize = 136;

    fn validate(&self) -> SnpCodecResult<()> {
        if self.role != SnpMaRoleV1::Destination
            || self.direction != SnpConfirmationDirectionV1::DestinationToSource
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        let valid_status = match self.outcome {
            SnpInstallationOutcomeV1::Succeeded => self.raw_firmware_status == Some(0),
            SnpInstallationOutcomeV1::Failed => {
                matches!(self.raw_firmware_status, Some(status) if status != 0)
            }
            SnpInstallationOutcomeV1::Aborted => self.raw_firmware_status.is_none(),
            SnpInstallationOutcomeV1::Indeterminate => true,
        };
        if !valid_status
            || (self.outcome != SnpInstallationOutcomeV1::Succeeded
                && self.installation_result_digest != [0; 48])
        {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        self.validate()?;
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut writer = StrictWriter::new(&mut bytes);
        encode_header(
            &mut writer,
            &Self::MAGIC,
            SnpRecordTypeV1::InstallationResult,
            Self::ENCODED_SIZE as u32,
        )?;
        writer.write_u64(self.session.request_id)?;
        self.role.encode(&mut writer)?;
        writer.write_u8(self.direction as u8)?;
        writer.write_u16(self.outcome as u16)?;
        writer.write_bytes(&self.session.session_context_digest)?;
        writer.write_u8(u8::from(self.raw_firmware_status.is_some()))?;
        writer.write_zeroes(3)?;
        match self.raw_firmware_status {
            Some(status) => writer.write_u32(status)?,
            None => writer.write_u32(0)?,
        }
        writer.write_bytes(&self.installation_result_digest)?;
        writer.write_zeroes(4)?;
        if writer.written() != Self::ENCODED_SIZE {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut reader = StrictReader::new(bytes);
        decode_header(
            &mut reader,
            &Self::MAGIC,
            SnpRecordTypeV1::InstallationResult,
            Self::ENCODED_SIZE as u32,
        )?;
        let request_id = reader.read_u64()?;
        let role = SnpMaRoleV1::decode(&mut reader)?;
        let direction = SnpConfirmationDirectionV1::decode(&mut reader)?;
        let outcome = SnpInstallationOutcomeV1::decode(&mut reader)?;
        let session_context_digest = reader.read_array()?;
        let status_present = reader.read_u8()?;
        reader.read_zeroes(3)?;
        let raw_status = reader.read_u32()?;
        let raw_firmware_status = match status_present {
            0 if raw_status == 0 => None,
            1 => Some(raw_status),
            0 => return Err(SnpCodecError::NonCanonicalEncoding),
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let value = Self {
            session: SnpSessionReferenceV1 {
                request_id,
                session_context_digest,
            },
            role,
            direction,
            outcome,
            raw_firmware_status,
            installation_result_digest: reader.read_array()?,
        };
        reader.read_zeroes(4)?;
        reader.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpConfirmationVerificationErrorV1 {
    ConfirmationCryptographyUnavailable,
    TagMismatch,
    PersistedStateUnavailable,
    PersistedStateMismatch,
}

/// Must use the approved P0.10 inter-node V1 HMAC-SHA384 recipe and distinct
/// direction-specific keys, checking all frozen context/status inputs.
pub trait SnpConfirmationVerifierV1 {
    fn verify(
        &self,
        confirmation: &SnpConfirmationV1,
    ) -> Result<(), SnpConfirmationVerificationErrorV1>;
}

/// Before returning success, authenticate fresh P0.3 purpose-3 evidence for
/// the same tenant/destination MA/session and exact accepted persisted history,
/// and return its existing installation-result digest. A local installer return
/// or peer success assertion is not evidence. Task 12 owns the real provider.
pub trait SnpPersistedInstallationVerifierV1 {
    fn verify_success(
        &self,
        expected: &SnpSessionReferenceV1,
    ) -> Result<[u8; 48], SnpConfirmationVerificationErrorV1>;
}

#[derive(Debug)]
pub struct UnavailableSnpConfirmationVerifierV1;

impl SnpConfirmationVerifierV1 for UnavailableSnpConfirmationVerifierV1 {
    fn verify(
        &self,
        _confirmation: &SnpConfirmationV1,
    ) -> Result<(), SnpConfirmationVerificationErrorV1> {
        Err(SnpConfirmationVerificationErrorV1::ConfirmationCryptographyUnavailable)
    }
}

#[derive(Debug)]
pub struct UnavailableSnpPersistedInstallationVerifierV1;

impl SnpPersistedInstallationVerifierV1 for UnavailableSnpPersistedInstallationVerifierV1 {
    fn verify_success(
        &self,
        _expected: &SnpSessionReferenceV1,
    ) -> Result<[u8; 48], SnpConfirmationVerificationErrorV1> {
        Err(SnpConfirmationVerificationErrorV1::PersistedStateUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpConfirmationErrorV1 {
    Codec(SnpCodecError),
    SessionMismatch,
    DirectionMismatch,
    ProtocolStateViolation,
    PeerRejected,
    DestinationOutcome(SnpInstallationOutcomeV1),
    Verification(SnpConfirmationVerificationErrorV1),
    Incomplete,
}

impl SnpConfirmationErrorV1 {
    pub fn protocol_failure(self) -> SnpAuthorizationFailureV1 {
        match self {
            Self::Codec(error) => SnpKeyContributionV1::codec_failure(error),
            Self::SessionMismatch
            | Self::Verification(SnpConfirmationVerificationErrorV1::TagMismatch) => {
                SnpAuthorizationFailureV1::ReportDataBindingFailed
            }
            Self::Verification(SnpConfirmationVerificationErrorV1::PersistedStateMismatch) => {
                SnpAuthorizationFailureV1::ReportVerificationFailed
            }
            Self::Verification(_)
            | Self::DestinationOutcome(SnpInstallationOutcomeV1::Succeeded)
            | Self::DestinationOutcome(SnpInstallationOutcomeV1::Failed)
            | Self::DestinationOutcome(SnpInstallationOutcomeV1::Indeterminate) => {
                SnpAuthorizationFailureV1::InternalError
            }
            Self::DirectionMismatch
            | Self::ProtocolStateViolation
            | Self::PeerRejected
            | Self::DestinationOutcome(SnpInstallationOutcomeV1::Aborted)
            | Self::Incomplete => SnpAuthorizationFailureV1::ProtocolStateViolation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpConfirmationStateV1 {
    AwaitingDestinationConfirmation,
    AwaitingSourceConfirmation,
    AwaitingPersistedState,
    AwaitingInstallationResult,
    Complete,
    Aborted,
}

/// Operation-local transcript, including local and remote messages. Trusted
/// composition must first enforce P0.7/Task 10, policy/history, durable replay
/// admission and authenticated encrypted SPDM. This type proves none of them.
#[derive(Debug)]
pub struct SnpConfirmationSequenceV1 {
    expected: SnpSessionReferenceV1,
    state: SnpConfirmationStateV1,
    destination_result: Option<SnpInstallationResultV1>,
    verified_installation_digest: Option<[u8; 48]>,
}

impl SnpConfirmationSequenceV1 {
    pub fn new(expected: SnpSessionReferenceV1) -> Self {
        Self {
            expected,
            state: SnpConfirmationStateV1::AwaitingDestinationConfirmation,
            destination_result: None,
            verified_installation_digest: None,
        }
    }

    pub const fn state(&self) -> SnpConfirmationStateV1 {
        self.state
    }

    /// Diagnostics only. A recorded result, even success, is not readiness.
    pub fn recorded_destination_result(&self) -> Option<&SnpInstallationResultV1> {
        self.destination_result.as_ref()
    }

    pub fn abort(&mut self) {
        self.verified_installation_digest = None;
        self.state = SnpConfirmationStateV1::Aborted;
    }

    pub fn accept_confirmation(
        &mut self,
        direction: SnpConfirmationDirectionV1,
        bytes: &[u8],
        verifier: &dyn SnpConfirmationVerifierV1,
    ) -> Result<(), SnpConfirmationErrorV1> {
        let result = (|| {
            let record =
                SnpConfirmationV1::decode_exact(bytes).map_err(SnpConfirmationErrorV1::Codec)?;
            if record.session != self.expected {
                return Err(SnpConfirmationErrorV1::SessionMismatch);
            }
            if record.direction != direction {
                return Err(SnpConfirmationErrorV1::DirectionMismatch);
            }
            let next = match (self.state, direction) {
                (
                    SnpConfirmationStateV1::AwaitingDestinationConfirmation,
                    SnpConfirmationDirectionV1::DestinationToSource,
                ) => SnpConfirmationStateV1::AwaitingSourceConfirmation,
                (
                    SnpConfirmationStateV1::AwaitingSourceConfirmation,
                    SnpConfirmationDirectionV1::SourceToDestination,
                ) => SnpConfirmationStateV1::AwaitingPersistedState,
                _ => return Err(SnpConfirmationErrorV1::ProtocolStateViolation),
            };
            if record.status == SnpConfirmationStatusV1::Rejected {
                return Err(SnpConfirmationErrorV1::PeerRejected);
            }
            verifier
                .verify(&record)
                .map_err(SnpConfirmationErrorV1::Verification)?;
            self.state = next;
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }

    /// Authenticate persisted-state evidence before admitting a success result.
    /// The provider returns the existing P0.3 digest from verified actual state,
    /// never a digest copied from an unverified peer result.
    pub fn verify_persisted_state(
        &mut self,
        persisted: &dyn SnpPersistedInstallationVerifierV1,
    ) -> Result<(), SnpConfirmationErrorV1> {
        let result = (|| {
            if self.state != SnpConfirmationStateV1::AwaitingPersistedState {
                return Err(SnpConfirmationErrorV1::ProtocolStateViolation);
            }
            let digest = persisted
                .verify_success(&self.expected)
                .map_err(SnpConfirmationErrorV1::Verification)?;
            self.verified_installation_digest = Some(digest);
            self.state = SnpConfirmationStateV1::AwaitingInstallationResult;
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }

    pub fn accept_installation_result(
        &mut self,
        direction: SnpConfirmationDirectionV1,
        bytes: &[u8],
    ) -> Result<(), SnpConfirmationErrorV1> {
        let result = (|| {
            let record = SnpInstallationResultV1::decode_exact(bytes)
                .map_err(SnpConfirmationErrorV1::Codec)?;
            if record.session != self.expected {
                return Err(SnpConfirmationErrorV1::SessionMismatch);
            }
            if record.direction != direction {
                return Err(SnpConfirmationErrorV1::DirectionMismatch);
            }
            if matches!(
                self.state,
                SnpConfirmationStateV1::Complete | SnpConfirmationStateV1::Aborted
            ) {
                return Err(SnpConfirmationErrorV1::ProtocolStateViolation);
            }
            if record.outcome != SnpInstallationOutcomeV1::Succeeded {
                let outcome = record.outcome;
                self.destination_result = Some(record);
                return Err(SnpConfirmationErrorV1::DestinationOutcome(outcome));
            }
            if self.state != SnpConfirmationStateV1::AwaitingInstallationResult {
                return Err(SnpConfirmationErrorV1::ProtocolStateViolation);
            }
            if self.verified_installation_digest != Some(record.installation_result_digest) {
                return Err(SnpConfirmationErrorV1::Verification(
                    SnpConfirmationVerificationErrorV1::PersistedStateMismatch,
                ));
            }
            self.destination_result = Some(record);
            self.state = SnpConfirmationStateV1::Complete;
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }

    pub fn finish(
        mut self,
    ) -> Result<VerifiedDestinationInstallationResultV1, SnpConfirmationErrorV1> {
        if self.state != SnpConfirmationStateV1::Complete {
            return Err(SnpConfirmationErrorV1::Incomplete);
        }
        Ok(VerifiedDestinationInstallationResultV1 {
            result: self
                .destination_result
                .take()
                .ok_or(SnpConfirmationErrorV1::Incomplete)?,
        })
    }
}

/// Verification-boundary receipt, not source-side installation or permission
/// to report readiness. Task 12 must confirm both role-specific installations.
///
/// ```compile_fail
/// use pal::snp::confirmation::{
///     SnpInstallationResultV1, VerifiedDestinationInstallationResultV1,
/// };
/// fn forge(result: SnpInstallationResultV1) {
///     VerifiedDestinationInstallationResultV1 { result };
/// }
/// ```
///
/// ```compile_fail
/// use pal::snp::confirmation::VerifiedDestinationInstallationResultV1;
/// fn duplicate(result: VerifiedDestinationInstallationResultV1) { result.clone(); }
/// ```
#[derive(Debug)]
pub struct VerifiedDestinationInstallationResultV1 {
    result: SnpInstallationResultV1,
}

impl VerifiedDestinationInstallationResultV1 {
    pub const fn result(&self) -> &SnpInstallationResultV1 {
        &self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp::{purpose_binding::sha384, purpose_binding::PostInstallBindingV1};
    use core::cell::Cell;

    fn session() -> SnpSessionReferenceV1 {
        SnpSessionReferenceV1 {
            request_id: 0x0102_0304_0506_0708,
            session_context_digest: [0x44; 48],
        }
    }

    fn confirmation(direction: SnpConfirmationDirectionV1) -> SnpConfirmationV1 {
        let (role, tag) = match direction {
            SnpConfirmationDirectionV1::DestinationToSource => {
                (SnpMaRoleV1::Destination, [0xd1; 48])
            }
            SnpConfirmationDirectionV1::SourceToDestination => (SnpMaRoleV1::Source, [0xa1; 48]),
        };
        SnpConfirmationV1 {
            session: session(),
            role,
            direction,
            status: SnpConfirmationStatusV1::Confirmed,
            tag,
        }
    }

    fn success() -> SnpInstallationResultV1 {
        let binding = PostInstallBindingV1::after_successful_persistence(
            session().request_id,
            [0x11; 32],
            [0x22; 32],
            &[0x66; 64],
            0,
            true,
        )
        .unwrap();
        SnpInstallationResultV1 {
            session: session(),
            role: SnpMaRoleV1::Destination,
            direction: SnpConfirmationDirectionV1::DestinationToSource,
            outcome: SnpInstallationOutcomeV1::Succeeded,
            raw_firmware_status: Some(0),
            installation_result_digest: *binding.installation_result_digest(),
        }
    }

    fn failure(outcome: SnpInstallationOutcomeV1) -> SnpInstallationResultV1 {
        SnpInstallationResultV1 {
            outcome,
            raw_firmware_status: match outcome {
                SnpInstallationOutcomeV1::Failed => Some(0x35),
                SnpInstallationOutcomeV1::Aborted => None,
                SnpInstallationOutcomeV1::Indeterminate => Some(0),
                SnpInstallationOutcomeV1::Succeeded => panic!("not a failure"),
            },
            installation_result_digest: [0; 48],
            ..success()
        }
    }

    // Oracles for callback/state conformance, not HMAC or firmware verifiers.
    #[derive(Default)]
    struct TestVerifiers {
        confirmations: Cell<usize>,
        persistence: Cell<usize>,
    }

    impl SnpConfirmationVerifierV1 for TestVerifiers {
        fn verify(
            &self,
            record: &SnpConfirmationV1,
        ) -> Result<(), SnpConfirmationVerificationErrorV1> {
            self.confirmations.set(self.confirmations.get() + 1);
            if record.tag == confirmation(record.direction).tag {
                Ok(())
            } else {
                Err(SnpConfirmationVerificationErrorV1::TagMismatch)
            }
        }
    }

    impl SnpPersistedInstallationVerifierV1 for TestVerifiers {
        fn verify_success(
            &self,
            expected: &SnpSessionReferenceV1,
        ) -> Result<[u8; 48], SnpConfirmationVerificationErrorV1> {
            self.persistence.set(self.persistence.get() + 1);
            if expected == &session() {
                Ok(success().installation_result_digest)
            } else {
                Err(SnpConfirmationVerificationErrorV1::PersistedStateMismatch)
            }
        }
    }

    fn advance(sequence: &mut SnpConfirmationSequenceV1, count: usize, verifiers: &TestVerifiers) {
        for direction in [
            SnpConfirmationDirectionV1::DestinationToSource,
            SnpConfirmationDirectionV1::SourceToDestination,
        ]
        .into_iter()
        .take(count)
        {
            sequence
                .accept_confirmation(
                    direction,
                    &confirmation(direction).encode_exact().unwrap(),
                    verifiers,
                )
                .unwrap();
        }
    }

    #[test]
    fn confirmation_layout_is_exact_for_both_roles() {
        for direction in [
            SnpConfirmationDirectionV1::DestinationToSource,
            SnpConfirmationDirectionV1::SourceToDestination,
        ] {
            let record = confirmation(direction);
            let mut expected = [0; 128];
            expected[..8].copy_from_slice(b"SNP-LM-C");
            expected[8..16].copy_from_slice(&[1, 0, 6, 0, 128, 0, 0, 0]);
            expected[16..24].copy_from_slice(&session().request_id.to_le_bytes());
            expected[24] = record.role as u8;
            expected[25] = record.direction as u8;
            expected[26..28].copy_from_slice(&1u16.to_le_bytes());
            expected[28..76].fill(0x44);
            expected[76..124].copy_from_slice(&record.tag);
            assert_eq!(record.encode_exact().unwrap(), expected);
            assert_eq!(SnpConfirmationV1::decode_exact(&expected).unwrap(), record);
        }
    }

    #[test]
    fn installation_layout_and_existing_p03_digest_are_exact() {
        let record = success();
        let mut expected = [0; 136];
        expected[..8].copy_from_slice(b"SNP-LM-I");
        expected[8..16].copy_from_slice(&[1, 0, 7, 0, 136, 0, 0, 0]);
        expected[16..24].copy_from_slice(&session().request_id.to_le_bytes());
        expected[24..28].copy_from_slice(&[1, 1, 1, 0]);
        expected[28..76].fill(0x44);
        expected[76] = 1;
        expected[84..132].copy_from_slice(&record.installation_result_digest);
        assert_eq!(record.encode_exact().unwrap(), expected);
        assert_eq!(
            SnpInstallationResultV1::decode_exact(&expected).unwrap(),
            record
        );
    }

    #[test]
    fn independent_python_record_vectors_match() {
        for (bytes, expected) in [
            (
                confirmation(SnpConfirmationDirectionV1::DestinationToSource)
                    .encode_exact()
                    .unwrap()
                    .to_vec(),
                "7e03ad174eecbfe2238e5d933b8e21f24b9be62b8727c475a04a44ea23e94b4e4893b98f314348d8a29034bf64ba4d0c",
            ),
            (
                confirmation(SnpConfirmationDirectionV1::SourceToDestination)
                    .encode_exact()
                    .unwrap()
                    .to_vec(),
                "c90c2b2d117d2915fcffa196375eb0e7bd0f268452bb51859ea3c63cb96126b91e493e1270d464b27b20c4276e19307d",
            ),
            (
                success().encode_exact().unwrap().to_vec(),
                "01a9dba7d3336d4f08e4b9697e2008554682aea48551b34c178b5461e33fa05840cf1e715a19dad033b46d1aed2020b5",
            ),
            (
                failure(SnpInstallationOutcomeV1::Failed).encode_exact().unwrap().to_vec(),
                "0a4600d5cccad9e924738551a59c01ba90369d27f12520e857f48fb1e727ad89c355f531b31df2105fafc2ef65f923ba",
            ),
            (
                failure(SnpInstallationOutcomeV1::Aborted).encode_exact().unwrap().to_vec(),
                "87c0c3fe81b9430dbfad02c62101e2feeaaa043fb1c647a0602d2a1efef7c935e9b7e1737d4683c239d6f1548d787921",
            ),
            (
                failure(SnpInstallationOutcomeV1::Indeterminate).encode_exact().unwrap().to_vec(),
                "98ffb25c0d3e9e6d54dc2b6d450b16c01c3502cd7d3f5c97270b3b9f7f5dbf6f4c139573a42ba3f972bd5929b019219b",
            ),
        ] {
            let actual: String = sha384(&bytes).iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn every_truncation_and_trailing_byte_is_rejected() {
        let encoded = confirmation(SnpConfirmationDirectionV1::DestinationToSource)
            .encode_exact()
            .unwrap();
        for length in 0..encoded.len() {
            assert!(SnpConfirmationV1::decode_exact(&encoded[..length]).is_err());
        }
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(SnpConfirmationV1::decode_exact(&extended).is_err());
        let encoded = success().encode_exact().unwrap();
        for length in 0..encoded.len() {
            assert!(SnpInstallationResultV1::decode_exact(&encoded[..length]).is_err());
        }
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(SnpInstallationResultV1::decode_exact(&extended).is_err());
    }

    #[test]
    fn malformed_headers_enums_roles_and_reserved_bytes_are_rejected() {
        for offset in [0, 8, 9, 10, 12, 24, 25, 26, 124, 125, 126, 127] {
            let mut bytes = confirmation(SnpConfirmationDirectionV1::DestinationToSource)
                .encode_exact()
                .unwrap();
            bytes[offset] ^= 0x80;
            assert!(SnpConfirmationV1::decode_exact(&bytes).is_err(), "{offset}");
        }
        for offset in [
            0, 8, 9, 10, 12, 24, 25, 26, 76, 77, 78, 79, 80, 132, 133, 134, 135,
        ] {
            let mut bytes = success().encode_exact().unwrap();
            bytes[offset] ^= 0x80;
            assert!(
                SnpInstallationResultV1::decode_exact(&bytes).is_err(),
                "{offset}"
            );
        }
        let mut record = confirmation(SnpConfirmationDirectionV1::DestinationToSource);
        record.role = SnpMaRoleV1::Source;
        assert!(record.encode_exact().is_err());
        record.role = SnpMaRoleV1::Incoming;
        assert!(record.encode_exact().is_err());
        let mut record = success();
        record.role = SnpMaRoleV1::Source;
        assert!(record.encode_exact().is_err());
        record.role = SnpMaRoleV1::Destination;
        record.direction = SnpConfirmationDirectionV1::SourceToDestination;
        assert!(record.encode_exact().is_err());
    }

    #[test]
    fn rejection_and_firmware_status_encodings_are_canonical() {
        let mut rejection = confirmation(SnpConfirmationDirectionV1::DestinationToSource);
        rejection.status = SnpConfirmationStatusV1::Rejected;
        assert!(rejection.encode_exact().is_err());
        rejection.tag = [0; 48];
        assert_eq!(
            SnpConfirmationV1::decode_exact(&rejection.encode_exact().unwrap()).unwrap(),
            rejection
        );
        for status in [None, Some(1)] {
            let mut record = success();
            record.raw_firmware_status = status;
            assert!(record.encode_exact().is_err());
        }
        for outcome in [
            SnpInstallationOutcomeV1::Failed,
            SnpInstallationOutcomeV1::Aborted,
            SnpInstallationOutcomeV1::Indeterminate,
        ] {
            let record = failure(outcome);
            assert_eq!(
                SnpInstallationResultV1::decode_exact(&record.encode_exact().unwrap()).unwrap(),
                record
            );
            let mut bad_digest = record.clone();
            bad_digest.installation_result_digest[0] = 1;
            assert!(bad_digest.encode_exact().is_err());
        }
        let mut failed = failure(SnpInstallationOutcomeV1::Failed);
        for status in [None, Some(0)] {
            failed.raw_firmware_status = status;
            assert!(failed.encode_exact().is_err());
        }
        let mut aborted = failure(SnpInstallationOutcomeV1::Aborted);
        aborted.raw_firmware_status = Some(0);
        assert!(aborted.encode_exact().is_err());
        let mut bytes = failure(SnpInstallationOutcomeV1::Aborted)
            .encode_exact()
            .unwrap();
        bytes[80] = 1;
        assert!(SnpInstallationResultV1::decode_exact(&bytes).is_err());
    }

    #[test]
    fn optional_status_preserves_unknown_and_observed_zero_separately() {
        for status in [None, Some(0), Some(0x35), Some(u32::MAX)] {
            let mut record = failure(SnpInstallationOutcomeV1::Indeterminate);
            record.raw_firmware_status = status;
            assert_eq!(
                SnpInstallationResultV1::decode_exact(&record.encode_exact().unwrap()).unwrap(),
                record
            );
        }
    }

    #[test]
    fn successful_sequence_requires_two_tags_then_persisted_evidence() {
        let verifiers = TestVerifiers::default();
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        assert_eq!(
            sequence.state(),
            SnpConfirmationStateV1::AwaitingDestinationConfirmation
        );
        advance(&mut sequence, 2, &verifiers);
        assert_eq!(
            sequence.state(),
            SnpConfirmationStateV1::AwaitingPersistedState
        );
        sequence.verify_persisted_state(&verifiers).unwrap();
        assert_eq!(
            sequence.state(),
            SnpConfirmationStateV1::AwaitingInstallationResult
        );
        let expected = success();
        sequence
            .accept_installation_result(expected.direction, &expected.encode_exact().unwrap())
            .unwrap();
        assert_eq!(sequence.state(), SnpConfirmationStateV1::Complete);
        assert_eq!(verifiers.confirmations.get(), 2);
        assert_eq!(verifiers.persistence.get(), 1);
        assert_eq!(sequence.finish().unwrap().result(), &expected);
    }

    #[test]
    fn tag_mismatch_at_either_stage_aborts_without_resume() {
        for preceding in 0..=1 {
            let verifiers = TestVerifiers::default();
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            advance(&mut sequence, preceding, &verifiers);
            let direction = if preceding == 0 {
                SnpConfirmationDirectionV1::DestinationToSource
            } else {
                SnpConfirmationDirectionV1::SourceToDestination
            };
            let mut record = confirmation(direction);
            record.tag[0] ^= 1;
            assert_eq!(
                sequence.accept_confirmation(
                    direction,
                    &record.encode_exact().unwrap(),
                    &verifiers
                ),
                Err(SnpConfirmationErrorV1::Verification(
                    SnpConfirmationVerificationErrorV1::TagMismatch
                ))
            );
            assert_eq!(sequence.state(), SnpConfirmationStateV1::Aborted);
            assert!(sequence
                .accept_confirmation(
                    direction,
                    &confirmation(direction).encode_exact().unwrap(),
                    &verifiers
                )
                .is_err());
            assert!(sequence.finish().is_err());
        }
    }

    #[test]
    fn missing_confirmation_crypto_has_no_success_fallback() {
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        let direction = SnpConfirmationDirectionV1::DestinationToSource;
        let error = sequence
            .accept_confirmation(
                direction,
                &confirmation(direction).encode_exact().unwrap(),
                &UnavailableSnpConfirmationVerifierV1,
            )
            .unwrap_err();
        assert_eq!(
            error,
            SnpConfirmationErrorV1::Verification(
                SnpConfirmationVerificationErrorV1::ConfirmationCryptographyUnavailable
            )
        );
        assert_eq!(
            error.protocol_failure(),
            SnpAuthorizationFailureV1::InternalError
        );
        assert!(sequence.finish().is_err());
    }

    #[test]
    fn reflected_other_direction_tag_is_rejected() {
        for count in 0..=1 {
            let verifiers = TestVerifiers::default();
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            advance(&mut sequence, count, &verifiers);
            let (direction, other) = if count == 0 {
                (
                    SnpConfirmationDirectionV1::DestinationToSource,
                    SnpConfirmationDirectionV1::SourceToDestination,
                )
            } else {
                (
                    SnpConfirmationDirectionV1::SourceToDestination,
                    SnpConfirmationDirectionV1::DestinationToSource,
                )
            };
            let mut record = confirmation(direction);
            record.tag = confirmation(other).tag;
            assert_eq!(
                sequence.accept_confirmation(
                    direction,
                    &record.encode_exact().unwrap(),
                    &verifiers
                ),
                Err(SnpConfirmationErrorV1::Verification(
                    SnpConfirmationVerificationErrorV1::TagMismatch
                ))
            );
            assert!(sequence.finish().is_err());
        }
    }

    #[test]
    fn wrong_request_or_session_digest_fails_before_verification() {
        for field in 0..2 {
            let verifiers = TestVerifiers::default();
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            let mut record = confirmation(SnpConfirmationDirectionV1::DestinationToSource);
            if field == 0 {
                record.session.request_id ^= 1;
            } else {
                record.session.session_context_digest[0] ^= 1;
            }
            assert_eq!(
                sequence.accept_confirmation(
                    record.direction,
                    &record.encode_exact().unwrap(),
                    &verifiers
                ),
                Err(SnpConfirmationErrorV1::SessionMismatch)
            );
            assert_eq!(verifiers.confirmations.get(), 0);
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            advance(&mut sequence, 2, &verifiers);
            let mut result = success();
            result.session = record.session;
            assert_eq!(
                sequence
                    .accept_installation_result(result.direction, &result.encode_exact().unwrap(),),
                Err(SnpConfirmationErrorV1::SessionMismatch)
            );
            assert_eq!(verifiers.persistence.get(), 0);
            assert!(sequence.finish().is_err());
        }
    }

    #[test]
    fn trusted_direction_must_match_each_record() {
        let verifiers = TestVerifiers::default();
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        assert_eq!(
            sequence.accept_confirmation(
                SnpConfirmationDirectionV1::SourceToDestination,
                &confirmation(SnpConfirmationDirectionV1::DestinationToSource)
                    .encode_exact()
                    .unwrap(),
                &verifiers
            ),
            Err(SnpConfirmationErrorV1::DirectionMismatch)
        );
        assert_eq!(verifiers.confirmations.get(), 0);
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        advance(&mut sequence, 2, &verifiers);
        assert_eq!(
            sequence.accept_installation_result(
                SnpConfirmationDirectionV1::SourceToDestination,
                &success().encode_exact().unwrap(),
            ),
            Err(SnpConfirmationErrorV1::DirectionMismatch)
        );
        assert_eq!(verifiers.persistence.get(), 0);
    }

    #[test]
    fn reordered_or_duplicate_tags_abort_before_more_verification() {
        let verifiers = TestVerifiers::default();
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        let source = confirmation(SnpConfirmationDirectionV1::SourceToDestination);
        assert_eq!(
            sequence.accept_confirmation(
                source.direction,
                &source.encode_exact().unwrap(),
                &verifiers
            ),
            Err(SnpConfirmationErrorV1::ProtocolStateViolation)
        );
        assert_eq!(verifiers.confirmations.get(), 0);
        for count in 1..=2 {
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            advance(&mut sequence, count, &verifiers);
            let calls = verifiers.confirmations.get();
            let direction = if count == 1 {
                SnpConfirmationDirectionV1::DestinationToSource
            } else {
                SnpConfirmationDirectionV1::SourceToDestination
            };
            assert_eq!(
                sequence.accept_confirmation(
                    direction,
                    &confirmation(direction).encode_exact().unwrap(),
                    &verifiers
                ),
                Err(SnpConfirmationErrorV1::ProtocolStateViolation)
            );
            assert_eq!(verifiers.confirmations.get(), calls);
            assert!(sequence.finish().is_err());
        }
    }

    #[test]
    fn success_before_both_confirmations_is_never_admitted() {
        for count in 0..=1 {
            let verifiers = TestVerifiers::default();
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            advance(&mut sequence, count, &verifiers);
            let result = success();
            assert_eq!(
                sequence
                    .accept_installation_result(result.direction, &result.encode_exact().unwrap(),),
                Err(SnpConfirmationErrorV1::ProtocolStateViolation)
            );
            assert_eq!(verifiers.persistence.get(), 0);
            assert!(sequence.recorded_destination_result().is_none());
            assert!(sequence.finish().is_err());
        }
    }

    #[test]
    fn negative_results_terminate_early_without_success_only_evidence() {
        for count in 0..=3 {
            for outcome in [
                SnpInstallationOutcomeV1::Failed,
                SnpInstallationOutcomeV1::Aborted,
                SnpInstallationOutcomeV1::Indeterminate,
            ] {
                let verifiers = TestVerifiers::default();
                let mut sequence = SnpConfirmationSequenceV1::new(session());
                advance(&mut sequence, count.min(2), &verifiers);
                if count == 3 {
                    sequence.verify_persisted_state(&verifiers).unwrap();
                }
                let result = failure(outcome);
                assert_eq!(
                    sequence.accept_installation_result(
                        result.direction,
                        &result.encode_exact().unwrap(),
                    ),
                    Err(SnpConfirmationErrorV1::DestinationOutcome(outcome))
                );
                assert_eq!(sequence.state(), SnpConfirmationStateV1::Aborted);
                assert_eq!(sequence.recorded_destination_result(), Some(&result));
                assert_eq!(verifiers.persistence.get(), usize::from(count == 3));
                assert!(sequence.finish().is_err());
            }
        }
    }

    #[test]
    fn explicit_confirmation_rejection_does_not_invoke_hmac_verifier() {
        for count in 0..=1 {
            let verifiers = TestVerifiers::default();
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            advance(&mut sequence, count, &verifiers);
            let mut record = confirmation(if count == 0 {
                SnpConfirmationDirectionV1::DestinationToSource
            } else {
                SnpConfirmationDirectionV1::SourceToDestination
            });
            record.status = SnpConfirmationStatusV1::Rejected;
            record.tag = [0; 48];
            let calls = verifiers.confirmations.get();
            assert_eq!(
                sequence.accept_confirmation(
                    record.direction,
                    &record.encode_exact().unwrap(),
                    &verifiers
                ),
                Err(SnpConfirmationErrorV1::PeerRejected)
            );
            assert_eq!(verifiers.confirmations.get(), calls);
            assert!(sequence.finish().is_err());
        }
    }

    #[test]
    fn local_success_without_persisted_evidence_cannot_complete() {
        let verifiers = TestVerifiers::default();
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        advance(&mut sequence, 2, &verifiers);
        let result = success();
        assert_eq!(
            sequence.accept_installation_result(result.direction, &result.encode_exact().unwrap(),),
            Err(SnpConfirmationErrorV1::ProtocolStateViolation)
        );
        assert!(sequence.recorded_destination_result().is_none());
        assert!(sequence.finish().is_err());
    }

    #[test]
    fn missing_persisted_provider_prevents_result_admission() {
        let verifiers = TestVerifiers::default();
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        advance(&mut sequence, 2, &verifiers);
        assert_eq!(
            sequence.verify_persisted_state(&UnavailableSnpPersistedInstallationVerifierV1),
            Err(SnpConfirmationErrorV1::Verification(
                SnpConfirmationVerificationErrorV1::PersistedStateUnavailable
            ))
        );
        assert_eq!(sequence.state(), SnpConfirmationStateV1::Aborted);
        assert!(sequence
            .accept_installation_result(
                SnpConfirmationDirectionV1::DestinationToSource,
                &success().encode_exact().unwrap()
            )
            .is_err());
        assert!(sequence.finish().is_err());
    }

    #[test]
    fn persisted_verification_occurs_once_after_both_tags() {
        for count in 0..=2 {
            let verifiers = TestVerifiers::default();
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            advance(&mut sequence, count, &verifiers);
            if count == 2 {
                sequence.verify_persisted_state(&verifiers).unwrap();
                assert_eq!(
                    sequence.state(),
                    SnpConfirmationStateV1::AwaitingInstallationResult
                );
            }
            assert_eq!(
                sequence.verify_persisted_state(&verifiers),
                Err(SnpConfirmationErrorV1::ProtocolStateViolation)
            );
            assert_eq!(verifiers.persistence.get(), usize::from(count == 2));
            assert!(sequence.finish().is_err());
        }
    }

    #[test]
    fn substituted_installation_digest_is_rejected_by_persistence_boundary() {
        let verifiers = TestVerifiers::default();
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        advance(&mut sequence, 2, &verifiers);
        sequence.verify_persisted_state(&verifiers).unwrap();
        let mut result = success();
        result.installation_result_digest[0] ^= 1;
        assert_eq!(
            sequence.accept_installation_result(result.direction, &result.encode_exact().unwrap(),),
            Err(SnpConfirmationErrorV1::Verification(
                SnpConfirmationVerificationErrorV1::PersistedStateMismatch
            ))
        );
        assert_eq!(verifiers.persistence.get(), 1);
        assert!(sequence.finish().is_err());
    }

    #[test]
    fn cancellation_and_incomplete_sequences_never_yield_receipts() {
        for count in 0..=3 {
            let mut sequence = SnpConfirmationSequenceV1::new(session());
            let verifiers = TestVerifiers::default();
            advance(&mut sequence, count.min(2), &verifiers);
            if count == 3 {
                sequence.verify_persisted_state(&verifiers).unwrap();
            }
            if count >= 2 {
                sequence.abort();
                sequence.abort();
            }
            assert_eq!(
                sequence.finish().unwrap_err(),
                SnpConfirmationErrorV1::Incomplete
            );
        }
    }

    #[test]
    fn duplicate_result_never_overwrites_or_reverifies_terminal_result() {
        let verifiers = TestVerifiers::default();
        let mut sequence = SnpConfirmationSequenceV1::new(session());
        advance(&mut sequence, 2, &verifiers);
        sequence.verify_persisted_state(&verifiers).unwrap();
        let result = success();
        sequence
            .accept_installation_result(result.direction, &result.encode_exact().unwrap())
            .unwrap();
        let failure = failure(SnpInstallationOutcomeV1::Failed);
        assert_eq!(
            sequence
                .accept_installation_result(failure.direction, &failure.encode_exact().unwrap(),),
            Err(SnpConfirmationErrorV1::ProtocolStateViolation)
        );
        assert_eq!(verifiers.persistence.get(), 1);
        assert_eq!(sequence.recorded_destination_result(), Some(&result));
        assert!(sequence.finish().is_err());
    }

    #[test]
    fn seeded_codec_round_trips_preserve_all_fields() {
        for byte in 0u8..=255 {
            let mut record = confirmation(if byte % 2 == 0 {
                SnpConfirmationDirectionV1::SourceToDestination
            } else {
                SnpConfirmationDirectionV1::DestinationToSource
            });
            record.session.request_id = u64::from(byte) << 48;
            record.session.session_context_digest = [byte; 48];
            record.tag = [byte; 48];
            assert_eq!(
                SnpConfirmationV1::decode_exact(&record.encode_exact().unwrap()).unwrap(),
                record
            );
            let mut result = failure(SnpInstallationOutcomeV1::Failed);
            result.session = record.session;
            result.raw_firmware_status = Some(u32::from(byte) + 1);
            assert_eq!(
                SnpInstallationResultV1::decode_exact(&result.encode_exact().unwrap()).unwrap(),
                result
            );
        }
    }

    #[test]
    fn protocol_errors_never_map_to_success() {
        for error in [
            SnpConfirmationErrorV1::Codec(SnpCodecError::Truncated),
            SnpConfirmationErrorV1::SessionMismatch,
            SnpConfirmationErrorV1::DirectionMismatch,
            SnpConfirmationErrorV1::ProtocolStateViolation,
            SnpConfirmationErrorV1::PeerRejected,
            SnpConfirmationErrorV1::DestinationOutcome(SnpInstallationOutcomeV1::Succeeded),
            SnpConfirmationErrorV1::DestinationOutcome(SnpInstallationOutcomeV1::Failed),
            SnpConfirmationErrorV1::DestinationOutcome(SnpInstallationOutcomeV1::Aborted),
            SnpConfirmationErrorV1::DestinationOutcome(SnpInstallationOutcomeV1::Indeterminate),
            SnpConfirmationErrorV1::Verification(
                SnpConfirmationVerificationErrorV1::ConfirmationCryptographyUnavailable,
            ),
            SnpConfirmationErrorV1::Verification(SnpConfirmationVerificationErrorV1::TagMismatch),
            SnpConfirmationErrorV1::Verification(
                SnpConfirmationVerificationErrorV1::PersistedStateUnavailable,
            ),
            SnpConfirmationErrorV1::Verification(
                SnpConfirmationVerificationErrorV1::PersistedStateMismatch,
            ),
            SnpConfirmationErrorV1::Incomplete,
        ] {
            assert_ne!(error.protocol_failure(), SnpAuthorizationFailureV1::None);
        }
    }
}
