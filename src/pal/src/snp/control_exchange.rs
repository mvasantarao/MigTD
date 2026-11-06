// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Superseded, test-only T4.12 V1 schedule. Firmware observations are not the
//! frozen P0.8 persisted-state record, attestation or automatic readiness.

use super::{
    confirmation::{
        SnpConfirmationDirectionV1, SnpConfirmationStatusV1, SnpConfirmationV1,
        SnpConfirmationVerifierV1, SnpSessionReferenceV1,
    },
    host_control::HostControlErrorV1,
    migration_install::{
        MigrationInstallCompletionV1, MigrationInstallEffectV1, MigrationInstallErrorV1,
        MigrationInstallFailureV1, MigrationInstallRequestV1,
    },
    report_data_context::SnpMaRoleV1,
    wire::{SnpCodecError, SnpCodecResult, StrictReader, StrictWriter},
};
use crate::types::MigrationRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FirmwareCompletionOutcomeV1 {
    Completed = 1,
    NotApplied = 2,
    Unavailable = 3,
    Indeterminate = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FirmwareCompletionEffectV1 {
    NotApplied = 0,
    Applied = 1,
    Partial = 2,
    Unknown = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareCompletionRecordV1 {
    pub session: SnpSessionReferenceV1,
    pub role: SnpMaRoleV1,
    pub outcome: FirmwareCompletionOutcomeV1,
    pub effect: FirmwareCompletionEffectV1,
    pub raw_firmware_status: Option<u32>,
}

fn header(
    w: &mut StrictWriter<'_>,
    magic: &[u8; 8],
    kind: u16,
    length: usize,
) -> SnpCodecResult<()> {
    w.write_bytes(magic)?;
    w.write_u16(1)?;
    w.write_u16(kind)?;
    w.write_u32(length as u32)
}
fn read_header(
    r: &mut StrictReader<'_>,
    magic: &[u8; 8],
    kind: u16,
    length: usize,
) -> SnpCodecResult<()> {
    if &r.read_array::<8>()? != magic {
        return Err(SnpCodecError::InvalidMagic);
    }
    if r.read_u16()? != 1 {
        return Err(SnpCodecError::UnsupportedVersion);
    }
    if r.read_u16()? != kind {
        return Err(SnpCodecError::UnknownRecordType);
    }
    if r.read_u32()? as usize != length {
        return Err(SnpCodecError::InvalidLength);
    }
    Ok(())
}
fn session(w: &mut StrictWriter<'_>, value: &SnpSessionReferenceV1) -> SnpCodecResult<()> {
    w.write_u64(value.request_id)?;
    w.write_bytes(&value.session_context_digest)
}
fn read_session(r: &mut StrictReader<'_>) -> SnpCodecResult<SnpSessionReferenceV1> {
    Ok(SnpSessionReferenceV1 {
        request_id: r.read_u64()?,
        session_context_digest: r.read_array()?,
    })
}

impl FirmwareCompletionRecordV1 {
    pub const ENCODED_SIZE: usize = 88;
    pub fn from_local(
        request: &MigrationInstallRequestV1<'_>,
        result: Result<&MigrationInstallCompletionV1, &MigrationInstallErrorV1>,
    ) -> Result<Self, HostControlErrorV1> {
        let correlation = match result {
            Ok(value) => value.correlation(),
            Err(error) => error.correlation(),
        };
        if correlation != &request.correlation() {
            return Err(HostControlErrorV1::CorrelationMismatch);
        }
        let (outcome, effect, raw_firmware_status) = match result {
            Ok(_) => (
                FirmwareCompletionOutcomeV1::Completed,
                FirmwareCompletionEffectV1::Applied,
                Some(0),
            ),
            Err(error) => {
                let effect = match error.effect() {
                    MigrationInstallEffectV1::NotApplied => FirmwareCompletionEffectV1::NotApplied,
                    MigrationInstallEffectV1::Partial => FirmwareCompletionEffectV1::Partial,
                    MigrationInstallEffectV1::Unknown => FirmwareCompletionEffectV1::Unknown,
                };
                let outcome = if error.failure() == MigrationInstallFailureV1::Unavailable {
                    FirmwareCompletionOutcomeV1::Unavailable
                } else if effect == FirmwareCompletionEffectV1::NotApplied {
                    FirmwareCompletionOutcomeV1::NotApplied
                } else {
                    FirmwareCompletionOutcomeV1::Indeterminate
                };
                (outcome, effect, error.firmware_status())
            }
        };
        Ok(Self {
            session: SnpSessionReferenceV1 {
                request_id: correlation.session().request_id,
                session_context_digest: correlation.session().session_context_digest,
            },
            role: match correlation.operation().role {
                MigrationRole::Source => SnpMaRoleV1::Source,
                MigrationRole::Destination => SnpMaRoleV1::Destination,
            },
            outcome,
            effect,
            raw_firmware_status,
        })
    }

    fn validate(&self) -> SnpCodecResult<()> {
        let valid = match self.outcome {
            FirmwareCompletionOutcomeV1::Completed => {
                self.effect == FirmwareCompletionEffectV1::Applied
                    && self.raw_firmware_status == Some(0)
            }
            FirmwareCompletionOutcomeV1::Unavailable => {
                self.effect == FirmwareCompletionEffectV1::NotApplied
                    && self.raw_firmware_status.is_none()
            }
            FirmwareCompletionOutcomeV1::NotApplied => {
                self.effect == FirmwareCompletionEffectV1::NotApplied
                    && self.raw_firmware_status != Some(0)
            }
            FirmwareCompletionOutcomeV1::Indeterminate => matches!(
                self.effect,
                FirmwareCompletionEffectV1::Partial | FirmwareCompletionEffectV1::Unknown
            ),
        };
        if !valid || !matches!(self.role, SnpMaRoleV1::Source | SnpMaRoleV1::Destination) {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        Ok(())
    }

    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        self.validate()?;
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut w = StrictWriter::new(&mut bytes);
        header(&mut w, b"SNP-LM-F", 8, Self::ENCODED_SIZE)?;
        session(&mut w, &self.session)?;
        w.write_u8(self.role as u8)?;
        w.write_u8(self.outcome as u8)?;
        w.write_u8(self.effect as u8)?;
        w.write_u8(u8::from(self.raw_firmware_status.is_some()))?;
        w.write_u32(self.raw_firmware_status.unwrap_or(0))?;
        w.write_zeroes(8)?;
        Ok(bytes)
    }

    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut r = StrictReader::new(bytes);
        read_header(&mut r, b"SNP-LM-F", 8, Self::ENCODED_SIZE)?;
        let session = read_session(&mut r)?;
        let role = match r.read_u8()? {
            0 => SnpMaRoleV1::Source,
            1 => SnpMaRoleV1::Destination,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let outcome = match r.read_u8()? {
            1 => FirmwareCompletionOutcomeV1::Completed,
            2 => FirmwareCompletionOutcomeV1::NotApplied,
            3 => FirmwareCompletionOutcomeV1::Unavailable,
            4 => FirmwareCompletionOutcomeV1::Indeterminate,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let effect = match r.read_u8()? {
            0 => FirmwareCompletionEffectV1::NotApplied,
            1 => FirmwareCompletionEffectV1::Applied,
            2 => FirmwareCompletionEffectV1::Partial,
            3 => FirmwareCompletionEffectV1::Unknown,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let present = r.read_u8()?;
        let raw = r.read_u32()?;
        let raw_firmware_status = match present {
            0 if raw == 0 => None,
            1 => Some(raw),
            _ => return Err(SnpCodecError::NonCanonicalEncoding),
        };
        r.read_zeroes(8)?;
        r.finish()?;
        let value = Self {
            session,
            role,
            outcome,
            effect,
            raw_firmware_status,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InstallSessionControlKindV1 {
    PollDestinationConfirmation = 1,
    AcknowledgeSourceCompletion = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSessionControlV1 {
    pub session: SnpSessionReferenceV1,
    pub kind: InstallSessionControlKindV1,
}
impl InstallSessionControlV1 {
    pub const ENCODED_SIZE: usize = 80;
    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut w = StrictWriter::new(&mut bytes);
        header(&mut w, b"SNP-LM-Q", 9, Self::ENCODED_SIZE)?;
        session(&mut w, &self.session)?;
        w.write_u8(self.kind as u8)?;
        w.write_zeroes(7)?;
        Ok(bytes)
    }
    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut r = StrictReader::new(bytes);
        read_header(&mut r, b"SNP-LM-Q", 9, Self::ENCODED_SIZE)?;
        let session = read_session(&mut r)?;
        let kind = match r.read_u8()? {
            1 => InstallSessionControlKindV1::PollDestinationConfirmation,
            2 => InstallSessionControlKindV1::AcknowledgeSourceCompletion,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        r.read_zeroes(7)?;
        r.finish()?;
        Ok(Self { session, kind })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallExchangeRequestV1 {
    Poll(InstallSessionControlV1),
    SourceConfirmation(SnpConfirmationV1),
    SourceCompletion(FirmwareCompletionRecordV1),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallExchangeResponseV1 {
    DestinationConfirmation(SnpConfirmationV1),
    DestinationCompletion(FirmwareCompletionRecordV1),
    Acknowledgement(InstallSessionControlV1),
}

/// One transcript for both local and remote records, over an independently
/// authenticated/encrypted inter-node session. This is not a session factory.
pub struct InstallExchangeSequenceV1 {
    expected: SnpSessionReferenceV1,
    stage: u8,
    pending: bool,
}
impl InstallExchangeSequenceV1 {
    pub fn new(expected: SnpSessionReferenceV1) -> Self {
        Self {
            expected,
            stage: 0,
            pending: false,
        }
    }
    pub fn abort(&mut self) {
        self.stage = 255;
        self.pending = false;
    }

    pub fn begin_request(
        &mut self,
        request: &InstallExchangeRequestV1,
        verifier: &dyn SnpConfirmationVerifierV1,
    ) -> Result<(), HostControlErrorV1> {
        let result = (|| {
            if self.pending {
                return Err(HostControlErrorV1::InvalidState);
            }
            match (self.stage, request) {
                (0, InstallExchangeRequestV1::Poll(control))
                    if control.session == self.expected
                        && control.kind
                            == InstallSessionControlKindV1::PollDestinationConfirmation => {}
                (1, InstallExchangeRequestV1::SourceConfirmation(record)) => self.confirm(
                    record,
                    SnpConfirmationDirectionV1::SourceToDestination,
                    verifier,
                )?,
                (2, InstallExchangeRequestV1::SourceCompletion(record)) => {
                    self.completion(record, SnpMaRoleV1::Source)?
                }
                _ => return Err(HostControlErrorV1::InvalidState),
            }
            self.pending = true;
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }

    pub fn complete_response(
        &mut self,
        response: &InstallExchangeResponseV1,
        verifier: &dyn SnpConfirmationVerifierV1,
    ) -> Result<(), HostControlErrorV1> {
        let result = (|| {
            if !self.pending {
                return Err(HostControlErrorV1::InvalidState);
            }
            match (self.stage, response) {
                (0, InstallExchangeResponseV1::DestinationConfirmation(record)) => self.confirm(
                    record,
                    SnpConfirmationDirectionV1::DestinationToSource,
                    verifier,
                )?,
                (1, InstallExchangeResponseV1::DestinationCompletion(record)) => {
                    self.completion(record, SnpMaRoleV1::Destination)?
                }
                (2, InstallExchangeResponseV1::Acknowledgement(control))
                    if control.session == self.expected
                        && control.kind
                            == InstallSessionControlKindV1::AcknowledgeSourceCompletion => {}
                _ => return Err(HostControlErrorV1::InvalidState),
            }
            self.stage += 1;
            self.pending = false;
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }

    fn confirm(
        &self,
        record: &SnpConfirmationV1,
        direction: SnpConfirmationDirectionV1,
        verifier: &dyn SnpConfirmationVerifierV1,
    ) -> Result<(), HostControlErrorV1> {
        record.encode_exact()?;
        if record.session != self.expected
            || record.direction != direction
            || record.status != SnpConfirmationStatusV1::Confirmed
        {
            return Err(HostControlErrorV1::CorrelationMismatch);
        }
        verifier
            .verify(record)
            .map_err(HostControlErrorV1::Confirmation)
    }
    fn completion(
        &self,
        record: &FirmwareCompletionRecordV1,
        role: SnpMaRoleV1,
    ) -> Result<(), HostControlErrorV1> {
        record.validate()?;
        if record.session != self.expected || record.role != role {
            return Err(HostControlErrorV1::CorrelationMismatch);
        }
        if record.outcome != FirmwareCompletionOutcomeV1::Completed {
            return Err(HostControlErrorV1::PeerInstallation {
                outcome: record.outcome,
                effect: record.effect,
                raw_firmware_status: record.raw_firmware_status,
            });
        }
        Ok(())
    }
    pub fn finish(self) -> Result<CompletedInstallExchangeV1, HostControlErrorV1> {
        if self.stage != 3 || self.pending {
            return Err(HostControlErrorV1::InvalidState);
        }
        Ok(CompletedInstallExchangeV1 {
            session: self.expected,
        })
    }
    pub fn confirmed_session(&self) -> Result<ConfirmedInstallSessionV1, HostControlErrorV1> {
        if !((self.stage == 1 && self.pending) || self.stage == 2 || self.stage == 3) {
            return Err(HostControlErrorV1::InvalidState);
        }
        Ok(ConfirmedInstallSessionV1 {
            session: self.expected.clone(),
            destination_completed: self.stage >= 2,
        })
    }
}

/// Verified directional confirmations, not policy or active-session authority.
///
/// ```compile_fail
/// use pal::snp::control_exchange::ConfirmedInstallSessionV1;
/// let forged = ConfirmedInstallSessionV1 {};
/// ```
pub struct ConfirmedInstallSessionV1 {
    session: SnpSessionReferenceV1,
    destination_completed: bool,
}
impl ConfirmedInstallSessionV1 {
    pub const fn session(&self) -> &SnpSessionReferenceV1 {
        &self.session
    }
    pub fn permits_installation(&self, role: MigrationRole) -> bool {
        role == MigrationRole::Destination || self.destination_completed
    }
}

/// Successful correlated firmware-completion exchange, not attested persistence
/// or a substitute for policy/replay/current-firmware checks.
///
/// ```compile_fail
/// use pal::snp::control_exchange::CompletedInstallExchangeV1;
/// fn duplicate(receipt: CompletedInstallExchangeV1) { receipt.clone(); }
/// ```
pub struct CompletedInstallExchangeV1 {
    session: SnpSessionReferenceV1,
}
impl CompletedInstallExchangeV1 {
    pub const fn session(&self) -> &SnpSessionReferenceV1 {
        &self.session
    }
}

#[cfg(test)]
mod tests;
