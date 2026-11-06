// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! V2 protected delivery/acceptance followed by correlated firmware outcomes.
//! Acceptance is neither HMAC key confirmation nor attested persistence.

use super::{
    direct_key::{
        read_header, read_session, write_header, write_session, MigrationKeyV2,
        MigrationSessionContextV2, SnpSessionReferenceV2,
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
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FirmwareCompletionOutcomeV2 {
    Completed = 1,
    NotApplied = 2,
    Unavailable = 3,
    Indeterminate = 4,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FirmwareCompletionEffectV2 {
    NotApplied = 0,
    Applied = 1,
    Partial = 2,
    Unknown = 3,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareCompletionRecordV2 {
    pub session: SnpSessionReferenceV2,
    pub role: SnpMaRoleV1,
    pub outcome: FirmwareCompletionOutcomeV2,
    pub effect: FirmwareCompletionEffectV2,
    pub raw_firmware_status: Option<u32>,
}
impl FirmwareCompletionRecordV2 {
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
                FirmwareCompletionOutcomeV2::Completed,
                FirmwareCompletionEffectV2::Applied,
                Some(0),
            ),
            Err(error) => {
                let effect = match error.effect() {
                    MigrationInstallEffectV1::NotApplied => FirmwareCompletionEffectV2::NotApplied,
                    MigrationInstallEffectV1::Partial => FirmwareCompletionEffectV2::Partial,
                    MigrationInstallEffectV1::Unknown => FirmwareCompletionEffectV2::Unknown,
                };
                let outcome = if error.failure() == MigrationInstallFailureV1::Unavailable {
                    FirmwareCompletionOutcomeV2::Unavailable
                } else if effect == FirmwareCompletionEffectV2::NotApplied {
                    FirmwareCompletionOutcomeV2::NotApplied
                } else {
                    FirmwareCompletionOutcomeV2::Indeterminate
                };
                (outcome, effect, error.firmware_status())
            }
        };
        Ok(Self {
            session: correlation.session().clone(),
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
            FirmwareCompletionOutcomeV2::Completed => {
                self.effect == FirmwareCompletionEffectV2::Applied
                    && self.raw_firmware_status == Some(0)
            }
            FirmwareCompletionOutcomeV2::Unavailable => {
                self.effect == FirmwareCompletionEffectV2::NotApplied
                    && self.raw_firmware_status.is_none()
            }
            FirmwareCompletionOutcomeV2::NotApplied => {
                self.effect == FirmwareCompletionEffectV2::NotApplied
                    && self.raw_firmware_status != Some(0)
            }
            FirmwareCompletionOutcomeV2::Indeterminate => matches!(
                self.effect,
                FirmwareCompletionEffectV2::Partial | FirmwareCompletionEffectV2::Unknown
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
        write_header(&mut w, b"SNP-LM-F", 12, Self::ENCODED_SIZE)?;
        write_session(&mut w, &self.session)?;
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
        read_header(&mut r, b"SNP-LM-F", 12, Self::ENCODED_SIZE)?;
        let session = read_session(&mut r)?;
        let role = match r.read_u8()? {
            0 => SnpMaRoleV1::Source,
            1 => SnpMaRoleV1::Destination,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let outcome = match r.read_u8()? {
            1 => FirmwareCompletionOutcomeV2::Completed,
            2 => FirmwareCompletionOutcomeV2::NotApplied,
            3 => FirmwareCompletionOutcomeV2::Unavailable,
            4 => FirmwareCompletionOutcomeV2::Indeterminate,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        let effect = match r.read_u8()? {
            0 => FirmwareCompletionEffectV2::NotApplied,
            1 => FirmwareCompletionEffectV2::Applied,
            2 => FirmwareCompletionEffectV2::Partial,
            3 => FirmwareCompletionEffectV2::Unknown,
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

/// Explicit accepted delivery, authenticated only by the protected peer channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAcceptanceV2 {
    pub session: SnpSessionReferenceV2,
}
impl KeyAcceptanceV2 {
    pub const ENCODED_SIZE: usize = 80;
    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut w = StrictWriter::new(&mut bytes);
        write_header(&mut w, b"SNP-LM-A", 11, Self::ENCODED_SIZE)?;
        write_session(&mut w, &self.session)?;
        w.write_u8(SnpMaRoleV1::Destination as u8)?;
        w.write_u8(1)?;
        w.write_zeroes(6)?;
        Ok(bytes)
    }
    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut r = StrictReader::new(bytes);
        read_header(&mut r, b"SNP-LM-A", 11, Self::ENCODED_SIZE)?;
        let session = read_session(&mut r)?;
        if r.read_u8()? != SnpMaRoleV1::Destination as u8 || r.read_u8()? != 1 {
            return Err(SnpCodecError::NonCanonicalEncoding);
        }
        r.read_zeroes(6)?;
        r.finish()?;
        Ok(Self { session })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InstallSessionControlKindV2 {
    PollDestinationCompletion = 1,
    AcknowledgeSourceCompletion = 2,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSessionControlV2 {
    pub session: SnpSessionReferenceV2,
    pub kind: InstallSessionControlKindV2,
}
impl InstallSessionControlV2 {
    pub const ENCODED_SIZE: usize = 80;
    pub fn encode_exact(&self) -> SnpCodecResult<[u8; Self::ENCODED_SIZE]> {
        let mut bytes = [0; Self::ENCODED_SIZE];
        let mut w = StrictWriter::new(&mut bytes);
        write_header(&mut w, b"SNP-LM-Q", 13, Self::ENCODED_SIZE)?;
        write_session(&mut w, &self.session)?;
        w.write_u8(self.kind as u8)?;
        w.write_zeroes(7)?;
        Ok(bytes)
    }
    pub fn decode_exact(bytes: &[u8]) -> SnpCodecResult<Self> {
        let mut r = StrictReader::new(bytes);
        read_header(&mut r, b"SNP-LM-Q", 13, Self::ENCODED_SIZE)?;
        let session = read_session(&mut r)?;
        let kind = match r.read_u8()? {
            1 => InstallSessionControlKindV2::PollDestinationCompletion,
            2 => InstallSessionControlKindV2::AcknowledgeSourceCompletion,
            _ => return Err(SnpCodecError::UnknownEnumValue),
        };
        r.read_zeroes(7)?;
        r.finish()?;
        Ok(Self { session, kind })
    }
}

enum InstallRecordV2 {
    Key(MigrationKeyV2),
    Acceptance(KeyAcceptanceV2),
    Control(InstallSessionControlV2),
    Completion(FirmwareCompletionRecordV2),
}

/// Minted only after successful I/O and current-binding checks by the promoted
/// peer boundary. A decoded frame or public session reference cannot mint it.
///
/// ```compile_fail
/// use pal::snp::direct_exchange::ProtectedInstallRecordV2;
/// let forged = ProtectedInstallRecordV2 {};
/// ```
pub struct ProtectedInstallRecordV2 {
    opcode: u8,
    record: InstallRecordV2,
    th1: [u8; 48],
    local_role: MigrationRole,
}
impl ProtectedInstallRecordV2 {
    pub(crate) fn from_peer(
        opcode: u8,
        payload: &[u8],
        context: &MigrationSessionContextV2,
    ) -> SnpCodecResult<Self> {
        let record = match opcode {
            0x30 => {
                let mut bytes = Zeroizing::new(payload.to_vec());
                let key = MigrationKeyV2::decode_delivery(&mut bytes)?;
                if !key.matches(context) {
                    return Err(SnpCodecError::NonCanonicalEncoding);
                }
                InstallRecordV2::Key(key)
            }
            0x31 => {
                let value = KeyAcceptanceV2::decode_exact(payload)?;
                if &value.session != context.reference() {
                    return Err(SnpCodecError::NonCanonicalEncoding);
                }
                InstallRecordV2::Acceptance(value)
            }
            0x32 | 0x35 => {
                let value = InstallSessionControlV2::decode_exact(payload)?;
                let kind = if opcode == 0x32 {
                    InstallSessionControlKindV2::PollDestinationCompletion
                } else {
                    InstallSessionControlKindV2::AcknowledgeSourceCompletion
                };
                if &value.session != context.reference() || value.kind != kind {
                    return Err(SnpCodecError::NonCanonicalEncoding);
                }
                InstallRecordV2::Control(value)
            }
            0x33 | 0x34 => {
                let value = FirmwareCompletionRecordV2::decode_exact(payload)?;
                let role = if opcode == 0x33 {
                    SnpMaRoleV1::Destination
                } else {
                    SnpMaRoleV1::Source
                };
                if &value.session != context.reference() || value.role != role {
                    return Err(SnpCodecError::NonCanonicalEncoding);
                }
                InstallRecordV2::Completion(value)
            }
            _ => return Err(SnpCodecError::UnknownRecordType),
        };
        Ok(Self {
            opcode,
            record,
            th1: context.source_context().th1,
            local_role: context.role(),
        })
    }
}

/// Observes both local sends and peer receives in the exact protected transcript.
pub struct InstallExchangeSequenceV2 {
    context: MigrationSessionContextV2,
    stage: u8,
}
impl InstallExchangeSequenceV2 {
    pub fn new(context: &MigrationSessionContextV2) -> Self {
        Self {
            context: context.clone(),
            stage: 0,
        }
    }
    pub fn abort(&mut self) {
        self.stage = 255;
    }
    pub fn observe(
        &mut self,
        record: ProtectedInstallRecordV2,
    ) -> Result<Option<MigrationKeyV2>, HostControlErrorV1> {
        let result = (|| {
            if self.stage >= 6
                || record.opcode != 0x30 + self.stage
                || record.th1 != self.context.source_context().th1
                || record.local_role != self.context.role()
            {
                return Err(HostControlErrorV1::InvalidState);
            }
            let key = match record.record {
                InstallRecordV2::Key(key) => {
                    if !key.matches(&self.context) {
                        return Err(HostControlErrorV1::CorrelationMismatch);
                    }
                    Some(key)
                }
                InstallRecordV2::Acceptance(value) => {
                    if &value.session != self.context.reference() {
                        return Err(HostControlErrorV1::CorrelationMismatch);
                    }
                    None
                }
                InstallRecordV2::Control(value) => {
                    if &value.session != self.context.reference() {
                        return Err(HostControlErrorV1::CorrelationMismatch);
                    }
                    None
                }
                InstallRecordV2::Completion(value) => {
                    if &value.session != self.context.reference() {
                        return Err(HostControlErrorV1::CorrelationMismatch);
                    }
                    if value.outcome != FirmwareCompletionOutcomeV2::Completed {
                        return Err(HostControlErrorV1::PeerInstallationV2 {
                            outcome: value.outcome,
                            effect: value.effect,
                            raw_firmware_status: value.raw_firmware_status,
                        });
                    }
                    None
                }
            };
            self.stage += 1;
            Ok(key)
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }
    pub fn accepted_session(&self) -> Result<AcceptedInstallSessionV2, HostControlErrorV1> {
        if !(2..=6).contains(&self.stage) {
            return Err(HostControlErrorV1::InvalidState);
        }
        Ok(AcceptedInstallSessionV2 {
            session: self.context.reference().clone(),
            destination_completed: self.stage >= 4,
            authorization_digest: *self.context.authorization_digest(),
            local_role: self.context.role(),
        })
    }
    pub fn finish(self) -> Result<CompletedInstallExchangeV2, HostControlErrorV1> {
        if self.stage != 6 {
            return Err(HostControlErrorV1::InvalidState);
        }
        Ok(CompletedInstallExchangeV2 {
            session: self.context.reference().clone(),
            local_role: self.context.role(),
            authorization_digest: *self.context.authorization_digest(),
        })
    }
}

/// Protected acceptance, NOT key-possession proof or firmware success.
///
/// ```compile_fail
/// use pal::snp::direct_exchange::AcceptedInstallSessionV2;
/// let forged = AcceptedInstallSessionV2 {};
/// ```
pub struct AcceptedInstallSessionV2 {
    session: SnpSessionReferenceV2,
    destination_completed: bool,
    authorization_digest: [u8; 48],
    local_role: MigrationRole,
}
impl AcceptedInstallSessionV2 {
    pub fn session(&self) -> &SnpSessionReferenceV2 {
        &self.session
    }
    pub fn authorization_digest(&self) -> &[u8; 48] {
        &self.authorization_digest
    }
    pub fn permits_installation(&self, role: MigrationRole) -> bool {
        role == self.local_role
            && (role == MigrationRole::Destination || self.destination_completed)
    }
}

/// Correlated firmware observations, not attested persistence.
///
/// ```compile_fail
/// use pal::snp::direct_exchange::CompletedInstallExchangeV2;
/// fn duplicate(receipt: CompletedInstallExchangeV2) { receipt.clone(); }
/// ```
pub struct CompletedInstallExchangeV2 {
    session: SnpSessionReferenceV2,
    local_role: MigrationRole,
    authorization_digest: [u8; 48],
}
impl CompletedInstallExchangeV2 {
    pub fn session(&self) -> &SnpSessionReferenceV2 {
        &self.session
    }
    pub fn local_role(&self) -> MigrationRole {
        self.local_role
    }
    pub fn authorization_digest(&self) -> &[u8; 48] {
        &self.authorization_digest
    }
}

#[cfg(test)]
pub(crate) mod tests;
