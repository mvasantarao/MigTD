// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg(any(feature = "spdm_attestation", feature = "SnpEmu"))]

#[cfg(feature = "SnpEmu")]
mod snp_vdm;
#[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
mod spdm_rebind;
mod spdm_req;
pub(crate) mod spdm_rsp;
mod spdm_vdm;
#[cfg(test)]
mod tests;
mod vmcall_msg;

use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use codec::Codec;
use codec::Reader;
use codec::Writer;
use log::error;
use spdmlib::common::{SpdmContext, SpdmDeviceIo};
use spdmlib::error::*;
use spin::Mutex;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use async_io::AsyncRead;
use async_io::AsyncWrite;
#[cfg(feature = "SnpEmu")]
pub use snp_vdm::*;
#[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
pub use spdm_rebind::spdm_requester_rebind_old;
#[cfg(all(feature = "main", feature = "policy_v2", feature = "vmcall-raw"))]
pub use spdm_rebind::spdm_responder_rebind_new;
pub use spdm_req::spdm_requester;
pub use spdm_req::spdm_requester_transfer_msk;
pub use spdm_rsp::spdm_responder;
pub use spdm_rsp::spdm_responder_transfer_msk;

pub use spdm_vdm::*;

#[cfg(not(feature = "SnpEmu"))]
use crate::migration::MigtdMigrationInformation;
#[cfg(feature = "SnpEmu")]
use crate::runtime::snp::legacy::LegacyAppContext as SpdmAppContextData;
use crate::spdm::vmcall_msg::VMCALL_SPDM_MESSAGE_HEADER_SIZE;
use crate::status::MigrationResult;

pub(crate) type SpdmDeviceIoArc<T> = Arc<Mutex<MigtdTransport<T>>>;
pub struct MigtdTransport<T: AsyncRead + AsyncWrite + Unpin + Send> {
    pub transport: T,
}

pub(crate) fn teardown_session(context: &mut SpdmContext, session_id: u32) {
    if let Some(session) = context.get_session_via_id(session_id) {
        session.teardown();
    }
}

pub(crate) fn teardown_sessions(context: &mut SpdmContext) {
    // FINISH clears last_session_id while the established session still holds keys.
    // Each context belongs to one exchange, so retire every slot before shutdown.
    for session in &mut context.session {
        session.teardown();
    }
}

#[async_trait]
impl<T: AsyncRead + AsyncWrite + Unpin + Send> SpdmDeviceIo for MigtdTransport<T> {
    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        let mut sent = 0;
        while sent < buffer.len() {
            match self.transport.write(&buffer[sent..]).await {
                Ok(len) => {
                    // Fail closed when the VMM-mediated transport reports
                    // success without progress to avoid an infinite loop.
                    if len == 0 {
                        log::error!("SPDM MigtdTransport::send: zero-length transport write\n");
                        return Err(SPDM_STATUS_SEND_FAIL);
                    }
                    sent += len;
                }
                // ConnectionAborted maps from VmcallRawError::VmmCanceled.
                // The SpdmDeviceIo trait cannot represent this error, so just
                // log and return the generic SPDM_STATUS_SEND_FAIL.
                Err(e) => {
                    if e.kind() == rust_std_stub::io::ErrorKind::ConnectionAborted {
                        log::warn!("VMM canceled migration session during SPDM send\n");
                    }
                    return Err(SPDM_STATUS_SEND_FAIL);
                }
            }
        }
        Ok(())
    }

    async fn receive(
        &mut self,
        buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let mut buffer = buffer.lock();
        if buffer.len() < VMCALL_SPDM_MESSAGE_HEADER_SIZE {
            return Err(0_usize);
        }

        let mut recvd = 0;
        while recvd < VMCALL_SPDM_MESSAGE_HEADER_SIZE {
            let n = self
                .transport
                .read(&mut buffer[recvd..VMCALL_SPDM_MESSAGE_HEADER_SIZE])
                .await
                // ConnectionAborted maps from VmcallRawError::VmmCanceled.
                // The SpdmDeviceIo trait cannot represent this error, so just
                // log and return the generic receive error.
                .map_err(|e| {
                    if e.kind() == rust_std_stub::io::ErrorKind::ConnectionAborted {
                        log::warn!("VMM canceled migration session during SPDM receive\n");
                    }
                    0_usize
                })?;
            // Fail closed when the transport reports success without progress.
            if n == 0 {
                log::error!("SPDM MigtdTransport::receive header: zero-length transport read\n");
                return Err(0_usize);
            }
            recvd += n;
        }

        let mut reader = Reader::init(&buffer);
        let vmcall_msg_header =
            vmcall_msg::VmCallMessageHeader::read(&mut reader).ok_or(0_usize)?;
        let payload_size = vmcall_msg_header.length as usize;

        if payload_size > buffer.len().saturating_sub(VMCALL_SPDM_MESSAGE_HEADER_SIZE) {
            return Err(0_usize);
        }

        let total = payload_size + VMCALL_SPDM_MESSAGE_HEADER_SIZE;
        while recvd < total {
            let n = self
                .transport
                .read(&mut buffer[recvd..total])
                .await
                .map_err(|e| {
                    if e.kind() == rust_std_stub::io::ErrorKind::ConnectionAborted {
                        log::warn!("VMM canceled migration session during SPDM receive\n");
                    }
                    0_usize
                })?;
            // Fail closed when the transport reports success without progress.
            if n == 0 {
                log::error!("SPDM MigtdTransport::receive payload: zero-length transport read\n");
                return Err(0_usize);
            }
            recvd += n;
        }

        Ok(total)
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

const ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH: usize = 0xb9;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
pub struct PrivateKeyDer {
    pub data_size: u16,
    pub data: Box<[u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]>,
}

impl Default for PrivateKeyDer {
    fn default() -> Self {
        Self {
            data_size: 0,
            data: Box::new([0u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]),
        }
    }
}
impl From<&[u8]> for PrivateKeyDer {
    fn from(value: &[u8]) -> Self {
        assert!(value.len() <= ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH);
        let data_size = value.len() as u16;
        let mut data = Box::new([0u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]);
        data[0..value.len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

impl Codec for PrivateKeyDer {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0usize;
        size += self.data_size.encode(bytes)?;
        for d in self.data.iter().take(self.data_size as usize) {
            size += d.encode(bytes)?;
        }
        Ok(size)
    }

    fn read(r: &mut Reader) -> Option<PrivateKeyDer> {
        let data_size = u16::read(r)?;
        if data_size > ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH as u16 {
            return None;
        }
        let mut data = Box::new([0u8; ECDSA_P384_SHA384_PRIVATE_KEY_LENGTH]);
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(PrivateKeyDer { data_size, data })
    }
}

#[derive(Debug)]
#[cfg(not(feature = "SnpEmu"))]
struct SpdmAppContextData {
    pub migration_info: MigtdMigrationInformation,
    pub private_key: PrivateKeyDer,
}

#[cfg(not(feature = "SnpEmu"))]
impl Codec for SpdmAppContextData {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut size = 0;
        size += self.migration_info.mig_request_id.encode(bytes)?;
        size += self.migration_info.migration_source.encode(bytes)?;
        size += self.migration_info.target_td_uuid.encode(bytes)?;
        size += self.migration_info.binding_handle.encode(bytes)?;

        #[cfg(not(feature = "vmcall-raw"))]
        {
            size += self.migration_info.mig_policy_id.encode(bytes)?;
            size += self.migration_info.communication_id.encode(bytes)?
        }

        size += self.private_key.encode(bytes)?;

        Ok(size)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        let mut migration_info = MigtdMigrationInformation::default();
        migration_info.mig_request_id = u64::read(reader)?;
        migration_info.migration_source = u8::read(reader)?;
        migration_info.target_td_uuid = <[u64; 4]>::read(reader)?;
        migration_info.binding_handle = u64::read(reader)?;

        #[cfg(not(feature = "vmcall-raw"))]
        {
            migration_info.mig_policy_id = u64::read(reader)?;
            migration_info.communication_id = u64::read(reader)?;
        }

        let private_key = PrivateKeyDer::read(reader)?;

        Some(Self {
            migration_info,
            private_key,
        })
    }
}

impl From<SpdmStatus> for MigrationResult {
    fn from(spdm_status: SpdmStatus) -> Self {
        if spdm_status.severity == StatusSeverity::SUCCESS {
            MigrationResult::Success
        } else if let StatusCode::VDM(vdm_error) = &spdm_status.status_code {
            MigrationResult::try_from(vdm_error.vdm_error_code as u8)
                .unwrap_or(MigrationResult::SecureSessionError)
        } else {
            MigrationResult::SecureSessionError
        }
    }
}

impl From<MigrationResult> for SpdmStatus {
    fn from(mig_result: MigrationResult) -> Self {
        if mig_result == MigrationResult::Success {
            SpdmStatus {
                severity: StatusSeverity::SUCCESS,
                status_code: StatusCode::SUCCESS,
                error_data: None,
            }
        } else {
            SpdmStatus {
                severity: StatusSeverity::ERROR,
                status_code: StatusCode::VDM(StatusCodeVdmError {
                    vdm_error_code: mig_result as u16,
                }),
                error_data: None,
            }
        }
    }
}

/// Decode an SpdmStatus returned by an SPDM session body into a
/// MigrationResult, preserving application-level errors carried over the wire
/// as `SpdmErrorVendorDefined`.
///
/// On the destination (local responder failure) the application code is
/// already encoded as `StatusCode::VDM` and decoded by the existing
/// `From<SpdmStatus>` impl. On the source (requester receiving a peer ERROR
/// response) the code arrives in `error_data` as Param2 of the SPDM ERROR
/// message; that path is not covered by `From<SpdmStatus>` so we extract it
/// here.
pub(crate) fn decode_spdm_session_err(e: SpdmStatus) -> MigrationResult {
    let local = MigrationResult::from(e);
    if local != MigrationResult::SecureSessionError {
        return local;
    }
    if let Some(ref ed) = e.error_data {
        if ed.length >= 4
            && ed.data[2] == spdmlib::message::SpdmErrorCode::SpdmErrorVendorDefined.get_u8()
        {
            if let Ok(decoded) = MigrationResult::try_from(ed.data[3]) {
                if decoded != MigrationResult::Success {
                    return decoded;
                }
            }
        }
    }
    MigrationResult::SecureSessionError
}

#[cfg(all(
    test,
    feature = "SnpEmu",
    not(feature = "test_disable_ra_and_accept_all")
))]
mod snp_fixture_tests {
    use pal::types::{
        HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, SnpOperationContext,
    };

    #[test]
    fn fixture_quote_runs_qvl_verification() {
        let context = SnpOperationContext::new(
            HostRequestId::new(7),
            MigrationId::new(7),
            MigrationRole::Source,
            ManagedGuestHandle::new(9),
        );
        let providers = crate::snp_composition::selected_runtime_provider_set();
        let quote = providers
            .legacy_report_blob(&[0u8; 64])
            .expect("fixture report");
        assert!(providers
            .verify_legacy_fixture_quote(&quote, &context)
            .is_ok());
    }
}
