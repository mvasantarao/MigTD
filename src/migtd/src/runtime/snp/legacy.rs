// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Isolated, migration-unqualified compatibility application, not V6/V2 admission.
//! The old five/three-element envelope is inert framing, not SNP policy evidence.

use super::requests::LegacyOperation;
use crate::snp_composition::SnpRuntimeProviders;
use crate::spdm::spdm_rsp::{upcast_mut, ResponderContextExInfo};
use crate::spdm::*;
use crate::status::MigrationResult;
use crate::transport::peer::TcpPeerStream;
use codec::{Codec, Reader, Writer};
use crypto::hash::digest_sha384;
use ring::rand::{SecureRandom, SystemRandom};
use spdmlib::{
    common::{session::SpdmSessionState, ManagedVdmBuffer, SpdmCodec},
    config,
    error::*,
    message::*,
    requester::RequesterContext,
    responder::ResponderContext,
};
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) struct LegacyResponsePayload(pub SpdmVdmResponsePayload);

impl core::ops::Deref for LegacyResponsePayload {
    type Target = SpdmVdmResponsePayload;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for LegacyResponsePayload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for LegacyResponsePayload {
    fn drop(&mut self) {
        self.0.rsp_payload.zeroize();
    }
}

#[derive(Debug)]
pub(crate) struct LegacyAppContext {
    pub migration_info: LegacyOperation,
    pub private_key: PrivateKeyDer,
}

impl Codec for LegacyAppContext {
    fn encode(&self, writer: &mut Writer) -> Result<usize, codec::EncodeErr> {
        Ok(self.migration_info.encode(writer)? + self.private_key.encode(writer)?)
    }

    fn read(reader: &mut Reader) -> Option<Self> {
        Some(Self {
            migration_info: LegacyOperation::read(reader)?,
            private_key: PrivateKeyDer::read(reader)?,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct LegacyKey([u8; 32]);

impl LegacyKey {
    fn random() -> SpdmResult<Self> {
        let mut key = Self([0; 32]);
        SystemRandom::new().fill(&mut key.0).map_err(|_| {
            eprintln!("[MA] legacy key generation failed");
            SPDM_STATUS_CRYPTO_ERROR
        })?;
        Ok(key)
    }
}

pub async fn exchange_legacy(
    operation: &LegacyOperation,
    providers: &SnpRuntimeProviders,
    peer: &TcpPeerStream,
) -> Result<(), MigrationResult> {
    eprintln!("[MA] LEGACY_SPDM_LIMITATION: captured evidence/compatibility envelope; no live TH1 admission, tenant authorization or production key installation");
    let exchange = async {
        if operation.is_src() {
            let (mut requester, _) =
                spdm_requester(peer.clone()).map_err(decode_spdm_session_err)?;
            let transfer = tokio::time::timeout(
                Duration::from_secs(60),
                spdm_requester_transfer_msk(&mut requester, operation, providers),
            )
            .await;
            // Cancellation drops the transfer future before its normal epilogue.
            teardown_sessions(&mut requester.common);
            requester.common.app_context_data_buffer.zeroize();
            match transfer {
                Ok(result) => result.map_err(decode_spdm_session_err),
                Err(error) => {
                    eprintln!("[MA] legacy requester timeout: {error}");
                    Err(MigrationResult::NetworkError)
                }
            }
        } else {
            let (mut responder, _) =
                spdm_responder(peer.clone(), providers.clone()).map_err(decode_spdm_session_err)?;
            let transfer = tokio::time::timeout(
                Duration::from_secs(60),
                spdm_responder_transfer_msk(&mut responder, operation),
            )
            .await;
            teardown_sessions(&mut responder.responder_context.common);
            responder
                .responder_context
                .common
                .app_context_data_buffer
                .zeroize();
            responder.info = ResponderContextExInfo::None;
            match transfer {
                Ok(Ok(())) if !responder.mig_info_exchanged => {
                    eprintln!("[MA] legacy peer ended the session without completing key exchange");
                    Err(MigrationResult::SecureSessionError)
                }
                Ok(result) => result.map_err(decode_spdm_session_err),
                Err(error) => {
                    eprintln!("[MA] legacy responder timeout: {error}");
                    Err(MigrationResult::NetworkError)
                }
            }
        }
    }
    .await;
    let shutdown = peer.shutdown().await.map_err(|error| {
        eprintln!("[MA] legacy peer shutdown failed: {error}");
        MigrationResult::NetworkError
    });
    match exchange {
        Err(error) => {
            eprintln!("[MA] legacy exchange failed: {error:?}");
            Err(error)
        }
        Ok(()) => shutdown,
    }
}

fn check_header(header: &VdmMessage, opcode: VdmMessageOpCode, count: u8) -> SpdmResult {
    if header.major_version != VDM_MESSAGE_MAJOR_VERSION
        || header.minor_version != VDM_MESSAGE_MINOR_VERSION
        || header.op_code != opcode
        || header.element_count != count
    {
        eprintln!("[MA] malformed legacy VDM header");
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    Ok(())
}

fn write_element(writer: &mut Writer, kind: VdmMessageElementType, data: &[u8]) -> SpdmResult {
    VdmMessageElement {
        element_type: kind,
        length: u32::try_from(data.len()).map_err(|_| SPDM_STATUS_INVALID_MSG_SIZE)?,
    }
    .encode(writer)
    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    writer
        .extend_from_slice(data)
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;
    Ok(())
}

fn read_element(
    reader: &mut Reader,
    kind: VdmMessageElementType,
) -> SpdmResult<Zeroizing<Vec<u8>>> {
    let element = VdmMessageElement::read(reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if element.element_type != kind {
        eprintln!("[MA] unexpected legacy VDM element");
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    reader
        .take(element.length as usize)
        .map(|data| Zeroizing::new(data.to_vec()))
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)
}

fn header(writer: &mut Writer, opcode: VdmMessageOpCode, count: u8) -> SpdmResult {
    VdmMessage {
        major_version: VDM_MESSAGE_MAJOR_VERSION,
        minor_version: VDM_MESSAGE_MINOR_VERSION,
        op_code: opcode,
        element_count: count,
    }
    .encode(writer)
    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    Ok(())
}

fn evidence(
    prefix: &[u8],
    th1: &spdmlib::protocol::SpdmDigestStruct,
    providers: &SnpRuntimeProviders,
) -> SpdmResult<Vec<u8>> {
    let hash =
        digest_sha384(&build_report_data(prefix, th1)?).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?;
    let mut nonce = [0; 64];
    nonce[..48].copy_from_slice(&hash);
    providers.legacy_report_blob(&nonce).map_err(|error| {
        eprintln!("[MA] legacy MA evidence acquisition failed: {error:?}");
        SpdmStatus::from(MigrationResult::MutualAttestationError)
    })
}

fn verify_evidence(
    blob: &[u8],
    operation: &LegacyOperation,
    providers: &SnpRuntimeProviders,
) -> SpdmResult {
    providers
        .verify_legacy_fixture_quote(blob, &operation.operation)
        .map_err(|error| {
            eprintln!("[MA] legacy captured evidence verification failed: {error:?}");
            SpdmStatus::from(MigrationResult::MutualAttestationError)
        })?;
    Ok(())
}

fn policy_placeholder() -> SpdmResult<Vec<u8>> {
    // Frozen legacy SnpMigPolicy was exactly 64 zero bytes, not an approved policy.
    digest_sha384(&[0u8; 64]).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)
}

fn write_attestation(writer: &mut Writer, blob: &[u8], source: bool) -> SpdmResult {
    header(
        writer,
        if source {
            VdmMessageOpCode::ExchangeMigrationAttestInfoReq
        } else {
            VdmMessageOpCode::ExchangeMigrationAttestInfoRsp
        },
        if source { 5 } else { 3 },
    )?;
    write_element(writer, VdmMessageElementType::QuoteMy, blob)?;
    write_element(writer, VdmMessageElementType::EventLogMy, &[])?;
    write_element(
        writer,
        VdmMessageElementType::MigPolicyMy,
        &policy_placeholder()?,
    )?;
    if source {
        write_element(writer, VdmMessageElementType::SerVtdExt, &[0; 272])?;
        write_element(writer, VdmMessageElementType::TdReportInit, &[0; 512])?;
    }
    Ok(())
}

fn read_attestation(reader: &mut Reader, source: bool) -> SpdmResult<Zeroizing<Vec<u8>>> {
    let quote = read_element(reader, VdmMessageElementType::QuoteMy)?;
    let log = read_element(reader, VdmMessageElementType::EventLogMy)?;
    let policy = read_element(reader, VdmMessageElementType::MigPolicyMy)?;
    if !log.is_empty() || policy.as_slice() != policy_placeholder()? {
        eprintln!("[MA] legacy envelope contains unsupported policy/event-log claims");
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if source
        && (read_element(reader, VdmMessageElementType::SerVtdExt)?.as_slice() != [0; 272]
            || read_element(reader, VdmMessageElementType::TdReportInit)?.as_slice() != [0; 512])
    {
        eprintln!("[MA] legacy envelope contains unsupported ServTD/TDINFO claims");
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    if reader.any_left() {
        eprintln!("[MA] trailing legacy attestation bytes");
        return Err(SPDM_STATUS_INVALID_MSG_SIZE);
    }
    Ok(quote)
}

async fn request_vdm(
    requester: &mut RequesterContext,
    session: Option<u32>,
    payload: &[u8],
) -> SpdmResult<(Zeroizing<Vec<u8>>, ManagedVdmBuffer)> {
    requester.common.reset_buffer_via_request_code(
        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
        None,
    );
    let mut vendor = [0; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
    vendor[..VDM_MESSAGE_VENDOR_ID_LEN].copy_from_slice(&VDM_MESSAGE_VENDOR_ID);
    let mut request_payload = vec![0; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
    request_payload
        .get_mut(..payload.len())
        .ok_or(SPDM_STATUS_BUFFER_FULL)?
        .copy_from_slice(payload);
    let mut send = Zeroizing::new([0; config::MAX_SPDM_MSG_SIZE]);
    let mut writer = Writer::init(send.as_mut());
    SpdmMessageHeader {
        version: requester.common.negotiate_info.spdm_version_sel,
        request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
    }
    .encode(&mut writer)
    .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
    let mut message = SpdmVdmRequestPayload {
        standard_id: RegistryOrStandardsBodyID::IANA,
        vendor_id: VendorIDStruct {
            len: VDM_MESSAGE_VENDOR_ID_LEN as u8,
            vendor_id: vendor,
        },
        req_length: payload.len() as u32,
        req_payload: request_payload,
    };
    let encoded = message.spdm_encode(&mut requester.common, &mut writer);
    message.req_payload.zeroize();
    encoded?;
    let used = writer.used();
    let mut receive = Zeroizing::new([0; config::MAX_SPDM_MSG_SIZE]);
    let response = requester
        .send_receive_spdm_vendor_defined_request_ex(session, &send[..used], receive.as_mut())
        .await?;
    let mut transcript = ManagedVdmBuffer::default();
    transcript
        .append_message(&digest_sha384(&send[..used]).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?)
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;
    transcript
        .append_message(&digest_sha384(response).map_err(|_| SPDM_STATUS_CRYPTO_ERROR)?)
        .ok_or(SPDM_STATUS_BUFFER_FULL)?;
    let mut reader = Reader::init(response);
    let response_header =
        SpdmMessageHeader::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    if response_header.version != requester.common.negotiate_info.spdm_version_sel
        || response_header.request_response_code
            != SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let reply = SpdmVdmResponsePayload::spdm_read(&mut requester.common, &mut reader)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    let protected_reply = Zeroizing::new(reply.rsp_payload);
    if reply.standard_id != RegistryOrStandardsBodyID::IANA
        || reply.vendor_id.len != VDM_MESSAGE_VENDOR_ID_LEN as u8
        || reply.vendor_id.vendor_id[..VDM_MESSAGE_VENDOR_ID_LEN] != VDM_MESSAGE_VENDOR_ID
        || reader.any_left()
    {
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let data = protected_reply
        .get(..reply.rsp_length as usize)
        .ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    Ok((Zeroizing::new(data.to_vec()), transcript))
}

pub(crate) async fn send_and_receive_sdm_migration_attest_info(
    requester: &mut RequesterContext,
    operation: &LegacyOperation,
    session_id: u32,
    providers: &SnpRuntimeProviders,
) -> SpdmResult {
    let session = requester
        .common
        .get_session_via_id(session_id)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    if session
        .runtime_info
        .vdm_message_transcript_before_finish
        .is_some()
    {
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let quote = evidence(b"MigTDReq", &session.get_th1(), providers)?;
    verify_evidence(&quote, operation, providers)?;
    let mut payload = vec![0; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
    let mut writer = Writer::init(&mut payload);
    write_attestation(&mut writer, &quote, true)?;
    let used = writer.used();
    let (response, transcript) = request_vdm(requester, None, &payload[..used]).await?;
    let mut reader = Reader::init(&response);
    let message = VdmMessage::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
    check_header(
        &message,
        VdmMessageOpCode::ExchangeMigrationAttestInfoRsp,
        3,
    )?;
    verify_evidence(&read_attestation(&mut reader, false)?, operation, providers)?;
    requester
        .common
        .get_session_via_id(session_id)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .runtime_info
        .vdm_message_transcript_before_finish = Some(transcript);
    Ok(())
}

pub fn handle_exchange_mig_attest_info_req(
    responder: &mut ResponderContext,
    session_id: Option<u32>,
    message: &VdmMessage,
    reader: &mut Reader,
    output: &mut [u8],
) -> SpdmResult<usize> {
    check_header(message, VdmMessageOpCode::ExchangeMigrationAttestInfoReq, 5)?;
    let (operation, providers) = unsafe {
        let outer = upcast_mut(responder);
        let ResponderContextExInfo::MigrationInformation(operation) = &outer.info else {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        };
        ((*operation).clone(), outer.snp_providers.clone())
    };
    let sid = session_id
        .or(responder.common.runtime_info.get_last_session_id())
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    let session = responder
        .common
        .get_session_via_id(sid)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    if session
        .runtime_info
        .vdm_message_transcript_before_finish
        .is_some()
        || responder.common.provision_info.my_pub_key.is_none()
        || responder.common.provision_info.peer_pub_key.is_none()
    {
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let th1 = responder
        .common
        .get_session_via_id(sid)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?
        .get_th1();
    verify_evidence(&read_attestation(reader, true)?, &operation, &providers)?;
    let quote = evidence(b"MigTDRsp", &th1, &providers)?;
    verify_evidence(&quote, &operation, &providers)?;
    let mut writer = Writer::init(output);
    write_attestation(&mut writer, &quote, false)?;
    Ok(writer.used())
}

fn write_key(writer: &mut Writer, key: &LegacyKey, source: bool) -> SpdmResult {
    header(
        writer,
        if source {
            VdmMessageOpCode::ExchangeMigrationInfoReq
        } else {
            VdmMessageOpCode::ExchangeMigrationInfoRsp
        },
        2,
    )?;
    write_element(
        writer,
        if source {
            VdmMessageElementType::MigrationExportVersion
        } else {
            VdmMessageElementType::MigrationImportVersion
        },
        &[1, 0, 1, 0],
    )?;
    write_element(
        writer,
        if source {
            VdmMessageElementType::ForwardMigrationSessionKey
        } else {
            VdmMessageElementType::BackwardMigrationSessionKey
        },
        &key.0,
    )
}

fn read_key(reader: &mut Reader, source: bool) -> SpdmResult<LegacyKey> {
    let version = read_element(
        reader,
        if source {
            VdmMessageElementType::MigrationExportVersion
        } else {
            VdmMessageElementType::MigrationImportVersion
        },
    )?;
    if version.as_slice() != [1, 0, 1, 0] {
        eprintln!("[MA] unsupported legacy compatibility version range");
        return Err(SPDM_STATUS_INVALID_MSG_FIELD);
    }
    let data = read_element(
        reader,
        if source {
            VdmMessageElementType::ForwardMigrationSessionKey
        } else {
            VdmMessageElementType::BackwardMigrationSessionKey
        },
    )?;
    let mut key = LegacyKey([0; 32]);
    if data.len() != 32 || reader.any_left() {
        return Err(SPDM_STATUS_INVALID_MSG_SIZE);
    }
    key.0.copy_from_slice(&data);
    Ok(key)
}

pub(crate) async fn send_and_receive_sdm_exchange_migration_info(
    requester: &mut RequesterContext,
    operation: &LegacyOperation,
    session: Option<u32>,
    providers: &SnpRuntimeProviders,
) -> SpdmResult {
    let key = LegacyKey::random()?;
    let mut payload = Zeroizing::new(vec![0; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE]);
    let mut writer = Writer::init(payload.as_mut());
    write_key(&mut writer, &key, true)?;
    let used = writer.used();
    let exchange = request_vdm(requester, session, &payload[..used]).await;
    payload.zeroize();
    let (mut response, _) = exchange?;
    let result = (|| {
        let mut reader = Reader::init(&response);
        let message = VdmMessage::read(&mut reader).ok_or(SPDM_STATUS_INVALID_MSG_SIZE)?;
        check_header(&message, VdmMessageOpCode::ExchangeMigrationInfoRsp, 2)?;
        let key = read_key(&mut reader, false)?;
        providers
            .install_legacy_key(&operation.operation, &key.0)
            .map_err(|error| {
                eprintln!("[MA] legacy mock installation failed: {error:?}");
                SPDM_STATUS_INVALID_STATE_LOCAL
            })
    })();
    response.zeroize();
    result
}

pub fn handle_exchange_mig_info_req(
    responder: &mut ResponderContext,
    session_id: Option<u32>,
    message: &VdmMessage,
    reader: &mut Reader,
    output: &mut [u8],
) -> SpdmResult<usize> {
    check_header(message, VdmMessageOpCode::ExchangeMigrationInfoReq, 2)?;
    let sid = session_id.ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    let (operation, providers, replay) = unsafe {
        let outer = upcast_mut(responder);
        let ResponderContextExInfo::MigrationInformation(operation) = &outer.info else {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        };
        (
            (*operation).clone(),
            outer.snp_providers.clone(),
            outer.mig_info_exchanged,
        )
    };
    let session = responder
        .common
        .get_session_via_id(sid)
        .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
    if replay
        || session.get_session_state() != SpdmSessionState::SpdmSessionEstablished
        || session
            .runtime_info
            .vdm_message_transcript_before_finish
            .is_none()
    {
        eprintln!("[MA] legacy key delivery outside established session or replay");
        session.teardown();
        return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
    }
    let key = read_key(reader, true)?;
    let backward = LegacyKey::random()?;
    let mut writer = Writer::init(output);
    write_key(&mut writer, &backward, false)?;
    providers
        .install_legacy_key(&operation.operation, &key.0)
        .map_err(|error| {
            eprintln!("[MA] legacy mock installation failed: {error:?}");
            SPDM_STATUS_INVALID_STATE_LOCAL
        })?;
    unsafe { upcast_mut(responder).mig_info_exchanged = true };
    Ok(writer.used())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal::types::MigrationRole;

    fn encoded_attestation(source: bool) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        let mut writer = Writer::init(&mut bytes);
        write_attestation(&mut writer, &[0x55; 1184], source).unwrap();
        let used = writer.used();
        bytes.truncate(used);
        bytes
    }

    #[test]
    fn legacy_envelopes_have_frozen_elements_without_policy_claims() {
        for source in [false, true] {
            let bytes = encoded_attestation(source);
            assert_eq!(bytes.len(), if source { 2050 } else { 1254 });
            let mut reader = Reader::init(&bytes);
            let message = VdmMessage::read(&mut reader).unwrap();
            assert_eq!(message.element_count, if source { 5 } else { 3 });
            assert_eq!(
                read_attestation(&mut reader, source).unwrap().as_slice(),
                [0x55; 1184]
            );
            assert!(!reader.any_left());
        }
    }

    #[test]
    fn malformed_legacy_attestation_is_not_admitted() {
        for source in [false, true] {
            let original = encoded_attestation(source);
            for end in 4..original.len() {
                let mut reader = Reader::init(&original[..end]);
                VdmMessage::read(&mut reader).unwrap();
                assert!(read_attestation(&mut reader, source).is_err());
            }
            let mut trailing = original.clone();
            trailing.push(0);
            let mut reader = Reader::init(&trailing);
            VdmMessage::read(&mut reader).unwrap();
            assert!(read_attestation(&mut reader, source).is_err());
            let mut wrong_policy = original.clone();
            // Header(4), quote TLV(6)+1184, empty event TLV(6), policy TLV(6).
            wrong_policy[4 + 6 + 1184 + 6 + 6] ^= 1;
            let mut reader = Reader::init(&wrong_policy);
            VdmMessage::read(&mut reader).unwrap();
            assert!(read_attestation(&mut reader, source).is_err());
        }
    }

    #[test]
    fn key_codec_is_exact_and_zeroizing() {
        for source in [false, true] {
            let mut bytes = [0; 64];
            let mut writer = Writer::init(&mut bytes);
            write_key(&mut writer, &LegacyKey([0xa5; 32]), source).unwrap();
            let used = writer.used();
            assert_eq!(used, 52);
            let mut reader = Reader::init(&bytes[..used]);
            VdmMessage::read(&mut reader).unwrap();
            let mut decoded = read_key(&mut reader, source).unwrap();
            assert_eq!(decoded.0, [0xa5; 32]);
            decoded.zeroize();
            assert_eq!(decoded.0, [0; 32]);
            bytes[4 + 6] = 2;
            let mut reader = Reader::init(&bytes[..used]);
            VdmMessage::read(&mut reader).unwrap();
            assert!(read_key(&mut reader, source).is_err());
        }
    }

    #[test]
    fn application_context_is_snp_owned_and_rejects_bad_roles() {
        let context = LegacyAppContext {
            migration_info: LegacyOperation::new(71, MigrationRole::Destination, 99),
            private_key: PrivateKeyDer::default(),
        };
        let mut bytes = [0; 64];
        let mut writer = Writer::init(&mut bytes);
        context.encode(&mut writer).unwrap();
        assert_eq!(writer.used(), 8 + 1 + 8 + 2);
        let decoded = LegacyAppContext::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(
            decoded.migration_info.operation,
            context.migration_info.operation
        );
        bytes[8] = 2;
        assert!(LegacyAppContext::read(&mut Reader::init(&bytes)).is_none());
    }

    #[tokio::test]
    async fn legacy_exchange_uses_direct_tcp_and_mock_effects_on_both_roles() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (destination, _) = listener.accept().await.unwrap();
        let source = TcpPeerStream::new(source);
        let destination = TcpPeerStream::new(destination);
        let providers = crate::snp_composition::selected_runtime_provider_set();
        let src = LegacyOperation::new(1003, MigrationRole::Source, 9);
        let dst = LegacyOperation::new(1003, MigrationRole::Destination, 9);
        let (a, b) = tokio::join!(
            exchange_legacy(&src, &providers, &source),
            exchange_legacy(&dst, &providers, &destination),
        );
        assert_eq!(a, Ok(()));
        assert_eq!(b, Ok(()));
    }
}
