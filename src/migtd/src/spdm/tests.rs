// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use spdmlib::common::{session::SpdmSessionState, INVALID_SESSION_ID};

struct TestTransport;

impl AsyncRead for TestTransport {
    async fn read(&mut self, _buffer: &mut [u8]) -> async_io::Result<usize> {
        unreachable!("session teardown must not read from the transport");
    }
}

impl AsyncWrite for TestTransport {
    async fn write(&mut self, _buffer: &[u8]) -> async_io::Result<usize> {
        unreachable!("session teardown must not write to the transport");
    }
}

fn assert_teardown_clears_sessions(context: &mut SpdmContext) {
    for last_session_id in [Some(1), None] {
        for (index, session) in context.session.iter_mut().enumerate() {
            session.setup(u32::try_from(index + 1).unwrap()).unwrap();
            session.set_session_state(if last_session_id.is_some() {
                SpdmSessionState::SpdmSessionHandshaking
            } else {
                SpdmSessionState::SpdmSessionEstablished
            });
            let mut secret = session.get_application_secret();
            secret.request_direction.encryption_key.data.fill(0xa5);
            secret.request_direction.encryption_key.data_size = 32;
            session.set_application_secret(secret);
        }
        // FINISH clears this field without removing the established session.
        context.runtime_info.set_last_session_id(last_session_id);

        for _ in 0..2 {
            teardown_sessions(context);
            for session in &context.session {
                assert_eq!(session.get_session_id(), INVALID_SESSION_ID);
                assert_eq!(
                    session.get_session_state(),
                    SpdmSessionState::SpdmSessionNotStarted
                );
                assert_eq!(session.get_application_secret(), Default::default());
            }
        }
    }
}

#[test]
fn requester_teardown_clears_handshaking_and_established_sessions() {
    let (mut requester, _) = spdm_requester(TestTransport).unwrap();
    assert_teardown_clears_sessions(&mut requester.common);
}

#[test]
fn responder_teardown_clears_handshaking_and_established_sessions() {
    #[cfg(not(feature = "SnpEmu"))]
    let (mut responder, _) = spdm_responder(TestTransport).unwrap();
    #[cfg(feature = "SnpEmu")]
    let (mut responder, _) = spdm_responder(
        TestTransport,
        crate::snp_composition::selected_runtime_provider_set(),
    )
    .unwrap();
    assert_teardown_clears_sessions(&mut responder.responder_context.common);
}

struct BufferedTransport {
    input: alloc::collections::VecDeque<u8>,
    output: Vec<u8>,
    read_limit: usize,
    write_limit: usize,
    zero_read_seen: bool,
    zero_write_seen: bool,
}

impl BufferedTransport {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: input.into(),
            output: Vec::new(),
            read_limit: usize::MAX,
            write_limit: usize::MAX,
            zero_read_seen: false,
            zero_write_seen: false,
        }
    }
}

impl AsyncRead for BufferedTransport {
    async fn read(&mut self, buffer: &mut [u8]) -> async_io::Result<usize> {
        let count = buffer.len().min(self.input.len()).min(self.read_limit);
        if count == 0 {
            assert!(!self.zero_read_seen, "repeated zero-progress read");
            self.zero_read_seen = true;
        }
        for (out, byte) in buffer[..count].iter_mut().zip(self.input.drain(..count)) {
            *out = byte;
        }
        Ok(count)
    }
}

impl AsyncWrite for BufferedTransport {
    async fn write(&mut self, buffer: &[u8]) -> async_io::Result<usize> {
        let count = buffer.len().min(self.write_limit);
        if count == 0 {
            assert!(!self.zero_write_seen, "repeated zero-progress write");
            self.zero_write_seen = true;
        }
        self.output.extend_from_slice(&buffer[..count]);
        Ok(count)
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0; VMCALL_SPDM_MESSAGE_HEADER_SIZE + payload.len()];
    let mut writer = Writer::init(&mut buffer);
    vmcall_msg::VmCallMessageHeader {
        version: vmcall_msg::VMCALL_SPDM_VERSION,
        msg_type: vmcall_msg::VmCallMessageType::SpdmMessage,
        length: u32::try_from(payload.len()).unwrap(),
    }
    .encode(&mut writer)
    .unwrap();
    writer.extend_from_slice(payload).unwrap();
    buffer
}

#[tokio::test]
async fn transport_rejects_zero_progress_write() {
    let mut io = BufferedTransport::new(Vec::new());
    io.write_limit = 0;
    let mut transport = MigtdTransport { transport: io };
    assert_eq!(
        transport.send(Arc::new(&[1u8][..])).await,
        Err(SPDM_STATUS_SEND_FAIL)
    );
}

#[tokio::test]
async fn transport_rejects_zero_progress_header_read() {
    let mut transport = MigtdTransport {
        transport: BufferedTransport::new(Vec::new()),
    };
    let mut buffer = [0; 64];
    assert_eq!(
        transport
            .receive(Arc::new(Mutex::new(&mut buffer[..])), 0)
            .await,
        Err(0)
    );
}

#[tokio::test]
async fn transport_rejects_truncated_payload() {
    let mut input = frame(&[1, 2]);
    input.pop();
    let mut transport = MigtdTransport {
        transport: BufferedTransport::new(input),
    };
    let mut buffer = [0; 64];
    assert_eq!(
        transport
            .receive(Arc::new(Mutex::new(&mut buffer[..])), 0)
            .await,
        Err(0)
    );
}

#[tokio::test]
async fn transport_preserves_coalesced_frame_boundaries() {
    let first = frame(&[1, 2]);
    let second = frame(&[3, 4, 5]);
    let mut input = first.clone();
    input.extend_from_slice(&second);
    let mut transport = MigtdTransport {
        transport: BufferedTransport::new(input),
    };
    let mut buffer = [0; 64];
    for expected in [first, second] {
        let length = transport
            .receive(Arc::new(Mutex::new(&mut buffer[..])), 0)
            .await
            .unwrap();
        assert_eq!(&buffer[..length], expected);
    }
    assert!(transport.transport.input.is_empty());
}

#[tokio::test]
async fn transport_handles_partial_reads_and_writes() {
    let expected = frame(&[1, 2, 3]);
    let mut io = BufferedTransport::new(expected.clone());
    io.read_limit = 1;
    io.write_limit = 1;
    let mut transport = MigtdTransport { transport: io };
    let mut buffer = [0; 64];
    let length = transport
        .receive(Arc::new(Mutex::new(&mut buffer[..])), 0)
        .await
        .unwrap();
    assert_eq!(&buffer[..length], expected);
    transport.send(Arc::new(&expected[..])).await.unwrap();
    assert_eq!(transport.transport.output, expected);
}

#[tokio::test]
async fn transport_rejects_payload_larger_than_receive_buffer() {
    let mut transport = MigtdTransport {
        transport: BufferedTransport::new(frame(&[1, 2, 3])),
    };
    let mut buffer = [0; VMCALL_SPDM_MESSAGE_HEADER_SIZE];
    assert_eq!(
        transport
            .receive(Arc::new(Mutex::new(&mut buffer[..])), 0)
            .await,
        Err(0)
    );
    assert_eq!(transport.transport.input.len(), 3);
}
