// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! TcpTransport: Phase 3a concrete impl of HostControlTransport over TCP.
//!
//! Wire frame (little-endian, both directions):
//!   Request  (Host->MA): | op:u8 | reserved:u8 | request_id:u64 | data_len:u32 | data |
//!   Response (MA->Host): | op:u8 | status:u8   | request_id:u64 | data_len:u32 | data |
//!
//! Source MA role: TCP client -- call TcpTransport::connect(host_addr).
//! Dest   MA role: TCP server -- call TcpTransport::accept(listen_addr).
//! Phase 3b: GhcbVmgexitTransport replaces this; same HostControlTransport trait.

#![cfg(feature = "SnpEmu")]

use async_trait::async_trait;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::migration::data::{MigrationInformation, WaitForRequestResponse};
use crate::migration::host_transport::HostControlTransport;
use crate::migration::MigrationResult;
use crate::migration::{EnableLogAreaInfo, MigtdMigrationInformation, ReportInfo};

/// Byte length of every frame header (request and response share the same layout).
const FRAME_HDR: usize = 14; // op(1) + reserved/status(1) + request_id(8) + data_len(4)
const MAX_REQUEST_DATA_LEN: usize = 4096;

pub struct TcpTransport {
    stream: Arc<Mutex<TcpStream>>,
    request_ids: Arc<Mutex<BTreeSet<u64>>>,
}

impl TcpTransport {
    /// Source MA: connect outward to the host WFR server.
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        eprintln!("[MA] TcpTransport: connecting to {}", addr);
        let stream = TcpStream::connect(addr).await?;
        eprintln!("[MA] TcpTransport: connected to {}", addr);
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            request_ids: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    /// Dest MA: listen and wait for the host WFR client to connect.
    pub async fn accept(listen_addr: &str) -> std::io::Result<Self> {
        eprintln!("[MA] TcpTransport: binding {}", listen_addr);
        let listener = TcpListener::bind(listen_addr).await?;
        eprintln!("[MA] TcpTransport: bound, waiting for connection...");
        let (stream, peer) = listener.accept().await?;
        eprintln!("[MA] TcpTransport: host connected from {}", peer);
        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            request_ids: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }
}

#[async_trait]
impl HostControlTransport for TcpTransport {
    async fn wait_for_request(&self) -> Result<WaitForRequestResponse, MigrationResult> {
        let mut stream = self.stream.lock().await;

        let mut hdr = [0u8; FRAME_HDR];
        stream
            .read_exact(&mut hdr)
            .await
            .map_err(|_| MigrationResult::NetworkError)?;

        let operation = hdr[0];
        if hdr[1] != 0 {
            return Err(MigrationResult::InvalidParameter);
        }
        let request_id = u64::from_le_bytes(hdr[2..10].try_into().unwrap());
        let data_len = u32::from_le_bytes(hdr[10..14].try_into().unwrap()) as usize;
        if data_len > MAX_REQUEST_DATA_LEN {
            return Err(MigrationResult::InvalidParameter);
        }

        let mut data = vec![0u8; data_len];
        if data_len > 0 {
            stream
                .read_exact(&mut data)
                .await
                .map_err(|_| MigrationResult::NetworkError)?;
        }
        if !self.request_ids.lock().await.insert(request_id) {
            return Err(MigrationResult::InvalidParameter);
        }

        eprintln!(
            "[MA] TcpTransport: recv opcode=0x{:02x} request_id={} data_len={}",
            operation, request_id, data_len
        );
        match operation {
            1 => parse_start_migration(request_id, &data),
            3 => parse_get_tdreport(request_id, &data),
            4 => parse_enable_logarea(request_id, &data),
            _ => {
                eprintln!(
                    "[MA] WARN: TcpTransport: unknown opcode 0x{:02x}",
                    operation
                );
                Err(MigrationResult::UnsupportedOperationError)
            }
        }
    }

    async fn report_status(
        &self,
        status: u8,
        request_id: u64,
        data: &[u8],
    ) -> Result<(), MigrationResult> {
        let data_len = data.len() as u32;
        let mut frame = Vec::with_capacity(FRAME_HDR + data.len());
        frame.push(0u8); // op field: host identifies response by request_id
        frame.push(status);
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&data_len.to_le_bytes());
        frame.extend_from_slice(data);

        let mut stream = self.stream.lock().await;
        stream
            .write_all(&frame)
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        stream
            .flush()
            .await
            .map_err(|_| MigrationResult::NetworkError)?;
        eprintln!(
            "[MA] TcpTransport: report_status sent: status={} request_id={} data_len={}",
            status,
            request_id,
            data.len()
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private parsers
// ---------------------------------------------------------------------------

fn parse_enable_logarea(
    request_id: u64,
    data: &[u8],
) -> Result<WaitForRequestResponse, MigrationResult> {
    // data payload: log_max_level(u8) + reserved([u8;7]) = 8 bytes
    if data.len() != 8 {
        return Err(MigrationResult::InvalidParameter);
    }
    let log_max_level = data[0];
    let mut reserved = [0u8; 7];
    reserved.copy_from_slice(&data[1..8]);
    if reserved.iter().any(|&b| b != 0) {
        return Err(MigrationResult::InvalidParameter);
    }
    Ok(WaitForRequestResponse::EnableLogArea(EnableLogAreaInfo {
        mig_request_id: request_id,
        log_max_level,
        reserved,
    }))
}

fn parse_get_tdreport(
    request_id: u64,
    data: &[u8],
) -> Result<WaitForRequestResponse, MigrationResult> {
    // data payload: reportdata([u8;64]) = 64 bytes
    if data.len() != 64 {
        return Err(MigrationResult::InvalidParameter);
    }
    let mut reportdata = [0u8; 64];
    reportdata.copy_from_slice(&data[..64]);
    Ok(WaitForRequestResponse::GetTdReport(ReportInfo {
        mig_request_id: request_id,
        reportdata,
    }))
}

fn parse_start_migration(
    request_id: u64,
    data: &[u8],
) -> Result<WaitForRequestResponse, MigrationResult> {
    // data payload (SnpEmu / vmcall-raw, no policy_v2):
    //   migration_source: u8   [0]
    //   has_init_data:    u8   [1]
    //   _reserved:        [u8;6] [2..8]
    //   target_td_uuid:   [u64;4] [8..40]
    //   binding_handle:   u64  [40..48]
    //   Total: 48 bytes minimum
    #[cfg(not(feature = "policy_v2"))]
    if data.len() != 48 {
        return Err(MigrationResult::InvalidParameter);
    }
    #[cfg(feature = "policy_v2")]
    if !matches!((data.get(1), data.len()), (Some(0), 48) | (Some(1), 560)) {
        return Err(MigrationResult::InvalidParameter);
    }
    let migration_source = data[0];
    let has_init_data = data[1];
    #[cfg(not(feature = "policy_v2"))]
    if has_init_data != 0 {
        return Err(MigrationResult::InvalidParameter);
    }
    if migration_source > 1 || data[2..8].iter().any(|&byte| byte != 0) {
        return Err(MigrationResult::InvalidParameter);
    }
    let mut uuid_bytes = [0u64; 4];
    for i in 0..4 {
        let off = 8 + i * 8;
        uuid_bytes[i] = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    }
    let binding_handle = u64::from_le_bytes(data[40..48].try_into().unwrap());

    // SAFETY: MigtdMigrationInformation has a private `_reserved` field.
    // We zero-initialize and then populate the public fields.
    let mut mig_info: MigtdMigrationInformation = unsafe { std::mem::zeroed() };
    mig_info.mig_request_id = request_id;
    mig_info.migration_source = migration_source;
    mig_info.has_init_data = has_init_data;
    mig_info.target_td_uuid = uuid_bytes;
    mig_info.binding_handle = binding_handle;
    #[cfg(feature = "policy_v2")]
    if has_init_data == 1 {
        mig_info.init_td_info.copy_from_slice(&data[48..560]);
    }

    Ok(WaitForRequestResponse::StartMigration(
        MigrationInformation { mig_info },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn transport_pair() -> (TcpTransport, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (
            TcpTransport {
                stream: Arc::new(Mutex::new(server)),
                request_ids: Arc::new(Mutex::new(BTreeSet::new())),
            },
            client,
        )
    }

    async fn send_request(stream: &mut TcpStream, operation: u8, request_id: u64, data: &[u8]) {
        let mut frame = Vec::with_capacity(FRAME_HDR + data.len());
        frame.push(operation);
        frame.push(0);
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&(data.len() as u32).to_le_bytes());
        frame.extend_from_slice(data);
        stream.write_all(&frame).await.unwrap();
    }

    fn start_payload(role: u8) -> Vec<u8> {
        let mut payload = vec![0u8; 48];
        payload[0] = role;
        payload
    }

    #[test]
    fn exact_request_lengths_are_required() {
        assert!(parse_enable_logarea(1, &[0u8; 8]).is_ok());
        assert!(parse_enable_logarea(1, &[0u8; 9]).is_err());
        assert!(parse_get_tdreport(2, &[0u8; 64]).is_ok());
        assert!(parse_get_tdreport(2, &[0u8; 65]).is_err());
        assert!(parse_start_migration(3, &start_payload(1)).is_ok());
        assert!(parse_start_migration(3, &[0u8; 47]).is_err());
    }

    #[test]
    fn start_migration_rejects_invalid_role_and_reserved_bytes() {
        assert!(parse_start_migration(1, &start_payload(2)).is_err());
        let mut payload = start_payload(1);
        payload[2] = 1;
        assert!(parse_start_migration(1, &payload).is_err());
    }

    #[cfg(not(feature = "policy_v2"))]
    #[test]
    fn start_migration_rejects_init_data_without_policy_v2() {
        let mut payload = start_payload(1);
        payload[1] = 1;
        assert!(parse_start_migration(1, &payload).is_err());
    }

    #[tokio::test]
    async fn duplicate_request_id_is_rejected() {
        let (transport, mut client) = transport_pair().await;
        send_request(&mut client, 4, 7, &[0u8; 8]).await;
        assert!(transport.wait_for_request().await.is_ok());
        send_request(&mut client, 4, 7, &[0u8; 8]).await;
        assert!(matches!(
            transport.wait_for_request().await,
            Err(MigrationResult::InvalidParameter)
        ));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_payload_read() {
        let (transport, mut client) = transport_pair().await;
        let mut header = [0u8; FRAME_HDR];
        header[0] = 1;
        header[2..10].copy_from_slice(&9u64.to_le_bytes());
        header[10..14].copy_from_slice(&((MAX_REQUEST_DATA_LEN + 1) as u32).to_le_bytes());
        client.write_all(&header).await.unwrap();
        assert!(matches!(
            transport.wait_for_request().await,
            Err(MigrationResult::InvalidParameter)
        ));
    }

    #[tokio::test]
    async fn truncated_frame_is_a_network_error() {
        let (transport, mut client) = transport_pair().await;
        client.write_all(&[1u8; 5]).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(matches!(
            transport.wait_for_request().await,
            Err(MigrationResult::NetworkError)
        ));
    }
}
