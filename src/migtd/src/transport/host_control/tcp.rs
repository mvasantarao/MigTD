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
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::migration::data::{MigrationInformation, WaitForRequestResponse};
use crate::migration::{EnableLogAreaInfo, MigtdMigrationInformation, ReportInfo};
use crate::migration::host_transport::HostControlTransport;
use crate::migration::MigrationResult;

/// Byte length of every frame header (request and response share the same layout).
const FRAME_HDR: usize = 14; // op(1) + reserved/status(1) + request_id(8) + data_len(4)

pub struct TcpTransport {
    stream: Arc<Mutex<TcpStream>>,
}

impl TcpTransport {
    /// Source MA: connect outward to the host WFR server.
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        log::info!("[MA] TcpTransport: connected to {}", addr);
        Ok(Self { stream: Arc::new(Mutex::new(stream)) })
    }

    /// Dest MA: listen and wait for the host WFR client to connect.
    pub async fn accept(listen_addr: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        log::info!("[MA] TcpTransport: listening on {}", listen_addr);
        let (stream, peer) = listener.accept().await?;
        log::info!("[MA] TcpTransport: host connected from {}", peer);
        Ok(Self { stream: Arc::new(Mutex::new(stream)) })
    }
}

#[async_trait]
impl HostControlTransport for TcpTransport {
    async fn wait_for_request(&self) -> Result<WaitForRequestResponse, MigrationResult> {
        let mut stream = self.stream.lock().await;

        let mut hdr = [0u8; FRAME_HDR];
        stream.read_exact(&mut hdr).await.map_err(|_| MigrationResult::NetworkError)?;

        let operation  = hdr[0];
        // hdr[1] = reserved (must be 0; we accept it silently)
        let request_id = u64::from_le_bytes(hdr[2..10].try_into().unwrap());
        let data_len   = u32::from_le_bytes(hdr[10..14].try_into().unwrap()) as usize;

        let mut data = vec![0u8; data_len];
        if data_len > 0 {
            stream.read_exact(&mut data).await.map_err(|_| MigrationResult::NetworkError)?;
        }

        match operation {
            1 => parse_start_migration(request_id, &data),
            3 => parse_get_tdreport(request_id, &data),
            4 => parse_enable_logarea(request_id, &data),
            _ => {
                log::warn!("[MA] TcpTransport: unknown opcode 0x{:02x}", operation);
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
        stream.write_all(&frame).await.map_err(|_| MigrationResult::NetworkError)?;
        stream.flush().await.map_err(|_| MigrationResult::NetworkError)?;
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
    if data.len() < 8 {
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
    if data.len() < 64 {
        return Err(MigrationResult::InvalidParameter);
    }
    let mut reportdata = [0u8; 64];
    reportdata.copy_from_slice(&data[..64]);
    Ok(WaitForRequestResponse::GetTdReport(ReportInfo { mig_request_id: request_id, reportdata }))
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
    if data.len() < 48 {
        return Err(MigrationResult::InvalidParameter);
    }
    let migration_source = data[0];
    let has_init_data    = data[1];
    let mut uuid_bytes = [0u64; 4];
    for i in 0..4 {
        let off = 8 + i * 8;
        uuid_bytes[i] = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
    }
    let binding_handle = u64::from_le_bytes(data[40..48].try_into().unwrap());

    // SAFETY: MigtdMigrationInformation has a private `_reserved` field.
    // We zero-initialize and then populate the public fields.
    let mut mig_info: MigtdMigrationInformation = unsafe { std::mem::zeroed() };
    mig_info.mig_request_id   = request_id;
    mig_info.migration_source  = migration_source;
    mig_info.has_init_data     = has_init_data;
    mig_info.target_td_uuid    = uuid_bytes;
    mig_info.binding_handle    = binding_handle;

    Ok(WaitForRequestResponse::StartMigration(MigrationInformation { mig_info }))
}
