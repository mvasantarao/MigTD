// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Phase 3a host TCP test tool -- simulates IGVMAgent WFR opcode sequence
//! toward a MigTD SNP MA running TcpTransport (SnpEmu mode).
//!
//! Wire frame (little-endian, mirrors TcpTransport in tcp.rs):
//!   Request  (Host->MA): | op:u8 | reserved:u8 | request_id:u64 | data_len:u32 | data |
//!   Response (MA->Host): | op:u8 | status:u8   | request_id:u64 | data_len:u32 | data |
//!
//! Usage:
//!   host_wfr_test --server 127.0.0.1:8001   # listen; Source MA (client) connects in
//!   host_wfr_test --client 127.0.0.1:8002   # connect; Dest MA (server) is listening
//!
//! Opcode sequence per session: EnableLogArea(4) -> GetTDReport(3) -> StartMigration(1)

use std::env;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HDR: usize = 14; // op(1)+status/reserved(1)+request_id(8)+data_len(4)

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: host_wfr_test --server <addr>|--client <addr>");
        eprintln!("  --server  listen for Source MA (client role) on <addr>");
        eprintln!("  --client  connect to Dest MA (server role) at <addr>");
        std::process::exit(1);
    }
    let mode = args[1].as_str();
    let addr = args[2].as_str();

    let stream = match mode {
        "--server" => {
            println!("[HOST] Listening on {} (waiting for Source MA client)...", addr);
            let listener = TcpListener::bind(addr).await.expect("bind failed");
            let (s, peer) = listener.accept().await.expect("accept failed");
            println!("[HOST] Source MA connected from {}", peer);
            s
        }
        "--client" => {
            println!("[HOST] Connecting to Dest MA server at {}...", addr);
            let s = TcpStream::connect(addr).await.expect("connect failed");
            println!("[HOST] Connected to Dest MA");
            s
        }
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    };

    let is_source = mode == "--server"; // source MA initiates TCP connection to host
    run_wfr_sequence(stream, is_source).await;
}

async fn run_wfr_sequence(mut stream: TcpStream, is_source: bool) {
    println!("[HOST] Starting WFR sequence (MA role: {})...",
        if is_source { "Source" } else { "Dest" });

    // Step 1: EnableLogArea
    send_enable_logarea(&mut stream, 1001).await;
    recv_response(&mut stream, 1001, "EnableLogArea").await;

    // Step 2: GetTDReport (IGVMAgent MA health check)
    send_get_tdreport(&mut stream, 1002).await;
    recv_response(&mut stream, 1002, "GetTDReport").await;

    // Step 3: StartMigration
    send_start_migration(&mut stream, 1003, is_source).await;
    recv_response(&mut stream, 1003, "StartMigration").await;

    println!("[HOST] WFR sequence complete.");
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

async fn send_enable_logarea(stream: &mut TcpStream, req_id: u64) {
    // data: log_max_level(u8=3/Info) + reserved([u8;7]=0) = 8 bytes
    let mut data = vec![0u8; 8];
    data[0] = 3; // log::LevelFilter::Info
    send_frame(stream, 4, req_id, &data).await;
    println!("[HOST] -> EnableLogArea(req_id={}, level=3/Info)", req_id);
}

async fn send_get_tdreport(stream: &mut TcpStream, req_id: u64) {
    // data: reportdata([u8;64]) nonce -- zeroed for health-check in Phase 3a
    let data = vec![0u8; 64];
    send_frame(stream, 3, req_id, &data).await;
    println!("[HOST] -> GetTDReport(req_id={}, reportdata=zeros)", req_id);
}

async fn send_start_migration(stream: &mut TcpStream, req_id: u64, is_source: bool) {
    // data (SnpEmu/vmcall-raw, no policy_v2 -- 48 bytes):
    //   [0]     migration_source: 1=source, 0=dest
    //   [1]     has_init_data: 0
    //   [2..8]  _reserved: zeros
    //   [8..40] target_td_uuid: zeros (fixture)
    //   [40..48] binding_handle: fixture sentinel
    let mut data = vec![0u8; 48];
    data[0] = if is_source { 1 } else { 0 };
    // binding_handle = fixture sentinel 0xDEADBEEFCAFEBABE
    let handle: u64 = 0xDEAD_BEEF_CAFE_BABE;
    data[40..48].copy_from_slice(&handle.to_le_bytes());
    send_frame(stream, 1, req_id, &data).await;
    println!("[HOST] -> StartMigration(req_id={}, source={})", req_id, is_source);
}

async fn send_frame(stream: &mut TcpStream, op: u8, req_id: u64, data: &[u8]) {
    let data_len = data.len() as u32;
    let mut frame = Vec::with_capacity(HDR + data.len());
    frame.push(op);
    frame.push(0u8); // reserved
    frame.extend_from_slice(&req_id.to_le_bytes());
    frame.extend_from_slice(&data_len.to_le_bytes());
    frame.extend_from_slice(data);
    stream.write_all(&frame).await.expect("send_frame write_all");
    stream.flush().await.expect("send_frame flush");
}

// ---------------------------------------------------------------------------
// Response reader
// ---------------------------------------------------------------------------

async fn recv_response(stream: &mut TcpStream, expected_req_id: u64, op_name: &str) {
    let mut hdr = [0u8; HDR];
    stream.read_exact(&mut hdr).await.expect("read response header");
    let status     = hdr[1];
    let request_id = u64::from_le_bytes(hdr[2..10].try_into().unwrap());
    let data_len   = u32::from_le_bytes(hdr[10..14].try_into().unwrap()) as usize;
    let mut resp_data = vec![0u8; data_len];
    if data_len > 0 {
        stream.read_exact(&mut resp_data).await.expect("read response data");
    }

    let ok_str = if status == 0 { "OK" } else { "FAIL" };
    println!(
        "[HOST] <- {} ACK (req_id={}, status=0x{:02x}/{}, data_len={})",
        op_name, request_id, status, ok_str, data_len
    );
    if request_id != expected_req_id {
        println!(
            "[HOST]    WARNING: expected req_id={} got {}",
            expected_req_id, request_id
        );
    }
    if op_name == "GetTDReport" && data_len > 0 {
        println!("[HOST]    ATTESTATION_REPORT: {} bytes received", data_len);
        let preview = data_len.min(16);
        println!("[HOST]    First {} bytes: {:02x?}", preview, &resp_data[..preview]);
    }
    if status != 0 {
        eprintln!("[HOST]    ERROR: MA returned failure status for {}", op_name);
    }
}
