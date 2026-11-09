// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Direct legacy SNP TCP transport; SPDM framing remains in the neutral codec.

use async_io::{AsyncRead, AsyncWrite, Error, ErrorKind};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct TcpPeerStream(Arc<Mutex<TcpStream>>);

impl TcpPeerStream {
    pub fn new(stream: TcpStream) -> Self {
        Self(Arc::new(Mutex::new(stream)))
    }

    pub async fn shutdown(&self) -> std::io::Result<()> {
        self.0.lock().await.shutdown().await
    }
}

fn io_error(error: std::io::Error) -> Error {
    eprintln!("[MA] peer TCP I/O failed: {error}");
    Error::new(ErrorKind::Other, "SNP peer TCP I/O failed")
}

impl AsyncRead for TcpPeerStream {
    async fn read(&mut self, buf: &mut [u8]) -> async_io::Result<usize> {
        let len = self.0.lock().await.read(buf).await.map_err(io_error)?;
        if len == 0 && !buf.is_empty() {
            eprintln!("[MA] peer TCP connection closed before SPDM message completion");
            return Err(Error::new(ErrorKind::UnexpectedEof, "SNP peer closed"));
        }
        Ok(len)
    }
}

impl AsyncWrite for TcpPeerStream {
    async fn write(&mut self, buf: &[u8]) -> async_io::Result<usize> {
        let len = self.0.lock().await.write(buf).await.map_err(io_error)?;
        if len == 0 && !buf.is_empty() {
            eprintln!("[MA] peer TCP write made no progress");
            return Err(Error::new(ErrorKind::WriteZero, "SNP peer write failed"));
        }
        Ok(len)
    }
}
