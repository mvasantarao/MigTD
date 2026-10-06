// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use base64::Engine;

use crate::traits::PalError;

pub fn der_chain_to_pem(cert_chain: &[Vec<u8>]) -> Result<Vec<u8>, PalError> {
    let mut pem = Vec::new();
    for der in cert_chain.iter().take(2) {
        if der.is_empty() {
            return Err(PalError::InvalidInput);
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.extend_from_slice(chunk);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::der_chain_to_pem;

    #[test]
    fn converts_der_chain_to_pem() {
        let pem = der_chain_to_pem(&[vec![1, 2, 3], vec![4, 5, 6]]).unwrap();
        let text = String::from_utf8(pem).unwrap();
        assert!(text.contains("-----BEGIN CERTIFICATE-----"));
        assert_eq!(text.matches("-----BEGIN CERTIFICATE-----").count(), 2);
    }
}