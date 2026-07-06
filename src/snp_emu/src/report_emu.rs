// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Fixture-based SNP attestation blob builder.
//!
//! Loads real AMD SNP fixture files captured from an Azure EPYC 7763 CVM
//! (northeurope, July 2026). The fixture report carries a valid AMD VCEK
//! P-384 signature — Phase 1 uses it as-is for chain verification.
//!
//! Blob format: report[1184B] || vcek_len[4LE] || vcek || ask_len[4LE] || ask || ark_len[4LE] || ark

use pal::traits::PalError;

static FIXTURE_REPORT: &[u8] = include_bytes!("fixture_data/snp_report.bin"); // 1184 bytes
static FIXTURE_VCEK:   &[u8] = include_bytes!("fixture_data/vcek.der");
static FIXTURE_ASK:    &[u8] = include_bytes!("fixture_data/ask.der");
static FIXTURE_ARK:    &[u8] = include_bytes!("fixture_data/ark.der");

/// Build the attestation blob: SNP report + cert chain DERs.
///
/// Format: report[1184] || vcek_len[4LE] || vcek || ask_len[4LE] || ask || ark_len[4LE] || ark
/// Total: ~5850 bytes (1184 + 3*4 + 1351 + 1677 + 1639)
pub fn build_fixture_blob() -> Result<Vec<u8>, PalError> {
    let mut blob = FIXTURE_REPORT.to_vec();
    for cert in &[FIXTURE_VCEK, FIXTURE_ASK, FIXTURE_ARK] {
        let len = cert.len() as u32;
        blob.extend_from_slice(&len.to_le_bytes());
        blob.extend_from_slice(cert);
    }
    Ok(blob)
}

/// Return the raw fixture SNP report bytes (1184 bytes, no cert chain).
pub fn fixture_report_bytes() -> &'static [u8] {
    FIXTURE_REPORT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{verify_snp_cert_chain_der, verify_snp_report_sig};

    #[test]
    fn test_fixture_chain_verification() {
        // Verify real AMD fixture: ARK->ASK->VCEK chain + VCEK report signature
        let vcek_pubkey = verify_snp_cert_chain_der(FIXTURE_ARK, FIXTURE_ASK, FIXTURE_VCEK)
            .expect("cert chain ARK->ASK->VCEK");
        verify_snp_report_sig(&vcek_pubkey, FIXTURE_REPORT)
            .expect("SNP report ECDSA-P384 sig");
        println!("Fixture chain + report sig verified OK (ring-based, cpuid_fam_id=0xD9)");
    }

    #[test]
    fn test_build_fixture_blob() {
        let blob = build_fixture_blob().expect("build_fixture_blob");
        assert_eq!(&blob[..1184], FIXTURE_REPORT, "report bytes match");
        assert!(blob.len() > 1184, "cert chain appended");
        println!("build_fixture_blob OK: {} bytes total", blob.len());
    }
}
