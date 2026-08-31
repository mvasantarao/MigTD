// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Fixture-based SNP attestation blob builder.
//!
//! Loads real AMD SNP fixture files captured from an Azure EPYC 7763 CVM
//! (northeurope, July 2026). The fixture report carries a valid AMD VCEK
//! P-384 signature — Phase 1 uses it as-is for chain verification.
//!
//! Blob format: report[1184B] || vcek_len[4LE] || vcek || ask_len[4LE] || ask
//!
//! Note on fixture extraction: the raw HCLA response has a 32-byte header (magic "HCLA",
//! version, payload_size, report_type, reserved). The 1184-byte SNP report starts at byte
//! 0x20. The fixture was extracted at offset 0x20; cpuid_fam_id=0x19 (Milan), version=5.

use pal::traits::PalError;

static FIXTURE_REPORT: &[u8] = include_bytes!("fixture_data/snp_report.bin"); // 1184 bytes
static FIXTURE_VCEK: &[u8] = include_bytes!("fixture_data/vcek.der");
static FIXTURE_ASK: &[u8] = include_bytes!("fixture_data/ask.der");

/// Build the attestation blob: SNP report + cert chain DERs.
///
/// Format: report[1184] || vcek_len[4LE] || vcek || ask_len[4LE] || ask || ark_len[4LE] || ark
/// Total: ~5850 bytes (1184 + 3*4 + 1351 + 1677 + 1639)
pub fn build_fixture_blob() -> Result<Vec<u8>, PalError> {
    let mut blob = FIXTURE_REPORT.to_vec();
    for cert in &[FIXTURE_VCEK, FIXTURE_ASK] {
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
    use tee_attestation_verification_lib::{
        certificate_from_der,
        snp::{
            report::{AttestationReport, TryFromBytes},
            verify::{sync::verify_attestation, ChainVerification},
        },
    };

    #[test]
    fn test_fixture_chain_verification() {
        // Parse certs from DER
        let ask = certificate_from_der(FIXTURE_ASK).expect("ASK DER parse");
        let vcek = certificate_from_der(FIXTURE_VCEK).expect("VCEK DER parse");

        // Parse SNP report (zerocopy, 1184 bytes, version=5, cpuid_fam_id=0x19 Milan)
        let report =
            AttestationReport::try_read_from_bytes(FIXTURE_REPORT).expect("SNP report parse");

        // Verify via TAV: ARK->ASK->VCEK chain + VCEK report sig
        verify_attestation(
            &report,
            &vcek,
            &ChainVerification::WithPinnedArk { ask: &ask },
        )
        .expect("TAV verify_attestation");

        println!("Fixture chain + report sig verified OK (TAV, cpuid_fam_id=0x19 Milan)");
    }

    #[test]
    fn test_build_fixture_blob() {
        let blob = build_fixture_blob().expect("build_fixture_blob");
        assert_eq!(&blob[..1184], FIXTURE_REPORT, "report bytes match");
        assert!(blob.len() > 1184, "cert chain appended");
        println!("build_fixture_blob OK: {} bytes total", blob.len());
    }
}
