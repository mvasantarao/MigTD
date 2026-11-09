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
/// Format: report[1184] || vcek_len[4LE] || vcek || ask_len[4LE] || ask
pub fn build_fixture_blob() -> Result<Vec<u8>, PalError> {
    use pal::types::{MaEvidence, MaEvidenceBinding, SnpVerificationCollateral};

    let evidence =
        MaEvidence::from_report_bytes(FIXTURE_REPORT, MaEvidenceBinding::CapturedFixture).map_err(
            |error| {
                log::error!("captured fixture report encoding failed: {error:?}");
                PalError::InvalidInput
            },
        )?;
    let collateral = SnpVerificationCollateral::new(FIXTURE_VCEK.to_vec(), FIXTURE_ASK.to_vec());
    pal::snp::fixture::encode_legacy_ma_blob(&evidence, &collateral)
}

/// Return the raw fixture SNP report bytes (1184 bytes, no cert chain).
pub fn fixture_report_bytes() -> &'static [u8] {
    FIXTURE_REPORT
}

pub fn fixture_vcek_der() -> &'static [u8] {
    FIXTURE_VCEK
}

pub fn fixture_ask_der() -> &'static [u8] {
    FIXTURE_ASK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_verifier_rejects_modified_signature_and_collateral() {
        use pal::snp::qvl::{validate::AttestationVerificationParams, verify::SnpQvl};
        use pal::traits::QvlLibrary;

        let expected = FIXTURE_REPORT[0x50..0x80].try_into().unwrap();
        let mut modified_report = FIXTURE_REPORT.to_vec();
        modified_report[0x2a0] ^= 1;
        assert!(SnpQvl
            .verify(
                &AttestationVerificationParams::crypto_only(&modified_report, &expected),
                &[FIXTURE_VCEK.to_vec(), FIXTURE_ASK.to_vec()],
            )
            .is_err());
        let mut modified_vcek = FIXTURE_VCEK.to_vec();
        let last = modified_vcek.len() - 1;
        modified_vcek[last] ^= 1;
        assert!(SnpQvl
            .verify(
                &AttestationVerificationParams::crypto_only(FIXTURE_REPORT, &expected),
                &[modified_vcek, FIXTURE_ASK.to_vec()],
            )
            .is_err());
    }

    #[test]
    fn test_fixture_verifier_accepts_complete_report_data() {
        use pal::snp::qvl::{validate::AttestationVerificationParams, verify::SnpQvl};
        use pal::traits::QvlLibrary;

        let expected: [u8; 48] = FIXTURE_REPORT[0x50..0x80].try_into().unwrap();
        assert_eq!(&FIXTURE_REPORT[0x80..0x90], &[0u8; 16]);
        let params = AttestationVerificationParams::crypto_only(FIXTURE_REPORT, &expected);
        SnpQvl
            .verify(&params, &[FIXTURE_VCEK.to_vec(), FIXTURE_ASK.to_vec()])
            .expect("fixture signature, collateral, and complete REPORT_DATA verification");
    }

    #[test]
    fn test_build_fixture_blob() {
        let blob = build_fixture_blob().expect("build_fixture_blob");
        assert_eq!(&blob[..1184], FIXTURE_REPORT, "report bytes match");
        assert!(blob.len() > 1184, "cert chain appended");
        println!("build_fixture_blob OK: {} bytes total", blob.len());
    }
}
