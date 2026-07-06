// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! AMD SNP attestation report + certificate chain verification using TAV.
//!
//! Phase 1: cert chain ARK->ASK->VCEK verified with TAV sync::verify_attestation.
//!          Report signature over [0..0x2A0] verified by TAV (ECDSA P-384).
//!          validate() is a Phase 1 stub (returns Ok unconditionally).
//! Phase 2 (P2-07): validate() extended with tcb_ge() + policy checks.
//!
//! Note: snp_report.bin is extracted from the Azure HCLA response at offset 0x20
//! (after the 32-byte HCLA wrapper header). cpuid_fam_id=0x19 (Milan, version=5).
//! Azure ark.der public key matches TAV's pinned Milan ARK exactly.

#[cfg(feature = "snp-emu")]
use tee_attestation_verification_lib::{
    certificate_from_der,
    snp::{
        report::{AttestationReport, TryFromBytes},
        verify::{sync::verify_attestation, ChainVerification},
    },
};

use crate::traits::{PalError, QvlLibrary};
use crate::types::{PlatformType, QvlResult, TcbStatus};
use crate::snp::qvl::validate::{validate, AttestationVerificationParams};

pub struct SnpQvl;

#[cfg(feature = "snp-emu")]
impl QvlLibrary for SnpQvl {
    /// Verify an SNP attestation report and its certificate chain using TAV.
    ///
    /// `cert_chain` must contain [vcek_der, ask_der, ark_der] in that order.
    /// `params.report` must be exactly 1184 bytes (AMD SNP AttestationReport).
    fn verify(
        &self,
        params: &AttestationVerificationParams<'_>,
        cert_chain: &[Vec<u8>],
    ) -> Result<QvlResult, PalError> {
        if cert_chain.len() < 3 {
            return Err(PalError::InvalidInput);
        }

        // 1. Parse DER certificates: cert_chain = [vcek, ask, ark]
        let vcek = certificate_from_der(&cert_chain[0])
            .map_err(|_| PalError::VerificationFailed("VCEK DER parse failed".into()))?;
        let ask = certificate_from_der(&cert_chain[1])
            .map_err(|_| PalError::VerificationFailed("ASK DER parse failed".into()))?;
        let ark = certificate_from_der(&cert_chain[2])
            .map_err(|_| PalError::VerificationFailed("ARK DER parse failed".into()))?;

        // 2. Parse AttestationReport (zerocopy: 1184 bytes, version=5 Milan)
        let report = AttestationReport::try_read_from_bytes(params.report)
            .map_err(|_| PalError::VerificationFailed("SNP report parse failed".into()))?;

        // 3. Verify ARK->ASK->VCEK chain + report signature using TAV.
        //    WithProvidedArk: Azure THIM-provided ARK; ark_matches_pinned() verifies
        //    it equals TAV's pinned Milan ARK (confirmed: same AMD root key).
        verify_attestation(
            &report,
            &vcek,
            &ChainVerification::WithProvidedArk { ask: &ask, ark: &ark },
        )
        .map_err(|e| PalError::VerificationFailed(format!("{}", e)))?;

        // 4. Phase 1 validate() stub — no-op. Phase 2 (P2-07): tcb_ge + policy.
        validate(params)?;

        log::info!("SnpQvl: ARK->ASK->VCEK chain + VCEK report sig OK (TAV, Milan)");
        Ok(QvlResult {
            platform: PlatformType::AmdSnp,
            tcb_status: TcbStatus::UpToDate,
        })
    }
}
