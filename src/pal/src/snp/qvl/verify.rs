// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! AMD SNP attestation report + certificate chain verification.
//!
//! Uses ring-based crypto (via the `crypto` crate) rather than TAV's
//! `verify_attestation`, which is gated on recognised processor generations
//! and fails for cpuid_fam_id=0xD9 (Azure AMD CVMs).
//!
//! Phase 1: cert chain verified (ARK->ASK->VCEK) + VCEK report sig verified.
//! Phase 2: validate() extended with tcb_ge() + policy checks.

#[cfg(feature = "snp-emu")]
use ::crypto::{verify_snp_cert_chain_der, verify_snp_report_sig};

use crate::traits::{PalError, QvlLibrary};
use crate::types::{PlatformType, QvlResult, TcbStatus};
use crate::snp::qvl::validate::{validate, AttestationVerificationParams};

pub struct SnpQvl;

#[cfg(feature = "snp-emu")]
impl QvlLibrary for SnpQvl {
    /// Verify the SNP attestation report and its AMD certificate chain.
    ///
    /// `cert_chain` must be [vcek_der, ask_der, ark_der].
    /// `params.report` must be exactly 1184 bytes.
    fn verify(
        &self,
        params: &AttestationVerificationParams<'_>,
        cert_chain: &[Vec<u8>],
    ) -> Result<QvlResult, PalError> {
        if cert_chain.len() < 3 {
            return Err(PalError::InvalidInput);
        }

        let (vcek_der, ask_der, ark_der) = (&cert_chain[0], &cert_chain[1], &cert_chain[2]);

        // 1. Verify ARK->ASK->VCEK cert chain. Returns VCEK public key bytes.
        let vcek_pubkey = verify_snp_cert_chain_der(ark_der, ask_der, vcek_der)
            .map_err(|e| PalError::VerificationFailed(format!("cert chain: {:?}", e)))?;

        // 2. Verify SNP report ECDSA-P384 signature over report[0..0x2A0].
        verify_snp_report_sig(&vcek_pubkey, params.report)
            .map_err(|e| PalError::VerificationFailed(format!("report sig: {:?}", e)))?;

        // 3. Phase 1 validate() stub. Phase 2: tcb_ge + policy.
        validate(params)?;

        log::info!("SnpQvl: ARK->ASK->VCEK chain + VCEK report sig OK");
        Ok(QvlResult {
            platform: PlatformType::AmdSnp,
            tcb_status: TcbStatus::UpToDate,
        })
    }
}
