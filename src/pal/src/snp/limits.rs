// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Frozen Version 1 size limits for the SNP migration protocol.

use super::{
    authorization_result::SnpAuthorizationResultV1,
    ma_evidence::SnpMaEvidenceV1,
    tenant_evidence::SnpTenantEvidenceV1,
    wire::{SnpCodecError, SnpCodecResult},
};

pub const MAX_SNP_MA_EVIDENCE_SIZE: usize = 2 * 1024;
pub const MAX_SNP_TENANT_EVIDENCE_SIZE: usize = 2 * 1024;
pub const MAX_SNP_AUTHORIZATION_RESULT_SIZE: usize = 512;
pub const MAX_SNP_CERTIFICATE_SIZE: usize = 4 * 1024;
pub const MAX_SNP_COLLATERAL_SET_SIZE: usize = 4_608;
pub const MAX_SNP_APPLICATION_MESSAGE_SIZE: usize = 8 * 1024;

pub const SNP_VDM_MESSAGE_HEADER_SIZE: usize = 4;
pub const SNP_VDM_ELEMENT_HEADER_SIZE: usize = 6;
pub const SNP_VDM_SINGLE_ELEMENT_OVERHEAD: usize =
    SNP_VDM_MESSAGE_HEADER_SIZE + SNP_VDM_ELEMENT_HEADER_SIZE;

const _: () = {
    assert!(SnpMaEvidenceV1::ENCODED_SIZE <= MAX_SNP_MA_EVIDENCE_SIZE);
    assert!(SnpTenantEvidenceV1::ENCODED_SIZE <= MAX_SNP_TENANT_EVIDENCE_SIZE);
    assert!(SnpAuthorizationResultV1::ENCODED_SIZE <= MAX_SNP_AUTHORIZATION_RESULT_SIZE);
    assert!(
        MAX_SNP_CERTIFICATE_SIZE
            <= MAX_SNP_COLLATERAL_SET_SIZE
                - super::collateral_set::SnpCollateralSetV1::MINIMUM_SIZE_BEFORE_DER
    );
    assert!(
        SNP_VDM_SINGLE_ELEMENT_OVERHEAD + MAX_SNP_MA_EVIDENCE_SIZE
            <= MAX_SNP_APPLICATION_MESSAGE_SIZE
    );
    assert!(
        SNP_VDM_SINGLE_ELEMENT_OVERHEAD + MAX_SNP_TENANT_EVIDENCE_SIZE
            <= MAX_SNP_APPLICATION_MESSAGE_SIZE
    );
    assert!(
        SNP_VDM_SINGLE_ELEMENT_OVERHEAD + MAX_SNP_AUTHORIZATION_RESULT_SIZE
            <= MAX_SNP_APPLICATION_MESSAGE_SIZE
    );
    assert!(
        SNP_VDM_SINGLE_ELEMENT_OVERHEAD + MAX_SNP_COLLATERAL_SET_SIZE
            <= MAX_SNP_APPLICATION_MESSAGE_SIZE
    );
};

pub fn validate_snp_application_message_size(length: usize) -> SnpCodecResult<()> {
    if length > MAX_SNP_APPLICATION_MESSAGE_SIZE {
        return Err(SnpCodecError::MessageTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_records_fit_frozen_limits() {
        assert_eq!(SnpMaEvidenceV1::ENCODED_SIZE, 1_540);
        assert_eq!(SnpTenantEvidenceV1::ENCODED_SIZE, 1_556);
        assert_eq!(SnpAuthorizationResultV1::ENCODED_SIZE, 88);
        assert!(SnpMaEvidenceV1::ENCODED_SIZE <= MAX_SNP_MA_EVIDENCE_SIZE);
        assert!(SnpTenantEvidenceV1::ENCODED_SIZE <= MAX_SNP_TENANT_EVIDENCE_SIZE);
        assert!(SnpAuthorizationResultV1::ENCODED_SIZE <= MAX_SNP_AUTHORIZATION_RESULT_SIZE);
    }

    #[test]
    fn bounded_collateral_vdm_fits_application_limit() {
        assert_eq!(
            SNP_VDM_SINGLE_ELEMENT_OVERHEAD + MAX_SNP_COLLATERAL_SET_SIZE,
            4_618
        );
        assert!(
            SNP_VDM_SINGLE_ELEMENT_OVERHEAD + MAX_SNP_COLLATERAL_SET_SIZE
                <= MAX_SNP_APPLICATION_MESSAGE_SIZE
        );
    }

    #[test]
    fn application_message_boundary_is_exact() {
        validate_snp_application_message_size(MAX_SNP_APPLICATION_MESSAGE_SIZE).unwrap();
        assert_eq!(
            validate_snp_application_message_size(MAX_SNP_APPLICATION_MESSAGE_SIZE + 1),
            Err(SnpCodecError::MessageTooLarge)
        );
    }
}
