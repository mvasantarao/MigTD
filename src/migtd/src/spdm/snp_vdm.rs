// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Static SNP opcode, element, and payload-length validation.

use pal::snp::{
    authorization_result::SnpAuthorizationResultV1,
    collateral_set::SnpCollateralSetV1,
    limits::{
        validate_snp_application_message_size, MAX_SNP_COLLATERAL_SET_SIZE,
        SNP_VDM_SINGLE_ELEMENT_OVERHEAD,
    },
    ma_evidence::SnpMaEvidenceV1,
    tenant_evidence::SnpTenantEvidenceV1,
};

use super::spdm_vdm::{VdmMessage, VdmMessageElement, VdmMessageElementType, VdmMessageOpCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnpVdmValidationError {
    NotSnpOpcode,
    InvalidElementCount,
    UnexpectedElementType,
    InvalidElementLength,
    ApplicationMessageTooLarge,
}

pub fn validate_snp_vdm_static_layout(
    message: &VdmMessage,
    element: &VdmMessageElement,
) -> Result<(), SnpVdmValidationError> {
    if message.element_count != 1 {
        return Err(SnpVdmValidationError::InvalidElementCount);
    }

    let (expected_element, minimum_length, maximum_length) =
        match message.op_code {
            VdmMessageOpCode::ExchangeSnpMaEvidenceReq
            | VdmMessageOpCode::ExchangeSnpMaEvidenceRsp => (
                VdmMessageElementType::SnpMaEvidenceV1,
                SnpMaEvidenceV1::ENCODED_SIZE,
                SnpMaEvidenceV1::ENCODED_SIZE,
            ),
            VdmMessageOpCode::ExchangeSnpCollateralReq
            | VdmMessageOpCode::ExchangeSnpCollateralRsp => (
                VdmMessageElementType::SnpCollateralSetV1,
                SnpCollateralSetV1::MINIMUM_SIZE_BEFORE_DER + 2,
                MAX_SNP_COLLATERAL_SET_SIZE,
            ),
            VdmMessageOpCode::ExchangeSnpTenantEvidenceReq => (
                VdmMessageElementType::SnpTenantEvidenceV1,
                SnpTenantEvidenceV1::ENCODED_SIZE,
                SnpTenantEvidenceV1::ENCODED_SIZE,
            ),
            VdmMessageOpCode::ExchangeSnpAuthorizationResultRsp => (
                VdmMessageElementType::SnpAuthorizationResultV1,
                SnpAuthorizationResultV1::ENCODED_SIZE,
                SnpAuthorizationResultV1::ENCODED_SIZE,
            ),
            _ => return Err(SnpVdmValidationError::NotSnpOpcode),
        };

    if element.element_type != expected_element {
        return Err(SnpVdmValidationError::UnexpectedElementType);
    }

    let element_length =
        usize::try_from(element.length).map_err(|_| SnpVdmValidationError::InvalidElementLength)?;
    if element_length < minimum_length || element_length > maximum_length {
        return Err(SnpVdmValidationError::InvalidElementLength);
    }

    let application_length = SNP_VDM_SINGLE_ELEMENT_OVERHEAD
        .checked_add(element_length)
        .ok_or(SnpVdmValidationError::ApplicationMessageTooLarge)?;
    validate_snp_application_message_size(application_length)
        .map_err(|_| SnpVdmValidationError::ApplicationMessageTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spdm::{VDM_MESSAGE_MAJOR_VERSION, VDM_MESSAGE_MINOR_VERSION};

    fn message(op_code: VdmMessageOpCode) -> VdmMessage {
        VdmMessage {
            major_version: VDM_MESSAGE_MAJOR_VERSION,
            minor_version: VDM_MESSAGE_MINOR_VERSION,
            op_code,
            element_count: 1,
        }
    }

    fn element(element_type: VdmMessageElementType, length: usize) -> VdmMessageElement {
        VdmMessageElement {
            element_type,
            length: length as u32,
        }
    }

    #[test]
    fn frozen_numeric_assignments_are_exact() {
        assert_eq!(VdmMessageOpCode::ExchangeSnpMaEvidenceReq.get_u8(), 0x20);
        assert_eq!(VdmMessageOpCode::ExchangeSnpMaEvidenceRsp.get_u8(), 0x21);
        assert_eq!(VdmMessageOpCode::ExchangeSnpCollateralReq.get_u8(), 0x22);
        assert_eq!(VdmMessageOpCode::ExchangeSnpCollateralRsp.get_u8(), 0x23);
        assert_eq!(
            VdmMessageOpCode::ExchangeSnpTenantEvidenceReq.get_u8(),
            0x24
        );
        assert_eq!(
            VdmMessageOpCode::ExchangeSnpAuthorizationResultRsp.get_u8(),
            0x25
        );
        assert_eq!(VdmMessageElementType::SnpMaEvidenceV1.get_u16(), 0x0100);
        assert_eq!(VdmMessageElementType::SnpCollateralSetV1.get_u16(), 0x0101);
        assert_eq!(VdmMessageElementType::SnpTenantEvidenceV1.get_u16(), 0x0102);
        assert_eq!(
            VdmMessageElementType::SnpAuthorizationResultV1.get_u16(),
            0x0103
        );
    }

    #[test]
    fn frozen_snp_opcode_element_mappings_are_accepted() {
        let cases = [
            (
                VdmMessageOpCode::ExchangeSnpMaEvidenceReq,
                VdmMessageElementType::SnpMaEvidenceV1,
                SnpMaEvidenceV1::ENCODED_SIZE,
            ),
            (
                VdmMessageOpCode::ExchangeSnpMaEvidenceRsp,
                VdmMessageElementType::SnpMaEvidenceV1,
                SnpMaEvidenceV1::ENCODED_SIZE,
            ),
            (
                VdmMessageOpCode::ExchangeSnpCollateralReq,
                VdmMessageElementType::SnpCollateralSetV1,
                SnpCollateralSetV1::MINIMUM_SIZE_BEFORE_DER + 2,
            ),
            (
                VdmMessageOpCode::ExchangeSnpCollateralRsp,
                VdmMessageElementType::SnpCollateralSetV1,
                MAX_SNP_COLLATERAL_SET_SIZE,
            ),
            (
                VdmMessageOpCode::ExchangeSnpTenantEvidenceReq,
                VdmMessageElementType::SnpTenantEvidenceV1,
                SnpTenantEvidenceV1::ENCODED_SIZE,
            ),
            (
                VdmMessageOpCode::ExchangeSnpAuthorizationResultRsp,
                VdmMessageElementType::SnpAuthorizationResultV1,
                SnpAuthorizationResultV1::ENCODED_SIZE,
            ),
        ];

        for (op_code, element_type, length) in cases {
            validate_snp_vdm_static_layout(&message(op_code), &element(element_type, length))
                .unwrap();
        }
    }

    #[test]
    fn invalid_count_type_and_length_are_rejected() {
        let mut invalid_count = message(VdmMessageOpCode::ExchangeSnpMaEvidenceReq);
        invalid_count.element_count = 2;
        assert_eq!(
            validate_snp_vdm_static_layout(
                &invalid_count,
                &element(
                    VdmMessageElementType::SnpMaEvidenceV1,
                    SnpMaEvidenceV1::ENCODED_SIZE,
                ),
            ),
            Err(SnpVdmValidationError::InvalidElementCount)
        );

        assert_eq!(
            validate_snp_vdm_static_layout(
                &message(VdmMessageOpCode::ExchangeSnpMaEvidenceReq),
                &element(
                    VdmMessageElementType::SnpTenantEvidenceV1,
                    SnpMaEvidenceV1::ENCODED_SIZE,
                ),
            ),
            Err(SnpVdmValidationError::UnexpectedElementType)
        );

        assert_eq!(
            validate_snp_vdm_static_layout(
                &message(VdmMessageOpCode::ExchangeSnpCollateralReq),
                &element(
                    VdmMessageElementType::SnpCollateralSetV1,
                    MAX_SNP_COLLATERAL_SET_SIZE + 1,
                ),
            ),
            Err(SnpVdmValidationError::InvalidElementLength)
        );
    }

    #[test]
    fn exact_and_bounded_lengths_reject_off_by_one_values() {
        let fixed_cases = [
            (
                VdmMessageOpCode::ExchangeSnpMaEvidenceReq,
                VdmMessageElementType::SnpMaEvidenceV1,
                SnpMaEvidenceV1::ENCODED_SIZE,
            ),
            (
                VdmMessageOpCode::ExchangeSnpTenantEvidenceReq,
                VdmMessageElementType::SnpTenantEvidenceV1,
                SnpTenantEvidenceV1::ENCODED_SIZE,
            ),
            (
                VdmMessageOpCode::ExchangeSnpAuthorizationResultRsp,
                VdmMessageElementType::SnpAuthorizationResultV1,
                SnpAuthorizationResultV1::ENCODED_SIZE,
            ),
        ];

        for (op_code, element_type, length) in fixed_cases {
            for malformed_length in [length - 1, length + 1] {
                assert_eq!(
                    validate_snp_vdm_static_layout(
                        &message(op_code),
                        &element(element_type, malformed_length),
                    ),
                    Err(SnpVdmValidationError::InvalidElementLength)
                );
            }
        }

        let minimum_collateral = SnpCollateralSetV1::MINIMUM_SIZE_BEFORE_DER + 2;
        assert_eq!(
            validate_snp_vdm_static_layout(
                &message(VdmMessageOpCode::ExchangeSnpCollateralReq),
                &element(
                    VdmMessageElementType::SnpCollateralSetV1,
                    minimum_collateral - 1,
                ),
            ),
            Err(SnpVdmValidationError::InvalidElementLength)
        );

        let mut zero_elements = message(VdmMessageOpCode::ExchangeSnpMaEvidenceReq);
        zero_elements.element_count = 0;
        assert_eq!(
            validate_snp_vdm_static_layout(
                &zero_elements,
                &element(
                    VdmMessageElementType::SnpMaEvidenceV1,
                    SnpMaEvidenceV1::ENCODED_SIZE,
                ),
            ),
            Err(SnpVdmValidationError::InvalidElementCount)
        );
    }

    #[test]
    fn non_snp_opcode_is_rejected() {
        assert_eq!(
            validate_snp_vdm_static_layout(
                &message(VdmMessageOpCode::ExchangePubKeyReq),
                &element(VdmMessageElementType::PubKeyMy, 1),
            ),
            Err(SnpVdmValidationError::NotSnpOpcode)
        );
    }
}
