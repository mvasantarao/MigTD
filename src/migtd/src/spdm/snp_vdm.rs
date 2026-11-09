// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Static SNP opcode, element, and payload-length validation.

use pal::snp::{
    limits::{validate_snp_application_message_size, SNP_VDM_SINGLE_ELEMENT_OVERHEAD},
    peer_channel::active_inter_node_layout,
};

use super::spdm_vdm::{VdmMessage, VdmMessageElement};

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
        active_inter_node_layout(message.op_code.get_u8())
            .ok_or(SnpVdmValidationError::NotSnpOpcode)?;

    if element.element_type.get_u16() != expected_element {
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
    use super::super::spdm_vdm::{VdmMessageElementType, VdmMessageOpCode};
    use super::*;
    use crate::spdm::{VDM_MESSAGE_MAJOR_VERSION, VDM_MESSAGE_MINOR_VERSION};
    use pal::snp::{
        authorization_result::SnpAuthorizationResultV1, collateral_set::SnpCollateralSetV1,
        limits::MAX_SNP_COLLATERAL_SET_SIZE, ma_evidence::SnpMaEvidenceV1,
        tenant_evidence::SnpTenantEvidenceV1,
    };

    #[test]
    fn direct_random_v2_schedule_has_distinct_exact_opcode_and_element_mappings() {
        let rows = [
            (
                VdmMessageOpCode::DeliverSnpKeyV2Req,
                0x30,
                VdmMessageElementType::SnpKeyDeliveryV2,
                0x0109,
                168,
            ),
            (
                VdmMessageOpCode::DeliverSnpKeyV2Rsp,
                0x31,
                VdmMessageElementType::SnpKeyAcceptanceV2,
                0x010a,
                80,
            ),
            (
                VdmMessageOpCode::PollSnpCompletionV2Req,
                0x32,
                VdmMessageElementType::SnpInstallSessionControlV2,
                0x010c,
                80,
            ),
            (
                VdmMessageOpCode::PollSnpCompletionV2Rsp,
                0x33,
                VdmMessageElementType::SnpFirmwareCompletionV2,
                0x010b,
                88,
            ),
            (
                VdmMessageOpCode::SubmitSnpCompletionV2Req,
                0x34,
                VdmMessageElementType::SnpFirmwareCompletionV2,
                0x010b,
                88,
            ),
            (
                VdmMessageOpCode::SubmitSnpCompletionV2Rsp,
                0x35,
                VdmMessageElementType::SnpInstallSessionControlV2,
                0x010c,
                80,
            ),
        ];
        for (opcode, number, tag, element_number, size) in rows {
            assert_eq!(opcode.get_u8(), number);
            assert_eq!(tag.get_u16(), element_number);
            assert_eq!(
                validate_snp_vdm_static_layout(&message(opcode), &element(tag, size)),
                Ok(())
            );
            for wrong_size in [size - 1, size + 1] {
                assert_eq!(
                    validate_snp_vdm_static_layout(&message(opcode), &element(tag, wrong_size)),
                    Err(SnpVdmValidationError::InvalidElementLength)
                );
            }
            assert_eq!(
                validate_snp_vdm_static_layout(
                    &message(opcode),
                    &element(VdmMessageElementType::SnpInstallationResultV1, 136)
                ),
                Err(SnpVdmValidationError::UnexpectedElementType)
            );
        }
    }

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

    #[test]
    fn historical_contribution_numbers_are_reserved_and_rejected() {
        assert_eq!(
            VdmMessageOpCode::ExchangeSnpKeyContributionReq.get_u8(),
            0x26
        );
        assert_eq!(
            VdmMessageOpCode::ExchangeSnpKeyContributionRsp.get_u8(),
            0x27
        );
        assert_eq!(
            VdmMessageElementType::SnpKeyContributionV1.get_u16(),
            0x0104
        );
        for opcode in [
            VdmMessageOpCode::ExchangeSnpKeyContributionReq,
            VdmMessageOpCode::ExchangeSnpKeyContributionRsp,
        ] {
            assert_eq!(
                validate_snp_vdm_static_layout(
                    &message(opcode),
                    &element(VdmMessageElementType::SnpKeyContributionV1, 272),
                ),
                Err(SnpVdmValidationError::NotSnpOpcode)
            );
            for length in [0, 271, 273, usize::MAX] {
                assert_eq!(
                    validate_snp_vdm_static_layout(
                        &message(opcode),
                        &element(VdmMessageElementType::SnpKeyContributionV1, length),
                    ),
                    Err(SnpVdmValidationError::NotSnpOpcode)
                );
            }
            for count in [0, 2] {
                let mut invalid = message(opcode);
                invalid.element_count = count;
                assert_eq!(
                    validate_snp_vdm_static_layout(
                        &invalid,
                        &element(VdmMessageElementType::SnpKeyContributionV1, 272),
                    ),
                    Err(SnpVdmValidationError::InvalidElementCount)
                );
            }
            assert_eq!(
                validate_snp_vdm_static_layout(
                    &message(opcode),
                    &element(VdmMessageElementType::ForwardMigrationSessionKey, 272),
                ),
                Err(SnpVdmValidationError::NotSnpOpcode)
            );
        }
        assert_eq!(SNP_VDM_SINGLE_ELEMENT_OVERHEAD + 272, 282);
    }

    #[test]
    fn confirmation_elements_are_reserved_but_not_activated_on_existing_opcodes() {
        assert_eq!(VdmMessageElementType::SnpConfirmationV1.get_u16(), 0x0105);
        assert_eq!(
            VdmMessageElementType::SnpInstallationResultV1.get_u16(),
            0x0106
        );
        for (element_type, size) in [
            (VdmMessageElementType::SnpConfirmationV1, 128),
            (VdmMessageElementType::SnpInstallationResultV1, 136),
        ] {
            assert_eq!(
                validate_snp_vdm_static_layout(
                    &message(VdmMessageOpCode::ExchangeSnpKeyContributionReq),
                    &element(element_type, size)
                ),
                Err(SnpVdmValidationError::NotSnpOpcode)
            );
            assert!(SNP_VDM_SINGLE_ELEMENT_OVERHEAD + size <= 8192);
        }
    }
}
