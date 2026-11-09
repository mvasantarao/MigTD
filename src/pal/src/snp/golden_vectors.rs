// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::{
    authorization_result::{
        SnpAuthorizationDecisionV1, SnpAuthorizationFailureV1, SnpAuthorizationResultV1,
    },
    collateral_set::{SnpCertificateEntryV1, SnpCertificateRoleV1, SnpCollateralSetV1},
    evidence_header::{
        SnpEvidenceHeaderV1, SnpEvidenceProfileV1, SnpRecordTypeV1, SnpTcbProfileV1,
    },
    ma_evidence::{SnpMaEvidenceV1, SNP_ATTESTATION_REPORT_SIZE},
    policy_identity::PolicyIdentityV1,
    report_data_context::{
        ReportDataContextV1, SnpEvidencePurposeV1, SnpMaRoleV1, SnpMigrationAlgorithmV1,
        SHA384_DIGEST_SIZE, TENANT_REPORT_ID_SIZE,
    },
    tenant_evidence::SnpTenantEvidenceV1,
    tenant_policy_context::{SnpEtcbProjectionProfileV1, TenantPolicyContextV1},
};

const REQUEST_ID: u64 = 0x0102_0304_0506_0708;

fn context(purpose: SnpEvidencePurposeV1) -> ReportDataContextV1 {
    ReportDataContextV1 {
        evidence_purpose: purpose,
        role: SnpMaRoleV1::Source,
        request_id: REQUEST_ID,
        negotiated_migration_version: 0x090A,
        algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
        tenant_binding_id: [0x11; TENANT_REPORT_ID_SIZE],
        th1: [0x22; SHA384_DIGEST_SIZE],
        purpose_binding_digest: [0x33; SHA384_DIGEST_SIZE],
        ma_policy_identity_digest: [0x44; SHA384_DIGEST_SIZE],
    }
}

fn golden_context(purpose: u8) -> [u8; ReportDataContextV1::ENCODED_SIZE] {
    let mut expected = [0u8; ReportDataContextV1::ENCODED_SIZE];
    expected[0x000..0x01C].copy_from_slice(b"AMD-SNP-MA-LM-REPORT-DATA-V1");
    expected[0x01C..0x01E].copy_from_slice(&1u16.to_le_bytes());
    expected[0x01E] = purpose;
    expected[0x01F] = 0;
    expected[0x020..0x028].copy_from_slice(&REQUEST_ID.to_le_bytes());
    expected[0x028..0x02A].copy_from_slice(&0x090Au16.to_le_bytes());
    expected[0x02A..0x02C].copy_from_slice(&3u16.to_le_bytes());
    expected[0x02C..0x04C].fill(0x11);
    expected[0x04C..0x07C].fill(0x22);
    expected[0x07C..0x0AC].fill(0x33);
    expected[0x0AC..0x0DC].fill(0x44);
    expected
}

fn header(
    record_type: SnpRecordTypeV1,
    record_length: usize,
    purpose: SnpEvidencePurposeV1,
    tcb_profile: SnpTcbProfileV1,
) -> SnpEvidenceHeaderV1 {
    SnpEvidenceHeaderV1 {
        record_type,
        record_length: record_length as u32,
        request_id: REQUEST_ID,
        role: SnpMaRoleV1::Source,
        evidence_purpose: purpose,
        evidence_profile: SnpEvidenceProfileV1::Production,
        tcb_profile,
    }
}

fn golden_header(
    record_type: u16,
    record_length: usize,
    purpose: u8,
    tcb_profile: u8,
) -> [u8; SnpEvidenceHeaderV1::ENCODED_SIZE] {
    let mut expected = [0u8; SnpEvidenceHeaderV1::ENCODED_SIZE];
    expected[0x00..0x08].copy_from_slice(b"SNP-LM-E");
    expected[0x08] = 1;
    expected[0x0A..0x0C].copy_from_slice(&record_type.to_le_bytes());
    expected[0x0C..0x10].copy_from_slice(&(record_length as u32).to_le_bytes());
    expected[0x10..0x18].copy_from_slice(&REQUEST_ID.to_le_bytes());
    expected[0x18] = 0;
    expected[0x19] = purpose;
    expected[0x1A] = 1;
    expected[0x1B] = tcb_profile;
    expected
}

fn policy_identity() -> PolicyIdentityV1 {
    PolicyIdentityV1 {
        policy_digest: [0x44; SHA384_DIGEST_SIZE],
    }
}

fn golden_policy_identity() -> [u8; PolicyIdentityV1::ENCODED_SIZE] {
    let mut expected = [0u8; PolicyIdentityV1::ENCODED_SIZE];
    expected[0] = 1;
    expected[4..8].copy_from_slice(&56u32.to_le_bytes());
    expected[8..56].fill(0x44);
    expected
}

fn tenant_policy_context() -> TenantPolicyContextV1 {
    TenantPolicyContextV1 {
        tcb_profile: SnpTcbProfileV1::Turin,
        etcb_projection_profile: SnpEtcbProjectionProfileV1::ArgSvnV1,
    }
}

fn golden_tenant_policy_context() -> [u8; TenantPolicyContextV1::ENCODED_SIZE] {
    let mut expected = [0u8; TenantPolicyContextV1::ENCODED_SIZE];
    expected[0..4].copy_from_slice(&[1, 0, 2, 1]);
    expected[4..8].copy_from_slice(&16u32.to_le_bytes());
    expected[8] = 1;
    expected[12..16].copy_from_slice(&0x1Fu32.to_le_bytes());
    expected
}

#[test]
fn nested_fixed_record_golden_vectors_are_stable() {
    let context = context(SnpEvidencePurposeV1::InterNodeKeyContribution);
    let encoded = context.encode_exact().unwrap();
    assert_eq!(encoded, golden_context(1));
    assert_eq!(
        ReportDataContextV1::decode_exact(&encoded)
            .unwrap()
            .encode_exact()
            .unwrap(),
        encoded
    );

    let header = header(
        SnpRecordTypeV1::MaEvidence,
        SnpMaEvidenceV1::ENCODED_SIZE,
        SnpEvidencePurposeV1::InterNodeKeyContribution,
        SnpTcbProfileV1::MilanGenoa,
    );
    let encoded = header.encode_exact().unwrap();
    assert_eq!(encoded, golden_header(1, 1_540, 1, 1));
    assert_eq!(
        SnpEvidenceHeaderV1::decode_exact(&encoded)
            .unwrap()
            .encode_exact()
            .unwrap(),
        encoded
    );

    let encoded = policy_identity().encode_exact().unwrap();
    assert_eq!(encoded, golden_policy_identity());
    assert_eq!(
        PolicyIdentityV1::decode_exact(&encoded)
            .unwrap()
            .encode_exact()
            .unwrap(),
        encoded
    );

    let encoded = tenant_policy_context().encode_exact().unwrap();
    assert_eq!(encoded, golden_tenant_policy_context());
    assert_eq!(
        TenantPolicyContextV1::decode_exact(&encoded)
            .unwrap()
            .encode_exact()
            .unwrap(),
        encoded
    );
}

#[test]
fn ma_evidence_golden_vector_is_stable() {
    let value = SnpMaEvidenceV1 {
        header: header(
            SnpRecordTypeV1::MaEvidence,
            SnpMaEvidenceV1::ENCODED_SIZE,
            SnpEvidencePurposeV1::InterNodeKeyContribution,
            SnpTcbProfileV1::MilanGenoa,
        ),
        report_data_context: context(SnpEvidencePurposeV1::InterNodeKeyContribution),
        policy_identity: policy_identity(),
        collateral_digest: [0x55; SHA384_DIGEST_SIZE],
        ma_report: [0x66; SNP_ATTESTATION_REPORT_SIZE],
    };
    let mut expected = [0u8; SnpMaEvidenceV1::ENCODED_SIZE];
    expected[0x000..0x020].copy_from_slice(&golden_header(1, 1_540, 1, 1));
    expected[0x020..0x0FC].copy_from_slice(&golden_context(1));
    expected[0x0FC..0x134].copy_from_slice(&golden_policy_identity());
    expected[0x134..0x164].fill(0x55);
    expected[0x164..0x604].fill(0x66);

    let encoded = value.encode_exact().unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(
        SnpMaEvidenceV1::decode_exact(&encoded)
            .unwrap()
            .encode_exact()
            .unwrap(),
        encoded
    );
}

#[test]
fn tenant_evidence_golden_vector_is_stable() {
    let value = SnpTenantEvidenceV1 {
        header: header(
            SnpRecordTypeV1::TenantEvidence,
            SnpTenantEvidenceV1::ENCODED_SIZE,
            SnpEvidencePurposeV1::InterNodeTenantAuthorization,
            SnpTcbProfileV1::Turin,
        ),
        report_data_context: context(SnpEvidencePurposeV1::InterNodeTenantAuthorization),
        policy_identity: policy_identity(),
        tenant_policy_context: tenant_policy_context(),
        collateral_digest: [0x55; SHA384_DIGEST_SIZE],
        tenant_report: [0x66; SNP_ATTESTATION_REPORT_SIZE],
    };
    let mut expected = [0u8; SnpTenantEvidenceV1::ENCODED_SIZE];
    expected[0x000..0x020].copy_from_slice(&golden_header(2, 1_556, 2, 2));
    expected[0x020..0x0FC].copy_from_slice(&golden_context(2));
    expected[0x0FC..0x134].copy_from_slice(&golden_policy_identity());
    expected[0x134..0x144].copy_from_slice(&golden_tenant_policy_context());
    expected[0x144..0x174].fill(0x55);
    expected[0x174..0x614].fill(0x66);

    let encoded = value.encode_exact().unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(
        SnpTenantEvidenceV1::decode_exact(&encoded)
            .unwrap()
            .encode_exact()
            .unwrap(),
        encoded
    );
}

#[test]
fn authorization_and_collateral_golden_vectors_are_stable() {
    let authorization = SnpAuthorizationResultV1 {
        request_id: REQUEST_ID,
        decision: SnpAuthorizationDecisionV1::Rejected,
        evidence_profile: SnpEvidenceProfileV1::Production,
        tcb_profile: SnpTcbProfileV1::Turin,
        failure: SnpAuthorizationFailureV1::PolicyDenied,
        algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
        negotiated_migration_version: 0x090A,
        authorization_context_digest: [0x77; SHA384_DIGEST_SIZE],
    };
    let mut expected = [0u8; SnpAuthorizationResultV1::ENCODED_SIZE];
    expected[0x00..0x08].copy_from_slice(b"SNP-LM-A");
    expected[0x08] = 1;
    expected[0x0A..0x0C].copy_from_slice(&4u16.to_le_bytes());
    expected[0x0C..0x10].copy_from_slice(&88u32.to_le_bytes());
    expected[0x10..0x18].copy_from_slice(&REQUEST_ID.to_le_bytes());
    expected[0x18..0x1C].copy_from_slice(&[2, 1, 1, 2]);
    expected[0x1C..0x1E].copy_from_slice(&0x000Cu16.to_le_bytes());
    expected[0x1E..0x20].copy_from_slice(&3u16.to_le_bytes());
    expected[0x20..0x22].copy_from_slice(&0x090Au16.to_le_bytes());
    expected[0x28..0x58].fill(0x77);
    let encoded = authorization.encode_exact().unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(
        SnpAuthorizationResultV1::decode_exact(&encoded)
            .unwrap()
            .encode_exact()
            .unwrap(),
        encoded
    );

    for leaf_role in [SnpCertificateRoleV1::Vcek, SnpCertificateRoleV1::Vlek] {
        let collateral = SnpCollateralSetV1 {
            evidence_profile: SnpEvidenceProfileV1::Production,
            tcb_profile: SnpTcbProfileV1::MilanGenoa,
            leaf_certificate: SnpCertificateEntryV1 {
                role: leaf_role,
                certificate_der: vec![0x30, 0x03, 0x02, 0x01, 0x01],
            },
            ask_certificate: SnpCertificateEntryV1 {
                role: SnpCertificateRoleV1::Ask,
                certificate_der: vec![0x30, 0x03, 0x02, 0x01, 0x02],
            },
        };
        let mut expected = vec![0u8; 50];
        expected[0x00..0x08].copy_from_slice(b"SNP-LM-C");
        expected[0x08] = 1;
        expected[0x0A..0x0C].copy_from_slice(&3u16.to_le_bytes());
        expected[0x0C..0x10].copy_from_slice(&50u32.to_le_bytes());
        expected[0x10..0x14].copy_from_slice(&[1, 1, 2, 0]);
        expected[0x18..0x1A].copy_from_slice(&(leaf_role as u16).to_le_bytes());
        expected[0x1C..0x20].copy_from_slice(&5u32.to_le_bytes());
        expected[0x20..0x25].copy_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x01]);
        expected[0x25..0x27].copy_from_slice(&3u16.to_le_bytes());
        expected[0x29..0x2D].copy_from_slice(&5u32.to_le_bytes());
        expected[0x2D..0x32].copy_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x02]);
        let encoded = collateral.encode_exact().unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(
            SnpCollateralSetV1::decode_exact(&encoded)
                .unwrap()
                .encode_exact()
                .unwrap(),
            encoded
        );
    }
}
