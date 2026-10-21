// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::{
    authorization_result::{
        SnpAuthorizationDecisionV1, SnpAuthorizationFailureV1, SnpAuthorizationResultV1,
    },
    collateral_set::{SnpCertificateEntryV1, SnpCertificateRoleV1, SnpCollateralSetV1},
    evidence_header::{SnpEvidenceHeaderV1, SnpEvidenceProfileV1, SnpTcbProfileV1},
    limits::MAX_SNP_COLLATERAL_SET_SIZE,
    ma_evidence::SnpMaEvidenceV1,
    policy_identity::PolicyIdentityV1,
    report_data_context::{
        ReportDataContextV1, SnpEvidencePurposeV1, SnpMaRoleV1, SnpMigrationAlgorithmV1,
        SHA384_DIGEST_SIZE, TENANT_REPORT_ID_SIZE,
    },
    tenant_evidence::SnpTenantEvidenceV1,
    tenant_policy_context::{SnpEtcbProjectionProfileV1, TenantPolicyContextV1},
};

fn next_u64(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

fn fill<const N: usize>(state: &mut u64) -> [u8; N] {
    let mut bytes = [0u8; N];
    for byte in &mut bytes {
        *byte = next_u64(state) as u8;
    }
    bytes
}

fn assert_all_truncations_rejected<T, E>(encoded: &[u8], decode: impl Fn(&[u8]) -> Result<T, E>) {
    for end in 0..encoded.len() {
        assert!(decode(&encoded[..end]).is_err(), "accepted length {end}");
    }
}

#[test]
fn seeded_fixed_record_round_trips_are_stable() {
    let mut state = 0xC0DE_CAFE_1234_5678;
    for index in 0..256 {
        let purpose = match index % 3 {
            0 => SnpEvidencePurposeV1::MaKeyContribution,
            1 => SnpEvidencePurposeV1::TenantMigrationAuthorization,
            _ => SnpEvidencePurposeV1::PostInstallConfirmation,
        };
        let role = if index % 2 == 0 {
            SnpMaRoleV1::Source
        } else {
            SnpMaRoleV1::Destination
        };
        let context = ReportDataContextV1 {
            evidence_purpose: purpose,
            role,
            request_id: next_u64(&mut state),
            negotiated_migration_version: next_u64(&mut state) as u16,
            algorithm: SnpMigrationAlgorithmV1::Aes256Gcm,
            tenant_report_id: fill::<TENANT_REPORT_ID_SIZE>(&mut state),
            th1: fill::<SHA384_DIGEST_SIZE>(&mut state),
            contribution_commitment: fill::<SHA384_DIGEST_SIZE>(&mut state),
            local_policy_digest: fill::<SHA384_DIGEST_SIZE>(&mut state),
        };
        let encoded = context.encode_exact().unwrap();
        assert_eq!(
            ReportDataContextV1::decode_exact(&encoded).unwrap(),
            context
        );

        let identity = PolicyIdentityV1 {
            policy_digest: fill::<SHA384_DIGEST_SIZE>(&mut state),
        };
        let encoded = identity.encode_exact().unwrap();
        assert_eq!(PolicyIdentityV1::decode_exact(&encoded).unwrap(), identity);

        let tenant_context = TenantPolicyContextV1 {
            tcb_profile: if index % 2 == 0 {
                SnpTcbProfileV1::MilanGenoa
            } else {
                SnpTcbProfileV1::Turin
            },
            etcb_projection_profile: SnpEtcbProjectionProfileV1::ArgSvnV1,
        };
        let encoded = tenant_context.encode_exact().unwrap();
        assert_eq!(
            TenantPolicyContextV1::decode_exact(&encoded).unwrap(),
            tenant_context
        );

        let accepted = index % 2 == 0;
        let authorization = SnpAuthorizationResultV1 {
            request_id: next_u64(&mut state),
            decision: if accepted {
                SnpAuthorizationDecisionV1::Accepted
            } else {
                SnpAuthorizationDecisionV1::Rejected
            },
            evidence_profile: if index % 4 < 2 {
                SnpEvidenceProfileV1::Production
            } else {
                SnpEvidenceProfileV1::Fixture
            },
            tcb_profile: tenant_context.tcb_profile,
            failure: if accepted {
                SnpAuthorizationFailureV1::None
            } else {
                SnpAuthorizationFailureV1::EvidenceInvalid
            },
            algorithm: SnpMigrationAlgorithmV1::Aes256Gcm,
            negotiated_migration_version: next_u64(&mut state) as u16,
            authorization_context_digest: fill::<SHA384_DIGEST_SIZE>(&mut state),
        };
        let encoded = authorization.encode_exact().unwrap();
        assert_eq!(
            SnpAuthorizationResultV1::decode_exact(&encoded).unwrap(),
            authorization
        );
    }
}

#[test]
fn collateral_role_and_length_combinations_round_trip() {
    let lengths = [1usize, 2, 31, 256, 1_024, 1_677, 2_048];
    for role in [SnpCertificateRoleV1::Vcek, SnpCertificateRoleV1::Vlek] {
        for leaf_length in lengths {
            for ask_length in lengths {
                let encoded_length = 40 + leaf_length + ask_length;
                if encoded_length > MAX_SNP_COLLATERAL_SET_SIZE {
                    continue;
                }
                let value = SnpCollateralSetV1 {
                    evidence_profile: SnpEvidenceProfileV1::Production,
                    tcb_profile: SnpTcbProfileV1::MilanGenoa,
                    leaf_certificate: SnpCertificateEntryV1 {
                        role,
                        certificate_der: vec![0xA5; leaf_length],
                    },
                    ask_certificate: SnpCertificateEntryV1 {
                        role: SnpCertificateRoleV1::Ask,
                        certificate_der: vec![0x5A; ask_length],
                    },
                };
                let encoded = value.encode_exact().unwrap();
                assert_eq!(encoded.len(), encoded_length);
                assert_eq!(SnpCollateralSetV1::decode_exact(&encoded).unwrap(), value);
            }
        }
    }
}

#[test]
fn every_truncation_of_valid_records_is_rejected() {
    let context = ReportDataContextV1 {
        evidence_purpose: SnpEvidencePurposeV1::TenantMigrationAuthorization,
        role: SnpMaRoleV1::Source,
        request_id: 1,
        negotiated_migration_version: 1,
        algorithm: SnpMigrationAlgorithmV1::Aes256Gcm,
        tenant_report_id: [1; TENANT_REPORT_ID_SIZE],
        th1: [2; SHA384_DIGEST_SIZE],
        contribution_commitment: [3; SHA384_DIGEST_SIZE],
        local_policy_digest: [4; SHA384_DIGEST_SIZE],
    };
    assert_all_truncations_rejected(&context.encode_exact().unwrap(), |bytes| {
        ReportDataContextV1::decode_exact(bytes)
    });

    let identity = PolicyIdentityV1 {
        policy_digest: [5; SHA384_DIGEST_SIZE],
    };
    assert_all_truncations_rejected(&identity.encode_exact().unwrap(), |bytes| {
        PolicyIdentityV1::decode_exact(bytes)
    });

    let tenant_context = TenantPolicyContextV1 {
        tcb_profile: SnpTcbProfileV1::Turin,
        etcb_projection_profile: SnpEtcbProjectionProfileV1::ArgSvnV1,
    };
    assert_all_truncations_rejected(&tenant_context.encode_exact().unwrap(), |bytes| {
        TenantPolicyContextV1::decode_exact(bytes)
    });

    let authorization = SnpAuthorizationResultV1 {
        request_id: 2,
        decision: SnpAuthorizationDecisionV1::Rejected,
        evidence_profile: SnpEvidenceProfileV1::Fixture,
        tcb_profile: SnpTcbProfileV1::Turin,
        failure: SnpAuthorizationFailureV1::PolicyDenied,
        algorithm: SnpMigrationAlgorithmV1::Aes256Gcm,
        negotiated_migration_version: 1,
        authorization_context_digest: [6; SHA384_DIGEST_SIZE],
    };
    assert_all_truncations_rejected(&authorization.encode_exact().unwrap(), |bytes| {
        SnpAuthorizationResultV1::decode_exact(bytes)
    });

    let collateral = SnpCollateralSetV1 {
        evidence_profile: SnpEvidenceProfileV1::Production,
        tcb_profile: SnpTcbProfileV1::MilanGenoa,
        leaf_certificate: SnpCertificateEntryV1 {
            role: SnpCertificateRoleV1::Vcek,
            certificate_der: vec![0x30; 32],
        },
        ask_certificate: SnpCertificateEntryV1 {
            role: SnpCertificateRoleV1::Ask,
            certificate_der: vec![0x30; 64],
        },
    };
    assert_all_truncations_rejected(&collateral.encode_exact().unwrap(), |bytes| {
        SnpCollateralSetV1::decode_exact(bytes)
    });
}

#[test]
fn arbitrary_bytes_are_handled_without_panics() {
    let mut state = 0xA11C_E5E1_D00D_F00D;
    for length in (0usize..=1_600).step_by(13) {
        let mut bytes = vec![0u8; length];
        for byte in &mut bytes {
            *byte = next_u64(&mut state) as u8;
        }

        let _ = ReportDataContextV1::decode_exact(&bytes);
        let _ = SnpEvidenceHeaderV1::decode_exact(&bytes);
        let _ = PolicyIdentityV1::decode_exact(&bytes);
        let _ = TenantPolicyContextV1::decode_exact(&bytes);
        let _ = SnpMaEvidenceV1::decode_exact(&bytes);
        let _ = SnpTenantEvidenceV1::decode_exact(&bytes);
        let _ = SnpAuthorizationResultV1::decode_exact(&bytes);
        let _ = SnpCollateralSetV1::decode_exact(&bytes);
    }
}
