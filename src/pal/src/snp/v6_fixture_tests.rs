// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Saved fixture codec conformance only; no common verifier or runtime activation.

use super::{
    collateral_set::SnpCollateralSetV1,
    ma_evidence::SnpMaEvidenceV1,
    ma_policy::{FixedReleaseAllowlistV1, MaPolicyIdentityInputV1},
    purpose_binding::sha384,
    report_data_context::{SnpEvidencePurposeV1, SnpMaRoleV1},
};

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            "../../../snp_emu/src/fixture_data/venice_v6_synthetic/",
            $name
        ))
    };
}

#[test]
fn saved_v6_fixtures_match_frozen_identity_allowlist_and_collateral_codecs() {
    let identity = MaPolicyIdentityInputV1::decode_exact(fixture!("identity/input.bin")).unwrap();
    assert_eq!(
        identity.encode_exact().unwrap(),
        *fixture!("identity/input.bin")
    );
    let allowlist =
        FixedReleaseAllowlistV1::decode_exact(fixture!("allowlists/approved.bin")).unwrap();
    assert_eq!(allowlist.identity_digest, identity.digest().unwrap());
    assert_eq!(
        allowlist.encode_exact().unwrap(),
        *fixture!("allowlists/approved.bin")
    );
    let bytes = fixture!("collateral/report-chain.bin");
    let collateral = SnpCollateralSetV1::decode_exact(bytes).unwrap();
    assert_eq!(collateral.encode_exact().unwrap().as_slice(), bytes);
    assert_eq!(
        collateral.leaf_certificate.certificate_der,
        fixture!("certificates/vcek.der")
    );
    assert_eq!(
        collateral.ask_certificate.certificate_der,
        fixture!("certificates/ask.der")
    );
}

#[test]
fn saved_ma_envelopes_use_v2_contexts_and_bind_the_full_report_data() {
    let identity = MaPolicyIdentityInputV1::decode_exact(fixture!("identity/input.bin")).unwrap();
    let records: &[(&[u8], SnpMaRoleV1, SnpEvidencePurposeV1)] = &[
        (
            fixture!("envelopes/source_session_v2.bin"),
            SnpMaRoleV1::Source,
            SnpEvidencePurposeV1::InterNodeSessionV2,
        ),
        (
            fixture!("envelopes/destination_session_v2.bin"),
            SnpMaRoleV1::Destination,
            SnpEvidencePurposeV1::InterNodeSessionV2,
        ),
        (
            fixture!("envelopes/source_authorization_v2.bin"),
            SnpMaRoleV1::Source,
            SnpEvidencePurposeV1::InterNodeTenantAuthorizationV2,
        ),
        (
            fixture!("envelopes/destination_authorization_v2.bin"),
            SnpMaRoleV1::Destination,
            SnpEvidencePurposeV1::InterNodeTenantAuthorizationV2,
        ),
    ];
    for (bytes, role, purpose) in records {
        let evidence = SnpMaEvidenceV1::decode_exact(bytes).unwrap();
        assert_eq!(evidence.encode_exact().unwrap().as_slice(), *bytes);
        assert_eq!(evidence.header.role, *role);
        assert_eq!(evidence.header.evidence_purpose, *purpose);
        assert_eq!(
            evidence.report_data_context.ma_policy_identity_digest,
            identity.digest().unwrap()
        );
        assert_eq!(
            evidence.collateral_digest,
            sha384(fixture!("collateral/report-chain.bin"))
        );
        let report_data = evidence.ma_report[0x50..0x90].try_into().unwrap();
        evidence
            .report_data_context
            .verify_report_data(report_data)
            .unwrap();
    }
}
