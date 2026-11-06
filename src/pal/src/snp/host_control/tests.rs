use super::*;
use crate::snp::{
    collateral_set::{SnpCertificateEntryV1, SnpCertificateRoleV1},
    evidence_header::{SnpEvidenceProfileV1, SnpTcbProfileV1},
};

fn package(fixture: bool) -> TenantEvidencePackage {
    let report = [31; 1184];
    let evidence = if fixture {
        SnpEvidenceInput::EmulatorV1(Box::new(SnpEmulatorEvidenceV1 {
            report,
            supplement: [43; 220],
            supplement_signature: [57; 96],
        }))
    } else {
        SnpEvidenceInput::RawAmdReport {
            report: Box::new(report),
        }
    };
    TenantEvidencePackage::new(
        evidence,
        SnpCollateralSetV1 {
            evidence_profile: if fixture {
                SnpEvidenceProfileV1::Fixture
            } else {
                SnpEvidenceProfileV1::Production
            },
            tcb_profile: SnpTcbProfileV1::Venice,
            leaf_certificate: SnpCertificateEntryV1 {
                role: SnpCertificateRoleV1::Vcek,
                certificate_der: vec![1; 16],
            },
            ask_certificate: SnpCertificateEntryV1 {
                role: SnpCertificateRoleV1::Ask,
                certificate_der: vec![2; 16],
            },
        },
    )
    .unwrap()
}

fn frame(fixture: bool, reference: bool) -> HostControlFrameV1 {
    let package = package(fixture);
    let operation = SnpOperationContext {
        peer: Some(PeerRoutingReference::new(0)),
        protocol_version: Some(ProtocolVersion::new(1, 0)),
        policy: Some(PolicyIdentity::new(23)),
        ..SnpOperationContext::new(
            HostRequestId::new(11),
            MigrationId::new(12),
            MigrationRole::Source,
            ManagedGuestHandle::new(13),
        )
    };
    let delivery = if reference {
        TenantReportDeliveryV1::Reference(TenantReportReferenceV1::new(sha384(
            package.evidence().report(),
        )))
    } else {
        TenantReportDeliveryV1::Inline(
            HostPushedTenantReportV1::from_bytes(package.evidence().report()).unwrap(),
        )
    };
    HostControlFrameV1 {
        kind: HostControlKindV1::Prepare,
        response: false,
        operation,
        body: HostControlBodyV1::Prepare {
            request: PrepareMigrationRequestV1::new(operation, delivery),
            package_digest: sha384(&package.encode_host_package_v1().unwrap()),
            package: if reference {
                None
            } else {
                Some(Box::new(package.clone()))
            },
            ma_profiles: Box::new(HostMaProfilesV1 {
                source: package.clone(),
                destination: package,
            }),
        },
    }
}

#[test]
fn host_query_matches_independent_python_struct_vector() {
    let query = HostControlFrameV1 {
        kind: HostControlKindV1::Query,
        response: false,
        operation: frame(false, true).operation,
        body: HostControlBodyV1::Empty,
    };
    let bytes = query.encode_exact().unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "534e502d48433031010004000000000048000000000000000b000000000000000c000000000000000d00000000000000000000000000000017000000000000000100000001070000");
}

#[test]
fn host_frame_roundtrips_complete_profiles_and_preserves_base_reference() {
    for fixture in [false, true] {
        for reference in [false, true] {
            let frame = frame(fixture, reference);
            let bytes = frame.encode_exact().unwrap();
            assert_eq!(HostControlFrameV1::decode_exact(&bytes).unwrap(), frame);
            assert_eq!(&bytes[..8], b"SNP-HC01");
            assert_eq!(
                u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize,
                bytes.len()
            );
        }
    }
}

#[test]
fn host_frame_rejects_all_truncations_and_trailing_bytes() {
    let bytes = frame(true, false).encode_exact().unwrap();
    for end in 0..bytes.len() {
        assert!(HostControlFrameV1::decode_exact(&bytes[..end]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(HostControlFrameV1::decode_exact(&extra).is_err());
    assert_eq!(
        HostControlFrameV1::decode_exact(&vec![0; MAX_HOST_CONTROL_FRAME_V1 + 1]),
        Err(SnpCodecError::RecordTooLarge)
    );
}

#[test]
fn host_frame_rejects_unknown_enums_flags_reserved_fields_and_substitution() {
    let bytes = frame(true, false).encode_exact().unwrap();
    for index in [0, 8, 10, 12, 13, 20, 68, 69, 70] {
        let mut bad = bytes.clone();
        bad[index] = 255;
        assert!(HostControlFrameV1::decode_exact(&bad).is_err(), "{index}");
    }
    let mut bad = frame(true, false);
    bad.operation.managed_guest = ManagedGuestHandle::new(999);
    assert!(bad.encode_exact().is_err());
    let HostControlBodyV1::Prepare { package_digest, .. } = &mut bad.body else {
        unreachable!()
    };
    package_digest[0] ^= 1;
    assert!(bad.encode_exact().is_err());
}

#[test]
fn operation_codec_distinguishes_absent_and_present_zero_options_and_roles() {
    for role in [MigrationRole::Source, MigrationRole::Destination] {
        let mut value = frame(false, true).operation;
        value.role = role;
        for present in [false, true] {
            value.peer = present.then_some(PeerRoutingReference::new(0));
            value.policy = present.then_some(PolicyIdentity::new(0));
            value.protocol_version = present.then_some(ProtocolVersion::new(0, 0));
            let mut bytes = [0; 48];
            encode_operation(&mut StrictWriter::new(&mut bytes), &value).unwrap();
            assert_eq!(
                decode_operation(&mut StrictReader::new(&bytes)).unwrap(),
                value
            );
        }
    }
}

#[test]
fn host_responses_are_correlated_typed_and_not_valid_as_requests() {
    for kind in [
        HostControlKindV1::Prepare,
        HostControlKindV1::Cancel,
        HostControlKindV1::Abort,
        HostControlKindV1::Query,
    ] {
        for outcome in [
            ReplayTerminalOutcomeV1::Succeeded,
            ReplayTerminalOutcomeV1::Failed,
            ReplayTerminalOutcomeV1::Aborted,
        ] {
            let response = HostControlFrameV1 {
                kind,
                response: true,
                operation: frame(false, false).operation,
                body: HostControlBodyV1::Status {
                    phase: HostOperationPhaseV1::Terminal,
                    terminal: Some(ReplayTerminalResultV1 {
                        outcome,
                        result_digest: [17; 48],
                    }),
                },
            };
            assert_eq!(
                HostControlFrameV1::decode_exact(&response.encode_exact().unwrap()).unwrap(),
                response
            );
            let mut bad = response;
            bad.response = false;
            assert!(bad.encode_exact().is_err());
        }
    }
}

#[test]
fn package_codec_does_not_confuse_fixture_supplement_with_production_layout() {
    let fixture = package(true);
    let raw = package(false);
    for package in [&fixture, &raw] {
        let bytes = package.encode_host_package_v1().unwrap();
        assert_eq!(
            TenantEvidencePackage::decode_host_package_v1(&bytes).unwrap(),
            *package
        );
        assert!(TenantEvidencePackage::decode_host_package_v1(&bytes[..bytes.len() - 1]).is_err());
    }
    let mut bad = fixture.encode_host_package_v1().unwrap();
    bad[0] = 0;
    assert!(TenantEvidencePackage::decode_host_package_v1(&bad).is_err());
}

#[test]
fn unavailable_host_transport_never_returns_or_delivers_success() {
    let mut provider = UnavailableSnpHostControlTransportV1;
    for _ in 0..2 {
        assert_eq!(
            provider.receive(),
            Err(HostControlErrorV1::ProviderUnavailable)
        );
        assert_eq!(
            provider.respond(&frame(false, true)),
            Err(HostControlErrorV1::ProviderUnavailable)
        );
    }
}
