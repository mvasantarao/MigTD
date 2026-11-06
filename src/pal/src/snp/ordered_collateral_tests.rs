// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::{
    snp::ma_policy::ordered::*,
    tenant_identity::{VerifiedTenantIdentity, VerifiedTenantReportDeliveryV1},
    types::{HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole, SnpOperationContext},
};
use std::collections::BTreeMap;

const PUBLISHER: [u8; 48] = [0x42; 48];

struct TestOrderedPolicy;
impl LmPolicyVerifierV1 for TestOrderedPolicy {
    fn authenticate_and_canonicalize(
        &self,
        signed: &[u8],
        _: &[Vec<u8>],
        trust: MaPolicyTrustV1,
        _: u64,
    ) -> Result<AuthenticatedLmPolicyV1, MaPolicyErrorV1> {
        if signed != b"ordered-fixture-policy" || trust != MaPolicyTrustV1::Fixture {
            return Err(MaPolicyErrorV1::InvalidPolicy);
        }
        Ok(AuthenticatedLmPolicyV1 {
            canonical_semantic_bytes:
                br#"{"fixturePublisher":"42","minimumSvn":2,"profile":"ordered"}"#.to_vec(),
            rules: rules(),
            release_rules: MaPolicyReleaseRulesV1::OrderedReleaseV1 {
                publisher_id: PUBLISHER,
                minimum_svn: 2,
            },
            trust,
            issued_at: 10,
            expires_at: 200,
        })
    }
}

fn ordered_setup() -> Setup {
    let mut setup = Setup::new();
    setup.policy = VerifiedLmPolicyV1::verify(
        &TestOrderedPolicy,
        &setup.clock,
        b"ordered-fixture-policy",
        &[vec![1]],
        MaPolicyTrustV1::Fixture,
    )
    .unwrap();
    let digest = MaPolicyIdentityInputV1::from_authenticated_report(
        &setup.evidence.ma_report,
        *setup.policy.digest(),
    )
    .unwrap()
    .digest()
    .unwrap();
    setup.selected = digest;
    let mut context = setup.context.clone();
    context.ma_policy_identity_digest = digest;
    setup.evidence.policy_identity.policy_digest = *setup.policy.digest();
    setup.rebind_context(context);
    setup
}

// Explicit test-only pinned keys: separate release and historical purposes.
// Real P-384 key material is generated locally, never used for production.
struct FixtureKeys {
    release: TestSigner,
    historical: TestSigner,
    epoch: Cell<u64>,
    revoked: Cell<bool>,
    unavailable: Cell<bool>,
}

impl FixtureKeys {
    fn new() -> Self {
        Self {
            release: TestSigner::new(),
            historical: TestSigner::new(),
            epoch: Cell::new(1),
            revoked: Cell::new(false),
            unavailable: Cell::new(false),
        }
    }

    fn release_id(&self) -> [u8; 48] {
        collateral_key_id_v1(&self.release.key.public_key().as_ref().try_into().unwrap())
    }

    fn historical_id(&self) -> [u8; 48] {
        collateral_key_id_v1(
            &self
                .historical
                .key
                .public_key()
                .as_ref()
                .try_into()
                .unwrap(),
        )
    }

    fn sign_release(&self, record: &mut MaReleaseEndorsementV1) {
        let message = record.signature_message().unwrap();
        record.signature.copy_from_slice(
            self.release
                .key
                .sign(&ring::rand::SystemRandom::new(), &message)
                .unwrap()
                .as_ref(),
        );
    }

    fn sign_initial(&self, record: &mut InitialMaAuthorizationV1) {
        let message = record.signature_message().unwrap();
        record.signature.copy_from_slice(
            self.historical
                .key
                .sign(&ring::rand::SystemRandom::new(), &message)
                .unwrap()
                .as_ref(),
        );
    }

    fn snapshot(&self, identity: [u8; 48], svn: u32) -> MaReleaseEndorsementV1 {
        let mut record = MaReleaseEndorsementV1 {
            publisher_id: PUBLISHER,
            signing_key_id: self.release_id(),
            trust_epoch: self.epoch.get(),
            sequence: 10,
            issued_at: 20,
            expires_at: 180,
            mappings: vec![MaPolicyTcbMapping {
                identity_digest: identity,
                combined_svn: svn,
                status: ReleaseStatusV1::Approved,
            }],
            signature: [0; 96],
        };
        self.sign_release(&mut record);
        record
    }

    fn initial(&self, identity: [u8; 48], policy: [u8; 48], svn: u32) -> InitialMaAuthorizationV1 {
        let mut record = InitialMaAuthorizationV1 {
            publisher_id: PUBLISHER,
            signing_key_id: self.historical_id(),
            trust_epoch: self.epoch.get(),
            sequence: 1,
            issued_at: 30,
            expires_at: 170,
            tenant_report_id: [0x77; 32],
            initial_ma_report_id: [0x33; 32],
            identity_digest: identity,
            lm_policy_digest: policy,
            combined_svn: svn,
            observed_at: 25,
            signature: [0; 96],
        };
        self.sign_initial(&mut record);
        record
    }
}

impl CollateralKeyProviderV1 for FixtureKeys {
    fn authorized_key(
        &self,
        request: &CollateralKeyRequestV1,
    ) -> Result<[u8; 97], MaPolicyErrorV1> {
        if self.unavailable.get() {
            return Err(MaPolicyErrorV1::LifecycleUnavailable);
        }
        if self.revoked.get()
            || request.trust != MaPolicyTrustV1::Fixture
            || request.publisher_id != PUBLISHER
            || request.trust_epoch != self.epoch.get()
            || request.issued_at < 20
            || request.issued_at >= 180
            || request.now >= 180
        {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        let key = match request.purpose {
            CollateralSignerPurposeV1::ReleaseSnapshot => &self.release,
            CollateralSignerPurposeV1::InitialAuthorization => &self.historical,
        };
        let bytes = key.key.public_key().as_ref().try_into().unwrap();
        if collateral_key_id_v1(&bytes) != request.key_id {
            return Err(MaPolicyErrorV1::InvalidSigner);
        }
        Ok(bytes)
    }
}

#[derive(Default)]
struct FixtureState {
    // The test provider encodes the namespace explicitly. This is not a durable store.
    states: BTreeMap<Vec<u8>, CollateralStateV1>,
    fail: bool,
    conflict: bool,
    commits: usize,
}

impl FixtureState {
    fn namespace(
        trust: MaPolicyTrustV1,
        publisher: &[u8; 48],
        slot: CollateralStateSlotV1,
    ) -> Vec<u8> {
        let mut key = vec![if trust == MaPolicyTrustV1::Fixture {
            0
        } else {
            1
        }];
        key.extend_from_slice(publisher);
        match slot {
            CollateralStateSlotV1::ReleaseSnapshot => key.push(0),
            CollateralStateSlotV1::InitialAuthorization {
                tenant_report_id,
                initial_ma_report_id,
            } => {
                key.push(1);
                key.extend_from_slice(&tenant_report_id);
                key.extend_from_slice(&initial_ma_report_id);
            }
        }
        key
    }
}

impl OrderedCollateralStoreV1 for FixtureState {
    fn load_authenticated(
        &mut self,
        trust: MaPolicyTrustV1,
        publisher: &[u8; 48],
        slot: CollateralStateSlotV1,
    ) -> Result<CollateralStateV1, MaPolicyErrorV1> {
        if self.fail {
            return Err(MaPolicyErrorV1::StoreUnavailable);
        }
        Ok(self
            .states
            .get(&Self::namespace(trust, publisher, slot))
            .cloned()
            .unwrap_or(CollateralStateV1 {
                revision: 0,
                record: None,
            }))
    }
    fn commit(
        &mut self,
        trust: MaPolicyTrustV1,
        publisher: &[u8; 48],
        slot: CollateralStateSlotV1,
        revision: u64,
        record: &[u8],
    ) -> Result<(), MaPolicyErrorV1> {
        if self.fail {
            return Err(MaPolicyErrorV1::StoreUnavailable);
        }
        let key = Self::namespace(trust, publisher, slot);
        let previous = self.states.get(&key).map(|s| s.revision).unwrap_or(0);
        if self.conflict || previous != revision {
            return Err(MaPolicyErrorV1::StoreConflict);
        }
        self.states.insert(
            key,
            CollateralStateV1 {
                revision: revision + 1,
                record: Some(record.to_vec()),
            },
        );
        self.commits += 1;
        Ok(())
    }
}

struct FixtureHistory;
impl HistoricalTenantBindingProviderV1 for FixtureHistory {
    fn initial_ma_report_id(
        &self,
        _: &VerifiedTenantReportDeliveryV1,
    ) -> Result<[u8; 32], MaPolicyErrorV1> {
        Ok([0x33; 32])
    }
}

fn tenant(setup: &Setup) -> VerifiedTenantReportDeliveryV1 {
    VerifiedTenantReportDeliveryV1::from_verified_report(
        SnpOperationContext::new(
            HostRequestId::new(setup.context.request_id),
            MigrationId::new(2),
            MigrationRole::Source,
            ManagedGuestHandle::new(3),
        ),
        VerifiedTenantIdentity::from_verified_report_id([0x77; 32]),
        [0x12; 48],
        setup.request().report_trust,
        [0; 32],
        [0x34; 48],
    )
}

fn services<'a>(
    keys: &'a FixtureKeys,
    clock: &'a TestClock,
    state: &'a mut FixtureState,
) -> OrderedCollateralServicesV1<'a> {
    OrderedCollateralServicesV1 {
        keys,
        clock,
        store: state,
    }
}

#[test]
fn custom_records_exact_layout_round_trip_and_domain_separation() {
    let keys = FixtureKeys::new();
    let r = keys.snapshot([0x11; 48], 7);
    let bytes = r.encode_exact().unwrap();
    assert_eq!(bytes.len(), 304);
    assert_eq!(
        &bytes[..16],
        &[b'S', b'N', b'P', b'-', b'M', b'A', b'-', b'R', 1, 0, 2, 0, 48, 1, 0, 0]
    );
    assert_eq!(&bytes[112..120], &1u64.to_le_bytes());
    assert_eq!(&bytes[144..152], &[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[152..200], &[0x11; 48]);
    assert_eq!(&bytes[200..208], &[7, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(MaReleaseEndorsementV1::decode_exact(&bytes).unwrap(), r);
    let mut expected = b"SNP-MA-COLLATERAL-v1".to_vec();
    expected.extend_from_slice(&bytes[..208]);
    assert_eq!(r.signature_message().unwrap(), expected);
    let h = keys.initial([0x11; 48], [0x22; 48], 7);
    let bytes = h.encode_exact().unwrap();
    assert_eq!(bytes.len(), 416);
    assert_eq!(&bytes[144..176], &[0x77; 32]);
    assert_eq!(&bytes[176..208], &[0x33; 32]);
    assert_eq!(&bytes[304..312], &[7, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[312..320], &25u64.to_le_bytes());
    assert_eq!(InitialMaAuthorizationV1::decode_exact(&bytes).unwrap(), h);
}

#[test]
fn independently_generated_snapshot_and_historical_vectors_match() {
    let keys = FixtureKeys::new();
    let mut r = keys.snapshot([0x11; 48], 7);
    r.signing_key_id = [0x24; 48];
    r.signature = [0; 96];
    assert_eq!(
        hex(&sha384(&r.signature_message().unwrap())),
        "dc4ba530980b192307b657ad753761077312e96e0e2161203fe7511a47f0d8a771d35290611066b023ab1dcb2dbddc89"
    );
    let mut h = keys.initial([0x11; 48], [0x22; 48], 7);
    h.signing_key_id = [0x24; 48];
    h.signature = [0; 96];
    assert_eq!(
        hex(&sha384(&h.signature_message().unwrap())),
        "e163f6077d0cf3eee3e065a7a42ade0ffc429b9f2666ace727c40f631d6782533b45134bb9cc0a7c0e3d2dfb45614426"
    );
}

#[test]
fn bounded_decode_rejects_all_truncations_trailing_headers_reserved_and_status() {
    let keys = FixtureKeys::new();
    let bytes = keys.snapshot([1; 48], 4).encode_exact().unwrap();
    for len in 0..bytes.len() {
        assert!(MaReleaseEndorsementV1::decode_exact(&bytes[..len]).is_err());
    }
    for offset in (0..16).chain(148..152).chain(204..208) {
        let mut changed = bytes.clone();
        changed[offset] ^= 0x80;
        assert!(
            MaReleaseEndorsementV1::decode_exact(&changed).is_err(),
            "{offset}"
        );
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(MaReleaseEndorsementV1::decode_exact(&changed).is_err());
    let bytes = keys.initial([1; 48], [2; 48], 4).encode_exact().unwrap();
    for len in 0..bytes.len() {
        assert!(InitialMaAuthorizationV1::decode_exact(&bytes[..len]).is_err());
    }
    for offset in (0..16).chain(308..312) {
        let mut changed = bytes;
        changed[offset] ^= 0x80;
        assert!(InitialMaAuthorizationV1::decode_exact(&changed).is_err());
    }
    let mut changed = bytes.to_vec();
    changed.push(0);
    assert!(InitialMaAuthorizationV1::decode_exact(&changed).is_err());
}

#[test]
fn duplicate_conflicting_unsorted_and_oversized_mappings_fail() {
    let keys = FixtureKeys::new();
    let mut r = keys.snapshot([1; 48], 2);
    r.mappings.push(r.mappings[0].clone());
    assert!(r.encode_exact().is_err());
    r.mappings[1].combined_svn = 9;
    assert!(r.encode_exact().is_err());
    r.mappings[1].identity_digest = [0; 48];
    assert!(r.encode_exact().is_err());
    r.mappings = (0..=MAX_RELEASE_MAPPINGS)
        .map(|n| MaPolicyTcbMapping {
            identity_digest: {
                let mut b = [0; 48];
                b[..8].copy_from_slice(&(n as u64).to_be_bytes());
                b
            },
            combined_svn: 2,
            status: ReleaseStatusV1::Approved,
        })
        .collect();
    assert!(r.encode_exact().is_err());
    r.mappings.pop();
    let bytes = r.encode_exact().unwrap();
    assert_eq!(bytes.len(), MaReleaseEndorsementV1::MAX_ENCODED_SIZE);
    MaReleaseEndorsementV1::decode_exact(&bytes).unwrap();
}

#[test]
fn real_fixture_signature_authenticates_every_signed_byte_and_signature_byte() {
    let keys = FixtureKeys::new();
    let clock = TestClock(Cell::new(100));
    let r = keys.snapshot([1; 48], 3);
    let encoded = r.encode_exact().unwrap();
    for offset in 0..encoded.len() {
        let mut bytes = encoded.clone();
        bytes[offset] ^= 1;
        if let Ok(changed) = MaReleaseEndorsementV1::decode_exact(&bytes) {
            assert!(
                VerifiedReleaseCollateralV1::verify(
                    &changed,
                    MaPolicyTrustV1::Fixture,
                    &mut services(&keys, &clock, &mut FixtureState::default())
                )
                .is_err(),
                "{offset}"
            );
        }
    }
}

#[test]
fn production_unknown_key_wrong_purpose_and_unavailable_lifecycle_fail() {
    let keys = FixtureKeys::new();
    let clock = TestClock(Cell::new(100));
    let mut r = keys.snapshot([1; 48], 3);
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Production,
            &mut services(&keys, &clock, &mut FixtureState::default())
        )),
        MaPolicyErrorV1::ProductionProfileUnavailable
    );
    r.signing_key_id = keys.historical_id();
    keys.sign_release(&mut r);
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut FixtureState::default())
        )),
        MaPolicyErrorV1::InvalidSigner
    );
    let r = keys.snapshot([1; 48], 3);
    keys.unavailable.set(true);
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut FixtureState::default())
        )),
        MaPolicyErrorV1::LifecycleUnavailable
    );
}

#[test]
fn expired_future_snapshots_revocation_and_epoch_changes_invalidate_cached_receipts() {
    let keys = FixtureKeys::new();
    let clock = TestClock(Cell::new(100));
    let r = keys.snapshot([1; 48], 3);
    let mut state = FixtureState::default();
    let verified = VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &clock, &mut state),
    )
    .unwrap();
    for now in [19, 180] {
        clock.0.set(now);
        assert!(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state)
        )
        .is_err());
    }
    clock.0.set(100);
    keys.revoked.set(true);
    assert!(VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &clock, &mut state)
    )
    .is_err());
    keys.revoked.set(false);
    keys.epoch.set(2);
    assert!(VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &clock, &mut state)
    )
    .is_err());
    drop(verified);
}

#[test]
fn sequence_cannot_reset_at_key_root_rotation_or_same_sequence_equivocation() {
    let mut keys = FixtureKeys::new();
    let clock = TestClock(Cell::new(100));
    let mut state = FixtureState::default();
    let r = keys.snapshot([1; 48], 3);
    VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &clock, &mut state),
    )
    .unwrap();
    let mut changed = r.clone();
    changed.expires_at -= 1;
    keys.sign_release(&mut changed);
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &changed,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state)
        )),
        MaPolicyErrorV1::SequenceContentConflict
    );
    keys.release = TestSigner::new();
    keys.epoch.set(2);
    changed.signing_key_id = keys.release_id();
    changed.trust_epoch = 2;
    changed.sequence = 1;
    keys.sign_release(&mut changed);
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &changed,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state)
        )),
        MaPolicyErrorV1::SequenceRollback
    );
    changed.sequence = 11;
    keys.sign_release(&mut changed);
    VerifiedReleaseCollateralV1::verify(
        &changed,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &clock, &mut state),
    )
    .unwrap();
}

#[test]
fn status_is_monotonic_and_svn_or_history_cannot_be_rewritten_or_removed() {
    let keys = FixtureKeys::new();
    let clock = TestClock(Cell::new(100));
    for action in 0..4 {
        let mut state = FixtureState::default();
        let mut r = keys.snapshot([1; 48], 3);
        VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state),
        )
        .unwrap();
        r.sequence += 1;
        match action {
            0 => r.mappings[0].combined_svn = 4,
            1 => r.mappings[0].identity_digest = [2; 48],
            _ => r.mappings[0].status = ReleaseStatusV1::Revoked,
        }
        keys.sign_release(&mut r);
        let result = VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state),
        );
        if action < 2 {
            assert_eq!(error(result), MaPolicyErrorV1::ConflictingMapping);
        } else {
            result.unwrap();
            r.sequence += 1;
            r.mappings[0].status = ReleaseStatusV1::Approved;
            keys.sign_release(&mut r);
            assert_eq!(
                error(VerifiedReleaseCollateralV1::verify(
                    &r,
                    MaPolicyTrustV1::Fixture,
                    &mut services(&keys, &clock, &mut state)
                )),
                MaPolicyErrorV1::ConflictingMapping
            );
        }
    }
}

#[test]
fn missing_corrupt_and_failed_cas_storage_never_mints_snapshot() {
    let keys = FixtureKeys::new();
    let clock = TestClock(Cell::new(100));
    let r = keys.snapshot([1; 48], 3);
    let mut state = FixtureState {
        fail: true,
        ..Default::default()
    };
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state)
        )),
        MaPolicyErrorV1::StoreUnavailable
    );
    state.fail = false;
    state.conflict = true;
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state)
        )),
        MaPolicyErrorV1::StoreConflict
    );
    state.conflict = false;
    state.states.insert(
        FixtureState::namespace(
            MaPolicyTrustV1::Fixture,
            &PUBLISHER,
            CollateralStateSlotV1::ReleaseSnapshot,
        ),
        CollateralStateV1 {
            revision: 1,
            record: Some(vec![0]),
        },
    );
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &clock, &mut state)
        )),
        MaPolicyErrorV1::InvalidStoredState
    );
}

fn ordered_receipt(
    setup: &Setup,
    snapshot: &VerifiedReleaseCollateralV1,
    keys: &FixtureKeys,
    state: &mut FixtureState,
) -> Result<VerifiedMaPolicyCollateral, MaPolicyErrorV1> {
    VerifiedMaPolicyCollateral::verify_ordered(
        &setup.request(),
        &setup.policy,
        snapshot,
        &TestEvidenceVerifier::default(),
        &mut services(keys, &setup.clock, state),
    )
}

#[test]
fn ordered_evidence_requires_approved_mapping_absolute_floor_and_live_snapshot() {
    let setup = ordered_setup();
    let keys = FixtureKeys::new();
    for (status, svn, expected) in [
        (
            ReleaseStatusV1::Approved,
            1,
            MaPolicyErrorV1::ReleaseDowngrade,
        ),
        (
            ReleaseStatusV1::HistoricalOnly,
            3,
            MaPolicyErrorV1::HistoricalOnly,
        ),
        (ReleaseStatusV1::Revoked, 3, MaPolicyErrorV1::ReleaseRevoked),
    ] {
        let mut r = keys.snapshot(setup.selected, svn);
        r.mappings[0].status = status;
        keys.sign_release(&mut r);
        let mut state = FixtureState::default();
        let snapshot = VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &setup.clock, &mut state),
        )
        .unwrap();
        assert_eq!(
            error(ordered_receipt(&setup, &snapshot, &keys, &mut state)),
            expected
        );
    }
    let mut state = FixtureState::default();
    let r = keys.snapshot(setup.selected, 3);
    let snapshot = VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    ordered_receipt(&setup, &snapshot, &keys, &mut state).unwrap();
    let mut replacement = r.clone();
    replacement.sequence += 1;
    replacement.mappings[0].status = ReleaseStatusV1::Revoked;
    keys.sign_release(&mut replacement);
    VerifiedReleaseCollateralV1::verify(
        &replacement,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    assert!(ordered_receipt(&setup, &snapshot, &keys, &mut state).is_err());
}

#[test]
fn historical_record_checks_signature_binding_mapping_expiry_and_immutable_renewal() {
    let setup = ordered_setup();
    let keys = FixtureKeys::new();
    let mut state = FixtureState::default();
    let r = keys.snapshot(setup.selected, 3);
    let snapshot = VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    let t = tenant(&setup);
    let mut h = keys.initial(setup.selected, *setup.policy.digest(), 3);
    VerifiedInitialMaAuthorizationV1::verify(
        &h,
        &t,
        &FixtureHistory,
        &snapshot,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    h.sequence += 1;
    h.expires_at += 1;
    keys.sign_initial(&mut h);
    VerifiedInitialMaAuthorizationV1::verify(
        &h,
        &t,
        &FixtureHistory,
        &snapshot,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    for field in 0..6 {
        let mut bad = h.clone();
        bad.sequence += 1;
        match field {
            0 => bad.tenant_report_id[0] ^= 1,
            1 => bad.initial_ma_report_id[0] ^= 1,
            2 => bad.combined_svn += 1,
            3 => bad.lm_policy_digest[0] ^= 1,
            4 => bad.observed_at += 1,
            _ => bad.signature[0] ^= 1,
        }
        if field != 5 {
            keys.sign_initial(&mut bad);
        }
        assert!(
            VerifiedInitialMaAuthorizationV1::verify(
                &bad,
                &t,
                &FixtureHistory,
                &snapshot,
                &mut services(&keys, &setup.clock, &mut state)
            )
            .is_err(),
            "{field}"
        );
    }
    setup.clock.0.set(171);
    assert!(VerifiedInitialMaAuthorizationV1::verify(
        &h,
        &t,
        &FixtureHistory,
        &snapshot,
        &mut services(&keys, &setup.clock, &mut state)
    )
    .is_err());
}

#[test]
fn historical_only_identity_is_not_current_approval_and_revocation_is_not_grandfathered() {
    let setup = ordered_setup();
    let keys = FixtureKeys::new();
    for status in [ReleaseStatusV1::HistoricalOnly, ReleaseStatusV1::Revoked] {
        let mut state = FixtureState::default();
        let mut r = keys.snapshot(setup.selected, 3);
        r.mappings[0].status = status;
        keys.sign_release(&mut r);
        let snapshot = VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &setup.clock, &mut state),
        )
        .unwrap();
        let result = VerifiedInitialMaAuthorizationV1::verify(
            &keys.initial(setup.selected, *setup.policy.digest(), 3),
            &tenant(&setup),
            &FixtureHistory,
            &snapshot,
            &mut services(&keys, &setup.clock, &mut state),
        );
        assert_eq!(result.is_ok(), status == ReleaseStatusV1::HistoricalOnly);
        assert!(ordered_receipt(&setup, &snapshot, &keys, &mut state).is_err());
    }
}

#[test]
fn ordered_pair_enforces_upgrade_tenant_binding_initial_svn_and_platform_forwarding() {
    for (src_svn, dst_svn, initial_svn, handoff, pass) in [
        (3, 3, 3, false, true),
        (3, 4, 2, false, true),
        (4, 3, 2, false, false),
        (3, 4, 5, false, false),
        (3, 3, 3, true, true),
        (3, 4, 2, true, true),
        (4, 3, 2, true, false),
        (3, 4, 5, true, false),
    ] {
        let mut setup = ordered_setup();
        if handoff {
            let mut context = setup.context.clone();
            context.role = SnpMaRoleV1::Outgoing;
            context.evidence_purpose = SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization;
            context.algorithm = SnpMigrationAlgorithmV1::LocalHandoffSecretV1;
            context.tenant_binding_id = [0; 32];
            setup.rebind_context(context);
        }
        let keys = FixtureKeys::new();
        let mut state = FixtureState::default();
        let mut dst_evidence = setup.evidence.clone();
        dst_evidence.ma_report[0x90] ^= 1;
        let dst_identity = MaPolicyIdentityInputV1::from_authenticated_report(
            &dst_evidence.ma_report,
            *setup.policy.digest(),
        )
        .unwrap()
        .digest()
        .unwrap();
        let mut dst_context = setup.context.clone();
        dst_context.role = if handoff {
            SnpMaRoleV1::Incoming
        } else {
            SnpMaRoleV1::Destination
        };
        dst_context.ma_policy_identity_digest = dst_identity;
        dst_evidence.report_data_context = dst_context.clone();
        dst_evidence.header.role = dst_context.role;
        dst_evidence.ma_report[0x50..0x90]
            .copy_from_slice(&dst_context.expected_report_data().unwrap());
        let historical_identity = [0x99; 48];
        let mut r = keys.snapshot(setup.selected, src_svn);
        r.mappings.push(MaPolicyTcbMapping {
            identity_digest: dst_identity,
            combined_svn: dst_svn,
            status: ReleaseStatusV1::Approved,
        });
        r.mappings.push(MaPolicyTcbMapping {
            identity_digest: historical_identity,
            combined_svn: initial_svn,
            status: ReleaseStatusV1::HistoricalOnly,
        });
        r.mappings.sort_by_key(|m| m.identity_digest);
        keys.sign_release(&mut r);
        let snapshot = VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &setup.clock, &mut state),
        )
        .unwrap();
        let src = ordered_receipt(&setup, &snapshot, &keys, &mut state).unwrap();
        let mut req = setup.request();
        req.evidence = &dst_evidence;
        req.expected_context = &dst_context;
        let dst = VerifiedMaPolicyCollateral::verify_ordered(
            &req,
            &setup.policy,
            &snapshot,
            &TestEvidenceVerifier::default(),
            &mut services(&keys, &setup.clock, &mut state),
        )
        .unwrap();
        let initial = VerifiedInitialMaAuthorizationV1::verify(
            &keys.initial(historical_identity, [0x21; 48], initial_svn),
            &tenant(&setup),
            &FixtureHistory,
            &snapshot,
            &mut services(&keys, &setup.clock, &mut state),
        )
        .unwrap();
        assert_eq!(
            admit_ordered_release_pair_v1(
                &src,
                &dst,
                &initial,
                &snapshot,
                &FixtureHistory,
                &mut services(&keys, &setup.clock, &mut state),
            )
            .is_ok(),
            pass
        );
        assert_eq!(
            admit_fixed_release_pair_v1(&src, &dst),
            Err(MaPolicyErrorV1::UnsupportedProfile)
        );
    }
}

fn same_release_pair(
    setup: &Setup,
    keys: &FixtureKeys,
    state: &mut FixtureState,
    destination_context: ReportDataContextV1,
    destination_tcb: u8,
) -> (
    VerifiedReleaseCollateralV1,
    VerifiedMaPolicyCollateral,
    VerifiedMaPolicyCollateral,
    VerifiedInitialMaAuthorizationV1,
) {
    let r = keys.snapshot(setup.selected, 3);
    let snapshot = VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(keys, &setup.clock, state),
    )
    .unwrap();
    let src = ordered_receipt(setup, &snapshot, keys, state).unwrap();
    let mut evidence = setup.evidence.clone();
    evidence.header.role = destination_context.role;
    evidence.header.request_id = destination_context.request_id;
    evidence.header.evidence_purpose = destination_context.evidence_purpose;
    evidence.report_data_context = destination_context.clone();
    evidence.ma_report[0x38] = destination_tcb;
    evidence.ma_report[0x50..0x90]
        .copy_from_slice(&destination_context.expected_report_data().unwrap());
    let mut req = setup.request();
    req.evidence = &evidence;
    req.expected_context = &destination_context;
    let dst = VerifiedMaPolicyCollateral::verify_ordered(
        &req,
        &setup.policy,
        &snapshot,
        &TestEvidenceVerifier::default(),
        &mut services(keys, &setup.clock, state),
    )
    .unwrap();
    let initial = VerifiedInitialMaAuthorizationV1::verify(
        &keys.initial(setup.selected, *setup.policy.digest(), 3),
        &tenant(setup),
        &FixtureHistory,
        &snapshot,
        &mut services(keys, &setup.clock, state),
    )
    .unwrap();
    (snapshot, src, dst, initial)
}

#[test]
fn final_admission_rechecks_history_expiry_key_revocation_and_store_cas() {
    let setup = ordered_setup();
    let keys = FixtureKeys::new();
    let mut state = FixtureState::default();
    let mut dst = setup.context.clone();
    dst.role = SnpMaRoleV1::Destination;
    let (snapshot, src, dst, initial) = same_release_pair(&setup, &keys, &mut state, dst, 2);
    admit_ordered_release_pair_v1(
        &src,
        &dst,
        &initial,
        &snapshot,
        &FixtureHistory,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    setup.clock.0.set(170);
    assert!(admit_ordered_release_pair_v1(
        &src,
        &dst,
        &initial,
        &snapshot,
        &FixtureHistory,
        &mut services(&keys, &setup.clock, &mut state)
    )
    .is_err());
    setup.clock.0.set(100);
    keys.revoked.set(true);
    assert!(admit_ordered_release_pair_v1(
        &src,
        &dst,
        &initial,
        &snapshot,
        &FixtureHistory,
        &mut services(&keys, &setup.clock, &mut state)
    )
    .is_err());
    keys.revoked.set(false);
    state.conflict = true;
    assert_eq!(
        admit_ordered_release_pair_v1(
            &src,
            &dst,
            &initial,
            &snapshot,
            &FixtureHistory,
            &mut services(&keys, &setup.clock, &mut state)
        ),
        Err(MaPolicyErrorV1::StoreConflict)
    );
}

#[test]
fn final_admission_rejects_tenant_current_ma_and_operation_substitution() {
    for field in 0..5 {
        let mut setup = ordered_setup();
        let keys = FixtureKeys::new();
        let mut state = FixtureState::default();
        let mut dst = setup.context.clone();
        dst.role = SnpMaRoleV1::Destination;
        match field {
            0 => dst.request_id ^= 1,
            1 => dst.tenant_binding_id[0] ^= 1,
            2 => dst.th1[0] ^= 1,
            3 => dst.role = SnpMaRoleV1::Source,
            _ => setup.evidence.ma_report[0x140] ^= 1,
        }
        let (snapshot, src, dst, initial) = same_release_pair(&setup, &keys, &mut state, dst, 2);
        assert_eq!(
            admit_ordered_release_pair_v1(
                &src,
                &dst,
                &initial,
                &snapshot,
                &FixtureHistory,
                &mut services(&keys, &setup.clock, &mut state)
            ),
            Err(MaPolicyErrorV1::ContextMismatch)
        );
    }
}

#[test]
fn ordered_planned_handoff_and_current_platform_forwarding_remain_snp_specific() {
    let mut setup = ordered_setup();
    let keys = FixtureKeys::new();
    let mut state = FixtureState::default();
    let mut outgoing = setup.context.clone();
    outgoing.role = SnpMaRoleV1::Outgoing;
    outgoing.evidence_purpose = SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization;
    outgoing.algorithm = SnpMigrationAlgorithmV1::LocalHandoffSecretV1;
    outgoing.tenant_binding_id = [0; 32];
    setup.rebind_context(outgoing.clone());
    let mut incoming = outgoing;
    incoming.role = SnpMaRoleV1::Incoming;
    let (snapshot, src, dst, initial) =
        same_release_pair(&setup, &keys, &mut state, incoming.clone(), 2);
    admit_ordered_release_pair_v1(
        &src,
        &dst,
        &initial,
        &snapshot,
        &FixtureHistory,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    let (snapshot, src, dst, initial) = same_release_pair(&setup, &keys, &mut state, incoming, 1);
    assert_eq!(
        admit_ordered_release_pair_v1(
            &src,
            &dst,
            &initial,
            &snapshot,
            &FixtureHistory,
            &mut services(&keys, &setup.clock, &mut state)
        ),
        Err(MaPolicyErrorV1::PlatformDowngrade)
    );
}

#[test]
fn missing_mapping_wrong_publisher_and_fixed_ordered_profile_confusion_fail() {
    let setup = ordered_setup();
    let keys = FixtureKeys::new();
    let mut state = FixtureState::default();
    let r = keys.snapshot([0x11; 48], 3);
    let snapshot = VerifiedReleaseCollateralV1::verify(
        &r,
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    assert_eq!(
        error(ordered_receipt(&setup, &snapshot, &keys, &mut state)),
        MaPolicyErrorV1::MissingMapping
    );
    let fixed = Setup::new();
    assert_eq!(
        error(ordered_receipt(&fixed, &snapshot, &keys, &mut state)),
        MaPolicyErrorV1::UnsupportedProfile
    );
    assert_eq!(
        error(setup.verify(&mut TestStore::default())),
        MaPolicyErrorV1::UnsupportedProfile
    );
    let mut r = r;
    r.publisher_id[0] ^= 1;
    keys.sign_release(&mut r);
    assert_eq!(
        error(VerifiedReleaseCollateralV1::verify(
            &r,
            MaPolicyTrustV1::Fixture,
            &mut services(&keys, &setup.clock, &mut state),
        )),
        MaPolicyErrorV1::InvalidSigner
    );
}

#[test]
fn historical_signature_all_bytes_purpose_and_unavailable_binding_are_enforced() {
    let setup = ordered_setup();
    let keys = FixtureKeys::new();
    let mut state = FixtureState::default();
    let snapshot = VerifiedReleaseCollateralV1::verify(
        &keys.snapshot(setup.selected, 3),
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    let tenant = tenant(&setup);
    let h = keys.initial(setup.selected, *setup.policy.digest(), 3);
    let bytes = h.encode_exact().unwrap();
    for offset in 0..bytes.len() {
        let mut changed = bytes;
        changed[offset] ^= 1;
        if let Ok(changed) = InitialMaAuthorizationV1::decode_exact(&changed) {
            assert!(
                VerifiedInitialMaAuthorizationV1::verify(
                    &changed,
                    &tenant,
                    &FixtureHistory,
                    &snapshot,
                    &mut services(&keys, &setup.clock, &mut state),
                )
                .is_err(),
                "{offset}"
            );
        }
    }
    assert!(VerifiedInitialMaAuthorizationV1::verify(
        &h,
        &tenant,
        &UnavailableOrderedCollateralServicesV1,
        &snapshot,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .is_err());
    let mut h = h;
    h.signing_key_id = keys.release_id();
    keys.sign_initial(&mut h);
    assert_eq!(
        error(VerifiedInitialMaAuthorizationV1::verify(
            &h,
            &tenant,
            &FixtureHistory,
            &snapshot,
            &mut services(&keys, &setup.clock, &mut state),
        )),
        MaPolicyErrorV1::InvalidSigner
    );
}

#[test]
fn historical_sequence_rollback_and_equivocation_survive_model_reload() {
    let setup = ordered_setup();
    let keys = FixtureKeys::new();
    let mut state = FixtureState::default();
    let snapshot = VerifiedReleaseCollateralV1::verify(
        &keys.snapshot(setup.selected, 3),
        MaPolicyTrustV1::Fixture,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    let h = keys.initial(setup.selected, *setup.policy.digest(), 3);
    VerifiedInitialMaAuthorizationV1::verify(
        &h,
        &tenant(&setup),
        &FixtureHistory,
        &snapshot,
        &mut services(&keys, &setup.clock, &mut state),
    )
    .unwrap();
    state = FixtureState {
        states: state.states,
        ..Default::default()
    };
    for rollback in [false, true] {
        let mut changed = h.clone();
        if rollback {
            changed.sequence = 0;
        } else {
            changed.expires_at += 1;
        }
        keys.sign_initial(&mut changed);
        assert_eq!(
            error(VerifiedInitialMaAuthorizationV1::verify(
                &changed,
                &tenant(&setup),
                &FixtureHistory,
                &snapshot,
                &mut services(&keys, &setup.clock, &mut state),
            )),
            if rollback {
                MaPolicyErrorV1::SequenceRollback
            } else {
                MaPolicyErrorV1::SequenceContentConflict
            }
        );
    }
}
