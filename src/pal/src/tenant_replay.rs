// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! P0.6 operation-local control over a trusted durable replay store.
//! This module implements no storage, sealing, rollback anchor or firmware I/O.

#[cfg(any(feature = "snp-core", test))]
use crate::tenant_identity::VerifiedTenantReportDeliveryV1;
use crate::types::{SnpOperationContext, SnpVerifierTrust};

/// Persisted data, not a way to construct an authorization capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTenantReplayBindingV1 {
    pub operation: SnpOperationContext,
    pub tenant_report_id: [u8; 32],
    pub tenant_evidence_digest: [u8; 48],
    pub authorization_context_digest: [u8; 48],
    pub source_ma_report_id: [u8; 32],
    pub destination_ma_report_id: [u8; 32],
    pub trust: SnpVerifierTrust,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTenantReplayBindingV1(StoredTenantReplayBindingV1);

impl VerifiedTenantReplayBindingV1 {
    #[cfg(any(feature = "snp-core", test))]
    pub(crate) fn from_verified_context(
        tenant: &VerifiedTenantReportDeliveryV1,
        authorization_context_digest: [u8; 48],
        source_ma_report_id: [u8; 32],
        destination_ma_report_id: [u8; 32],
    ) -> Self {
        Self(StoredTenantReplayBindingV1 {
            operation: *tenant.operation(),
            tenant_report_id: *tenant.identity().as_bytes(),
            tenant_evidence_digest: *tenant.canonical_evidence_digest(),
            authorization_context_digest,
            source_ma_report_id,
            destination_ma_report_id,
            trust: tenant.trust(),
        })
    }

    pub const fn as_stored(&self) -> &StoredTenantReplayBindingV1 {
        &self.0
    }
}

/// Both role-specific reports of the selected authorization profile were
/// authenticated for this binding (active V2 uses purpose7).
/// Policy, current firmware and durable replay checks remain mandatory.
///
/// ```compile_fail
/// use pal::tenant_replay::{VerifiedTenantAuthorizationV1, VerifiedTenantReplayBindingV1};
/// fn forge(binding: VerifiedTenantReplayBindingV1) {
///     VerifiedTenantAuthorizationV1::from_verified_roles(binding);
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedTenantAuthorizationV1(VerifiedTenantReplayBindingV1);

impl VerifiedTenantAuthorizationV1 {
    #[cfg(any(feature = "snp-core", test))]
    pub(crate) fn from_verified_roles(binding: VerifiedTenantReplayBindingV1) -> Self {
        Self(binding)
    }

    pub const fn binding(&self) -> &VerifiedTenantReplayBindingV1 {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantReplayErrorV1 {
    InvalidCapacity,
    CapacityExceeded,
    InvalidSnapshot,
    ConflictingReuse,
    TerminalOperation,
    InvalidTransition,
    RevisionExhausted,
    RollbackDetected,
    ConcurrentUpdate,
    ProductionReplayStateUnavailable,
    PersistenceFailure,
    PersistenceVerificationFailed,
    RecoveryRequired,
    FirmwareStateUnavailable,
    FirmwareStateMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayTerminalOutcomeV1 {
    Succeeded,
    Aborted,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayTerminalResultV1 {
    pub outcome: ReplayTerminalOutcomeV1,
    pub result_digest: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantReplayStateV1 {
    Reserved,
    Authorized,
    Terminal(ReplayTerminalResultV1),
}

impl TenantReplayStateV1 {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal(_))
    }

    fn follows(self, previous: Self) -> bool {
        match previous {
            Self::Reserved => true,
            Self::Authorized => self != Self::Reserved,
            Self::Terminal(_) => self == previous,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantReplayRecordV1 {
    pub binding: StoredTenantReplayBindingV1,
    pub state: TenantReplayStateV1,
}

/// A storage representation. Its fields confer no trust by themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantReplaySnapshotV1 {
    pub revision: u64,
    pub records: Vec<TenantReplayRecordV1>,
}

/// Trusted provider contract, scoped to a stable MA authority across restart
/// and handoff. Load must check integrity and an independent rollback-resistant
/// anchor, bound decoding before allocation, and reject absent/unprovisioned
/// state. Never turn a missing file into an empty snapshot.
///
/// Commit must compare-and-swap the revision, atomically persist the entire
/// replacement and advance its anchor, and acknowledge only durable success.
/// Ambiguous failures require authenticated recovery. No provider or fallback
/// is selected by this contract.
pub trait DurableTenantReplayStoreV1 {
    fn load_authenticated(
        &mut self,
        maximum_records: usize,
    ) -> Result<TenantReplaySnapshotV1, TenantReplayErrorV1>;

    fn commit(
        &mut self,
        expected_revision: u64,
        replacement: &TenantReplaySnapshotV1,
    ) -> Result<(), TenantReplayErrorV1>;
}

/// Query authoritative current firmware identity, binding and lifecycle for
/// the local source/destination role. Cached reports and host assertions are
/// insufficient. Providers must apply role-specific REPORT_ID/GCTX semantics.
pub trait CurrentTenantFirmwareStateV1 {
    fn validate_current(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<(), TenantReplayErrorV1>;
}

pub struct UnavailableTenantReplayStoreV1;

impl DurableTenantReplayStoreV1 for UnavailableTenantReplayStoreV1 {
    fn load_authenticated(
        &mut self,
        _maximum_records: usize,
    ) -> Result<TenantReplaySnapshotV1, TenantReplayErrorV1> {
        Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
    }

    fn commit(
        &mut self,
        _expected_revision: u64,
        _replacement: &TenantReplaySnapshotV1,
    ) -> Result<(), TenantReplayErrorV1> {
        Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
    }
}

pub struct UnavailableTenantFirmwareStateV1;

impl CurrentTenantFirmwareStateV1 for UnavailableTenantFirmwareStateV1 {
    fn validate_current(
        &mut self,
        _binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<(), TenantReplayErrorV1> {
        Err(TenantReplayErrorV1::FirmwareStateUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantReplayAdmissionV1 {
    FirstReservation,
    IdempotentRetry(TenantReplayStateV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantReplayAuthorizationV1 {
    FirstAuthorization,
    IdempotentRetry,
}

/// Decoded storage data cannot be admitted as a verified live binding:
///
/// ```compile_fail
/// use pal::tenant_replay::*;
/// fn reserve<S: DurableTenantReplayStoreV1>(
///     journal: &mut TenantReplayJournalV1<S>, stored: StoredTenantReplayBindingV1
/// ) {
///     journal.reserve(&stored);
/// }
/// ```
pub struct TenantReplayJournalV1<S> {
    store: S,
    maximum_records: usize,
    last_snapshot: Option<TenantReplaySnapshotV1>,
    recovery_required: bool,
}

impl<S: DurableTenantReplayStoreV1> TenantReplayJournalV1<S> {
    pub fn new(store: S, maximum_records: usize) -> Result<Self, TenantReplayErrorV1> {
        if maximum_records == 0 {
            return Err(TenantReplayErrorV1::InvalidCapacity);
        }
        Ok(Self {
            store,
            maximum_records,
            last_snapshot: None,
            recovery_required: false,
        })
    }

    fn load(&mut self) -> Result<TenantReplaySnapshotV1, TenantReplayErrorV1> {
        if self.recovery_required {
            return Err(TenantReplayErrorV1::RecoveryRequired);
        }
        let snapshot = self.store.load_authenticated(self.maximum_records)?;
        if snapshot.records.len() > self.maximum_records {
            return Err(TenantReplayErrorV1::CapacityExceeded);
        }
        let count = u64::try_from(snapshot.records.len())
            .map_err(|_| TenantReplayErrorV1::CapacityExceeded)?;
        if (snapshot.revision == 0) != snapshot.records.is_empty() || snapshot.revision < count {
            return Err(TenantReplayErrorV1::InvalidSnapshot);
        }
        for (index, record) in snapshot.records.iter().enumerate() {
            if snapshot.records[..index].iter().any(|other| {
                other.binding.operation.request_id == record.binding.operation.request_id
                    || other.binding.tenant_evidence_digest == record.binding.tenant_evidence_digest
                    || (other.binding.tenant_report_id == record.binding.tenant_report_id
                        && !other.state.is_terminal()
                        && !record.state.is_terminal())
            }) {
                return Err(TenantReplayErrorV1::InvalidSnapshot);
            }
        }
        if let Some(previous) = &self.last_snapshot {
            if snapshot.revision < previous.revision
                || (snapshot.revision == previous.revision && snapshot != *previous)
                || previous.records.iter().any(|old| {
                    !snapshot
                        .records
                        .iter()
                        .any(|new| new.binding == old.binding && new.state.follows(old.state))
                })
            {
                return Err(TenantReplayErrorV1::RollbackDetected);
            }
        }
        self.last_snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    fn locate(
        snapshot: &TenantReplaySnapshotV1,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<Option<usize>, TenantReplayErrorV1> {
        if let Some(index) = snapshot
            .records
            .iter()
            .position(|record| &record.binding == binding.as_stored())
        {
            return Ok(Some(index));
        }
        for record in &snapshot.records {
            if record.binding.operation.request_id == binding.0.operation.request_id
                || record.binding.tenant_evidence_digest == binding.0.tenant_evidence_digest
                || (record.binding.tenant_report_id == binding.0.tenant_report_id
                    && !record.state.is_terminal())
            {
                return Err(TenantReplayErrorV1::ConflictingReuse);
            }
        }
        Ok(None)
    }

    fn persist(&mut self, mut snapshot: TenantReplaySnapshotV1) -> Result<(), TenantReplayErrorV1> {
        let previous_revision = snapshot.revision;
        snapshot.revision = previous_revision
            .checked_add(1)
            .ok_or(TenantReplayErrorV1::RevisionExhausted)?;
        if let Err(error) = self.store.commit(previous_revision, &snapshot) {
            self.recovery_required = true;
            return Err(error);
        }
        match self.store.load_authenticated(self.maximum_records) {
            Ok(actual) if actual == snapshot => {
                self.last_snapshot = Some(snapshot);
                Ok(())
            }
            Ok(_) => {
                self.recovery_required = true;
                Err(TenantReplayErrorV1::PersistenceVerificationFailed)
            }
            Err(error) => {
                self.recovery_required = true;
                Err(error)
            }
        }
    }

    pub fn reserve(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<TenantReplayAdmissionV1, TenantReplayErrorV1> {
        let mut snapshot = self.load()?;
        if let Some(index) = Self::locate(&snapshot, binding)? {
            let state = snapshot.records[index].state;
            if state.is_terminal() {
                return Err(TenantReplayErrorV1::TerminalOperation);
            }
            return Ok(TenantReplayAdmissionV1::IdempotentRetry(state));
        }
        if snapshot.records.len() == self.maximum_records {
            return Err(TenantReplayErrorV1::CapacityExceeded);
        }
        snapshot.records.push(TenantReplayRecordV1 {
            binding: binding.0.clone(),
            state: TenantReplayStateV1::Reserved,
        });
        self.persist(snapshot)?;
        Ok(TenantReplayAdmissionV1::FirstReservation)
    }

    pub fn authorize(
        &mut self,
        authorization: &VerifiedTenantAuthorizationV1,
        firmware: &mut dyn CurrentTenantFirmwareStateV1,
    ) -> Result<TenantReplayAuthorizationV1, TenantReplayErrorV1> {
        let binding = authorization.binding();
        let mut snapshot = self.load()?;
        let index =
            Self::locate(&snapshot, binding)?.ok_or(TenantReplayErrorV1::InvalidTransition)?;
        let state = snapshot.records[index].state;
        if state.is_terminal() {
            return Err(TenantReplayErrorV1::TerminalOperation);
        }
        firmware.validate_current(binding)?;
        if state == TenantReplayStateV1::Authorized {
            return Ok(TenantReplayAuthorizationV1::IdempotentRetry);
        }
        snapshot.records[index].state = TenantReplayStateV1::Authorized;
        self.persist(snapshot)?;
        Ok(TenantReplayAuthorizationV1::FirstAuthorization)
    }

    pub fn finish(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
        result: ReplayTerminalResultV1,
    ) -> Result<(), TenantReplayErrorV1> {
        let mut snapshot = self.load()?;
        let index =
            Self::locate(&snapshot, binding)?.ok_or(TenantReplayErrorV1::InvalidTransition)?;
        let state = snapshot.records[index].state;
        if state.is_terminal() {
            return Err(TenantReplayErrorV1::TerminalOperation);
        }
        if state != TenantReplayStateV1::Authorized
            && result.outcome == ReplayTerminalOutcomeV1::Succeeded
        {
            return Err(TenantReplayErrorV1::InvalidTransition);
        }
        snapshot.records[index].state = TenantReplayStateV1::Terminal(result);
        self.persist(snapshot)
    }

    /// Read-only status queries never admit, authorize or repeat workflow effects.
    pub fn query_operation(
        &mut self,
        operation: &crate::types::SnpOperationContext,
    ) -> Result<Option<TenantReplayStateV1>, TenantReplayErrorV1> {
        let snapshot = self.load()?;
        if let Some(record) = snapshot
            .records
            .iter()
            .find(|record| record.binding.operation.request_id == operation.request_id)
        {
            if record.binding.operation != *operation {
                return Err(TenantReplayErrorV1::ConflictingReuse);
            }
            return Ok(Some(record.state));
        }
        Ok(None)
    }

    /// Read-only status queries never admit, authorize or repeat workflow effects.
    pub fn query(
        &mut self,
        binding: &VerifiedTenantReplayBindingV1,
    ) -> Result<Option<TenantReplayStateV1>, TenantReplayErrorV1> {
        let snapshot = self.load()?;
        Ok(Self::locate(&snapshot, binding)?.map(|index| snapshot.records[index].state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tenant_identity::VerifiedTenantIdentity,
        types::{HostRequestId, ManagedGuestHandle, MigrationId, MigrationRole},
    };
    use std::{cell::RefCell, rc::Rc};

    // Separate model fields stand in for storage and its independent anchor.
    // This exercises the boundary contract, not physical persistence/security.
    #[derive(Clone)]
    struct ModelStore(Rc<RefCell<ModelDisk>>);

    struct ModelDisk {
        image: TenantReplaySnapshotV1,
        anchor: TenantReplaySnapshotV1,
        commits: usize,
        commit_error: Option<TenantReplayErrorV1>,
        error_after_write: bool,
        acknowledge_without_write: bool,
        fail_read_after_write: bool,
        read_error: Option<TenantReplayErrorV1>,
    }

    impl ModelStore {
        fn provisioned() -> Self {
            let empty = TenantReplaySnapshotV1 {
                revision: 0,
                records: vec![],
            };
            Self(Rc::new(RefCell::new(ModelDisk {
                image: empty.clone(),
                anchor: empty,
                commits: 0,
                commit_error: None,
                error_after_write: false,
                acknowledge_without_write: false,
                fail_read_after_write: false,
                read_error: None,
            })))
        }

        fn install_authenticated_model_snapshot(&self, image: TenantReplaySnapshotV1) {
            let mut disk = self.0.borrow_mut();
            disk.image = image.clone();
            disk.anchor = image;
        }
    }

    impl DurableTenantReplayStoreV1 for ModelStore {
        fn load_authenticated(
            &mut self,
            maximum_records: usize,
        ) -> Result<TenantReplaySnapshotV1, TenantReplayErrorV1> {
            let mut disk = self.0.borrow_mut();
            if let Some(error) = disk.read_error.take() {
                return Err(error);
            }
            if disk.image != disk.anchor {
                return Err(TenantReplayErrorV1::RollbackDetected);
            }
            if disk.image.records.len() > maximum_records {
                return Err(TenantReplayErrorV1::CapacityExceeded);
            }
            Ok(disk.image.clone())
        }

        fn commit(
            &mut self,
            expected_revision: u64,
            replacement: &TenantReplaySnapshotV1,
        ) -> Result<(), TenantReplayErrorV1> {
            let mut disk = self.0.borrow_mut();
            if let Some(error) = disk.commit_error {
                return Err(error);
            }
            if disk.image.revision != expected_revision {
                return Err(TenantReplayErrorV1::ConcurrentUpdate);
            }
            if disk.acknowledge_without_write {
                return Ok(());
            }
            disk.image = replacement.clone();
            disk.anchor = replacement.clone();
            disk.commits += 1;
            if disk.fail_read_after_write {
                disk.read_error = Some(TenantReplayErrorV1::PersistenceFailure);
            }
            if disk.error_after_write {
                return Err(TenantReplayErrorV1::PersistenceFailure);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct ModelFirmware {
        calls: usize,
        error: Option<TenantReplayErrorV1>,
    }

    impl CurrentTenantFirmwareStateV1 for ModelFirmware {
        fn validate_current(
            &mut self,
            _: &VerifiedTenantReplayBindingV1,
        ) -> Result<(), TenantReplayErrorV1> {
            self.calls += 1;
            match self.error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    fn binding() -> VerifiedTenantReplayBindingV1 {
        let tenant = VerifiedTenantReportDeliveryV1::from_verified_report(
            SnpOperationContext::new(
                HostRequestId::new(1),
                MigrationId::new(2),
                MigrationRole::Source,
                ManagedGuestHandle::new(3),
            ),
            VerifiedTenantIdentity::from_verified_report_id([4; 32]),
            [5; 48],
            SnpVerifierTrust::PinnedMilanArkTest,
            [6; 32],
            [7; 48],
        );
        VerifiedTenantReplayBindingV1::from_verified_context(&tenant, [8; 48], [6; 32], [9; 32])
    }

    fn terminal(outcome: ReplayTerminalOutcomeV1) -> ReplayTerminalResultV1 {
        ReplayTerminalResultV1 {
            outcome,
            result_digest: [10; 48],
        }
    }

    #[test]
    fn persisted_reservation_authorization_and_terminal_query_have_exact_order() {
        let store = ModelStore::provisioned();
        let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        let binding = binding();
        let proof = VerifiedTenantAuthorizationV1::from_verified_roles(binding.clone());
        let mut firmware = ModelFirmware::default();
        assert_eq!(journal.query(&binding), Ok(None));
        assert_eq!(
            journal.reserve(&binding),
            Ok(TenantReplayAdmissionV1::FirstReservation)
        );
        assert_eq!(store.0.borrow().image.revision, 1);
        assert_eq!(
            journal.reserve(&binding),
            Ok(TenantReplayAdmissionV1::IdempotentRetry(
                TenantReplayStateV1::Reserved
            ))
        );
        assert_eq!(
            journal.authorize(&proof, &mut firmware),
            Ok(TenantReplayAuthorizationV1::FirstAuthorization)
        );
        assert_eq!(store.0.borrow().image.revision, 2);
        assert_eq!(
            journal.authorize(&proof, &mut firmware),
            Ok(TenantReplayAuthorizationV1::IdempotentRetry)
        );
        assert_eq!(firmware.calls, 2);
        let result = terminal(ReplayTerminalOutcomeV1::Succeeded);
        journal.finish(&binding, result).unwrap();
        assert_eq!(store.0.borrow().image.revision, 3);
        assert_eq!(
            journal.query(&binding),
            Ok(Some(TenantReplayStateV1::Terminal(result)))
        );
        assert_eq!(
            journal.reserve(&binding),
            Err(TenantReplayErrorV1::TerminalOperation)
        );
        assert_eq!(
            journal.authorize(&proof, &mut firmware),
            Err(TenantReplayErrorV1::TerminalOperation)
        );
        assert_eq!(
            journal.finish(&binding, result),
            Err(TenantReplayErrorV1::TerminalOperation)
        );
        assert_eq!(store.0.borrow().commits, 3);
        assert_eq!(firmware.calls, 2);
    }

    #[test]
    fn conflicting_request_report_tenant_session_role_policy_or_identity_is_rejected() {
        let store = ModelStore::provisioned();
        let mut journal = TenantReplayJournalV1::new(store, 8).unwrap();
        let original = binding();
        journal.reserve(&original).unwrap();
        let mut alternatives = vec![];
        let mut changed = original.clone();
        changed.0.operation.request_id = HostRequestId::new(99);
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.operation.migration_id = MigrationId::new(99);
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.operation.role = MigrationRole::Destination;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.operation.managed_guest = ManagedGuestHandle::new(99);
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.tenant_evidence_digest[47] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.tenant_report_id[31] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.authorization_context_digest[47] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.source_ma_report_id[31] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.destination_ma_report_id[31] ^= 1;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.trust = SnpVerifierTrust::AzureProduction;
        alternatives.push(changed);
        let mut changed = original.clone();
        changed.0.operation.request_id = HostRequestId::new(99);
        changed.0.tenant_evidence_digest[0] ^= 1;
        alternatives.push(changed);
        for changed in alternatives {
            assert_eq!(
                journal.reserve(&changed),
                Err(TenantReplayErrorV1::ConflictingReuse)
            );
        }
        assert_eq!(
            journal.query(&original),
            Ok(Some(TenantReplayStateV1::Reserved))
        );
    }

    #[test]
    fn missing_durable_store_never_falls_back_to_empty_or_memory_state() {
        let mut journal = TenantReplayJournalV1::new(UnavailableTenantReplayStoreV1, 2).unwrap();
        let binding = binding();
        let proof = VerifiedTenantAuthorizationV1::from_verified_roles(binding.clone());
        assert_eq!(
            journal.reserve(&binding),
            Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
        );
        assert_eq!(
            journal.authorize(&proof, &mut ModelFirmware::default()),
            Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
        );
        assert_eq!(
            journal.query(&binding),
            Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
        );
    }

    #[test]
    fn firmware_is_revalidated_on_first_authorization_and_every_authorization_retry() {
        let store = ModelStore::provisioned();
        let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        let binding = binding();
        let proof = VerifiedTenantAuthorizationV1::from_verified_roles(binding.clone());
        journal.reserve(&binding).unwrap();
        assert_eq!(
            journal.authorize(&proof, &mut UnavailableTenantFirmwareStateV1),
            Err(TenantReplayErrorV1::FirmwareStateUnavailable)
        );
        assert_eq!(
            journal.query(&binding),
            Ok(Some(TenantReplayStateV1::Reserved))
        );
        let mut firmware = ModelFirmware {
            error: Some(TenantReplayErrorV1::FirmwareStateMismatch),
            ..Default::default()
        };
        assert_eq!(
            journal.authorize(&proof, &mut firmware),
            Err(TenantReplayErrorV1::FirmwareStateMismatch)
        );
        firmware.error = None;
        journal.authorize(&proof, &mut firmware).unwrap();
        firmware.error = Some(TenantReplayErrorV1::FirmwareStateMismatch);
        assert_eq!(
            journal.authorize(&proof, &mut firmware),
            Err(TenantReplayErrorV1::FirmwareStateMismatch)
        );
        assert_eq!(store.0.borrow().commits, 2);
        assert_eq!(firmware.calls, 3);
    }

    #[test]
    fn reservation_is_required_and_only_failure_or_abort_can_terminate_before_authorization() {
        let mut journal = TenantReplayJournalV1::new(ModelStore::provisioned(), 2).unwrap();
        let binding = binding();
        let proof = VerifiedTenantAuthorizationV1::from_verified_roles(binding.clone());
        let mut firmware = ModelFirmware::default();
        assert_eq!(
            journal.authorize(&proof, &mut firmware),
            Err(TenantReplayErrorV1::InvalidTransition)
        );
        assert_eq!(firmware.calls, 0);
        journal.reserve(&binding).unwrap();
        assert_eq!(
            journal.finish(&binding, terminal(ReplayTerminalOutcomeV1::Succeeded)),
            Err(TenantReplayErrorV1::InvalidTransition)
        );
        journal
            .finish(&binding, terminal(ReplayTerminalOutcomeV1::Aborted))
            .unwrap();
        assert!(matches!(
            journal.query(&binding),
            Ok(Some(TenantReplayStateV1::Terminal(_)))
        ));
    }

    #[test]
    fn capacity_exhaustion_never_evicts_report_or_request_tombstones() {
        assert!(matches!(
            TenantReplayJournalV1::new(ModelStore::provisioned(), 0),
            Err(TenantReplayErrorV1::InvalidCapacity)
        ));
        let mut journal = TenantReplayJournalV1::new(ModelStore::provisioned(), 1).unwrap();
        let original = binding();
        journal.reserve(&original).unwrap();
        journal
            .finish(&original, terminal(ReplayTerminalOutcomeV1::Failed))
            .unwrap();
        let mut next = original.clone();
        next.0.operation.request_id = HostRequestId::new(99);
        next.0.tenant_evidence_digest[0] ^= 1;
        assert_eq!(
            journal.reserve(&next),
            Err(TenantReplayErrorV1::CapacityExceeded)
        );
        assert_eq!(
            journal.reserve(&original),
            Err(TenantReplayErrorV1::TerminalOperation)
        );
    }

    #[test]
    fn model_reopen_preserves_active_retry_and_terminal_rejection() {
        let store = ModelStore::provisioned();
        let binding = binding();
        {
            let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
            journal.reserve(&binding).unwrap();
        }
        let mut reopened = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        assert_eq!(
            reopened.reserve(&binding),
            Ok(TenantReplayAdmissionV1::IdempotentRetry(
                TenantReplayStateV1::Reserved
            ))
        );
        reopened
            .finish(&binding, terminal(ReplayTerminalOutcomeV1::Failed))
            .unwrap();
        let mut reopened = TenantReplayJournalV1::new(store, 2).unwrap();
        assert_eq!(
            reopened.reserve(&binding),
            Err(TenantReplayErrorV1::TerminalOperation)
        );
    }

    #[test]
    fn model_independent_anchor_rejects_rollback_even_after_controller_reopen() {
        let store = ModelStore::provisioned();
        let original_image = store.0.borrow().image.clone();
        let binding = binding();
        let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        journal.reserve(&binding).unwrap();
        store.0.borrow_mut().image = original_image;
        let mut reopened = TenantReplayJournalV1::new(store, 2).unwrap();
        assert_eq!(
            reopened.reserve(&binding),
            Err(TenantReplayErrorV1::RollbackDetected)
        );
    }

    #[test]
    fn observed_revision_state_regression_and_tombstone_removal_are_rejected() {
        for mutation in 0..4 {
            let store = ModelStore::provisioned();
            let binding = binding();
            let proof = VerifiedTenantAuthorizationV1::from_verified_roles(binding.clone());
            let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
            journal.reserve(&binding).unwrap();
            journal
                .authorize(&proof, &mut ModelFirmware::default())
                .unwrap();
            let mut forged = store.0.borrow().image.clone();
            match mutation {
                0 => forged.revision -= 1,
                1 => forged.records[0].state = TenantReplayStateV1::Reserved,
                2 => {
                    forged.revision += 1;
                    forged.records[0].state = TenantReplayStateV1::Reserved;
                }
                _ => {
                    forged.revision += 1;
                    forged.records[0].binding.tenant_report_id[0] ^= 1;
                }
            }
            store.install_authenticated_model_snapshot(forged);
            assert_eq!(
                journal.query(&binding),
                Err(TenantReplayErrorV1::RollbackDetected)
            );
        }
    }

    #[test]
    fn storage_failure_or_false_acknowledgement_never_publishes_admission() {
        for error in [
            TenantReplayErrorV1::PersistenceFailure,
            TenantReplayErrorV1::ConcurrentUpdate,
        ] {
            let store = ModelStore::provisioned();
            store.0.borrow_mut().commit_error = Some(error);
            let mut journal = TenantReplayJournalV1::new(store, 2).unwrap();
            assert_eq!(journal.reserve(&binding()), Err(error));
            assert_eq!(
                journal.reserve(&binding()),
                Err(TenantReplayErrorV1::RecoveryRequired)
            );
        }
        let store = ModelStore::provisioned();
        store.0.borrow_mut().acknowledge_without_write = true;
        let mut journal = TenantReplayJournalV1::new(store, 2).unwrap();
        assert_eq!(
            journal.reserve(&binding()),
            Err(TenantReplayErrorV1::PersistenceVerificationFailed)
        );
        assert_eq!(
            journal.query(&binding()),
            Err(TenantReplayErrorV1::RecoveryRequired)
        );
    }

    #[test]
    fn ambiguous_committed_write_requires_recovery_without_repeating_the_write() {
        let store = ModelStore::provisioned();
        store.0.borrow_mut().error_after_write = true;
        let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        assert_eq!(
            journal.reserve(&binding()),
            Err(TenantReplayErrorV1::PersistenceFailure)
        );
        assert_eq!(
            journal.reserve(&binding()),
            Err(TenantReplayErrorV1::RecoveryRequired)
        );
        store.0.borrow_mut().error_after_write = false;
        let mut recovered = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        assert_eq!(
            recovered.reserve(&binding()),
            Ok(TenantReplayAdmissionV1::IdempotentRetry(
                TenantReplayStateV1::Reserved
            ))
        );
        assert_eq!(store.0.borrow().commits, 1);
    }

    #[test]
    fn authorization_write_failure_or_failed_readback_never_returns_authorized() {
        for fail_readback in [false, true] {
            let store = ModelStore::provisioned();
            let binding = binding();
            let proof = VerifiedTenantAuthorizationV1::from_verified_roles(binding.clone());
            let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
            journal.reserve(&binding).unwrap();
            if fail_readback {
                store.0.borrow_mut().fail_read_after_write = true;
            } else {
                store.0.borrow_mut().commit_error = Some(TenantReplayErrorV1::PersistenceFailure);
            }
            assert_eq!(
                journal.authorize(&proof, &mut ModelFirmware::default()),
                Err(TenantReplayErrorV1::PersistenceFailure)
            );
            assert_eq!(
                journal.authorize(&proof, &mut ModelFirmware::default()),
                Err(TenantReplayErrorV1::RecoveryRequired)
            );
        }
    }

    #[test]
    fn new_report_and_request_can_follow_a_terminal_operation_but_old_report_cannot() {
        let store = ModelStore::provisioned();
        let original = binding();
        let mut journal = TenantReplayJournalV1::new(store, 2).unwrap();
        journal.reserve(&original).unwrap();
        journal
            .finish(&original, terminal(ReplayTerminalOutcomeV1::Aborted))
            .unwrap();
        let mut next = original.clone();
        next.0.operation.request_id = HostRequestId::new(99);
        assert_eq!(
            journal.reserve(&next),
            Err(TenantReplayErrorV1::ConflictingReuse)
        );
        next.0.tenant_evidence_digest[0] ^= 1;
        assert_eq!(
            journal.reserve(&next),
            Ok(TenantReplayAdmissionV1::FirstReservation)
        );
        assert_eq!(
            journal.reserve(&original),
            Err(TenantReplayErrorV1::TerminalOperation)
        );
    }

    #[test]
    fn a_terminal_outcome_cannot_be_changed_even_at_a_higher_revision() {
        let store = ModelStore::provisioned();
        let binding = binding();
        let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        journal.reserve(&binding).unwrap();
        journal
            .finish(&binding, terminal(ReplayTerminalOutcomeV1::Aborted))
            .unwrap();
        let mut forged = store.0.borrow().image.clone();
        forged.revision += 1;
        forged.records[0].state =
            TenantReplayStateV1::Terminal(terminal(ReplayTerminalOutcomeV1::Succeeded));
        store.install_authenticated_model_snapshot(forged);
        assert_eq!(
            journal.query(&binding),
            Err(TenantReplayErrorV1::RollbackDetected)
        );
    }

    #[test]
    fn terminal_status_lookup_is_independent_of_restored_record_order() {
        let store = ModelStore::provisioned();
        let original = binding();
        let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
        journal.reserve(&original).unwrap();
        let result = terminal(ReplayTerminalOutcomeV1::Aborted);
        journal.finish(&original, result).unwrap();
        let mut next = original.clone();
        next.0.operation.request_id = HostRequestId::new(99);
        next.0.tenant_evidence_digest[0] ^= 1;
        journal.reserve(&next).unwrap();
        let mut restored = store.0.borrow().image.clone();
        restored.records.reverse();
        store.install_authenticated_model_snapshot(restored);
        let mut reopened = TenantReplayJournalV1::new(store, 2).unwrap();
        assert_eq!(
            reopened.query(&original),
            Ok(Some(TenantReplayStateV1::Terminal(result)))
        );
        assert_eq!(
            reopened.reserve(&original),
            Err(TenantReplayErrorV1::TerminalOperation)
        );
        assert_eq!(
            reopened.reserve(&next),
            Ok(TenantReplayAdmissionV1::IdempotentRetry(
                TenantReplayStateV1::Reserved
            ))
        );
    }

    #[test]
    fn invalid_or_duplicate_snapshots_and_revision_exhaustion_fail_closed() {
        let store = ModelStore::provisioned();
        let binding = binding();
        let record = TenantReplayRecordV1 {
            binding: binding.0.clone(),
            state: TenantReplayStateV1::Reserved,
        };
        for image in [
            TenantReplaySnapshotV1 {
                revision: 0,
                records: vec![record.clone()],
            },
            TenantReplaySnapshotV1 {
                revision: 1,
                records: vec![],
            },
            TenantReplaySnapshotV1 {
                revision: 2,
                records: vec![record.clone(), record.clone()],
            },
        ] {
            store.install_authenticated_model_snapshot(image);
            let mut journal = TenantReplayJournalV1::new(store.clone(), 2).unwrap();
            assert_eq!(
                journal.query(&binding),
                Err(TenantReplayErrorV1::InvalidSnapshot)
            );
        }
        store.install_authenticated_model_snapshot(TenantReplaySnapshotV1 {
            revision: u64::MAX,
            records: vec![record],
        });
        let mut journal = TenantReplayJournalV1::new(store, 2).unwrap();
        let proof = VerifiedTenantAuthorizationV1::from_verified_roles(binding);
        assert_eq!(
            journal.authorize(&proof, &mut ModelFirmware::default()),
            Err(TenantReplayErrorV1::RevisionExhausted)
        );
    }
}
