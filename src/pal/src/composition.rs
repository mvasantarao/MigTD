// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Explicit composition contracts, not feature discovery or runtime activation.
//! Shared SNP callers borrow typed services; runtime roots own backend selection.

use crate::snp_report::{SnpEvidenceProfile, SnpTrustDomain};
use crate::types::PlatformType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformComposition {
    TdxHardware,
    AzCvmEmu,
    SnpEmuAzure,
    SnpHardware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustMode {
    NoStd,
    Std,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFamily {
    ExistingTdxHardware,
    ExistingTdxEmulator,
    SnpEmulator,
    SnpProduction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomnessProvider {
    ExistingTdxSystemRandom,
    LinuxSystemRandom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompositionSpec {
    pub platform: PlatformType,
    pub rust_mode: RustMode,
    pub providers: ProviderFamily,
    pub randomness: RandomnessProvider,
    pub snp_profile: Option<SnpEvidenceProfile>,
    pub snp_trust: Option<SnpTrustDomain>,
}

impl PlatformComposition {
    pub const fn name(self) -> &'static str {
        match self {
            Self::TdxHardware => "TDX hardware",
            Self::AzCvmEmu => "AzCVMEmu",
            Self::SnpEmuAzure => "SnpEmuAzure",
            Self::SnpHardware => "SnpHardware",
        }
    }

    pub const fn spec(self) -> CompositionSpec {
        match self {
            Self::TdxHardware | Self::AzCvmEmu => CompositionSpec {
                platform: PlatformType::Tdx,
                rust_mode: match self {
                    Self::TdxHardware => RustMode::NoStd,
                    _ => RustMode::Std,
                },
                providers: match self {
                    Self::TdxHardware => ProviderFamily::ExistingTdxHardware,
                    _ => ProviderFamily::ExistingTdxEmulator,
                },
                randomness: RandomnessProvider::ExistingTdxSystemRandom,
                snp_profile: None,
                snp_trust: None,
            },
            Self::SnpEmuAzure | Self::SnpHardware => CompositionSpec {
                platform: PlatformType::AmdSnp,
                rust_mode: RustMode::Std,
                providers: match self {
                    Self::SnpEmuAzure => ProviderFamily::SnpEmulator,
                    _ => ProviderFamily::SnpProduction,
                },
                randomness: RandomnessProvider::LinuxSystemRandom,
                snp_profile: Some(match self {
                    Self::SnpEmuAzure => SnpEvidenceProfile::SnpEmulatorV1,
                    _ => SnpEvidenceProfile::FirmwareAbi159V6,
                }),
                snp_trust: Some(match self {
                    Self::SnpEmuAzure => SnpTrustDomain::Fixture,
                    _ => SnpTrustDomain::ProductionAmd,
                }),
            },
        }
    }
}

#[cfg(feature = "snp-core")]
pub mod snp {
    use core::marker::PhantomData;

    use super::{CompositionSpec, PlatformComposition};
    use crate::random::{RandomSource, SystemRandomSource};
    use crate::snp::{
        binding_manager::MaBindingManagerV1,
        host_control::{HostControlContextAuthorityV1, SnpHostControlTransportV1},
        local_handoff::{LocalHandoffAuthorityV1, ProtectedHandoffSecretProviderV1},
        migration_install::SnpMigrationKeyInstaller,
        peer_channel::{PeerClockV1, PeerTransportFactory},
    };
    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    use crate::snp::{
        binding_manager::UnavailableMaBindingManagerV1,
        host_control::{
            UnavailableHostControlContextAuthorityV1, UnavailableSnpHostControlTransportV1,
        },
        local_handoff::UnavailableLocalHandoffServicesV1,
        migration_install::UnavailableMigrationKeyInstallerV1,
        peer_channel::{PeerProviderErrorV1, UnavailablePeerTransportFactoryV1},
    };
    use crate::snp_report::{SnpReportVerifier, UnavailableSnpReportVerifier};
    use crate::tenant_replay::{CurrentTenantFirmwareStateV1, DurableTenantReplayStoreV1};
    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    use crate::tenant_replay::{UnavailableTenantFirmwareStateV1, UnavailableTenantReplayStoreV1};
    use crate::traits::{
        MaEvidenceProvider, PlatformKeyProvider, SnpCollateralProvider,
        UnavailablePlatformKeyProvider,
    };
    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    use crate::types::{
        MaEvidence, MaEvidenceError, MaEvidenceRequest, SnpCollateralError, SnpCollateralRequest,
        SnpVerificationCollateral,
    };

    mod sealed {
        pub trait Sealed {}
    }

    pub trait SnpComposition: sealed::Sealed {
        const PLATFORM: PlatformComposition;
    }

    #[cfg(any(feature = "snp-fixture", test))]
    pub struct SnpEmuAzure;
    #[cfg(any(feature = "snp-linux-hardware", test))]
    pub struct SnpHardware;

    #[cfg(any(feature = "snp-fixture", test))]
    impl sealed::Sealed for SnpEmuAzure {}
    #[cfg(any(feature = "snp-linux-hardware", test))]
    impl sealed::Sealed for SnpHardware {}
    #[cfg(any(feature = "snp-fixture", test))]
    impl SnpComposition for SnpEmuAzure {
        const PLATFORM: PlatformComposition = PlatformComposition::SnpEmuAzure;
    }
    #[cfg(any(feature = "snp-linux-hardware", test))]
    impl SnpComposition for SnpHardware {
        const PLATFORM: PlatformComposition = PlatformComposition::SnpHardware;
    }

    /// Trusted emulator-root inputs, not host-selected providers. Verification
    /// and randomness are deliberately not injectable through this structure.
    pub struct SnpServiceProviders<P: PeerTransportFactory> {
        pub ma_evidence: Box<dyn MaEvidenceProvider>,
        pub collateral: Box<dyn SnpCollateralProvider>,
        pub peer_transport: P,
        pub peer_clock: Box<dyn PeerClockV1>,
        pub host_control: Box<dyn SnpHostControlTransportV1>,
        pub host_context: Box<dyn HostControlContextAuthorityV1>,
        pub replay: Box<dyn DurableTenantReplayStoreV1>,
        pub firmware_state: Box<dyn CurrentTenantFirmwareStateV1>,
        pub migration_install: Box<dyn SnpMigrationKeyInstaller>,
        pub bindings: Box<dyn MaBindingManagerV1>,
        pub handoff_authority: Box<dyn LocalHandoffAuthorityV1>,
        pub handoff_secrets: Box<dyn ProtectedHandoffSecretProviderV1>,
    }

    /// Borrowed typed seams; consumers cannot replace owned providers or change
    /// the composition. Policy and operation admission remain separate gates.
    pub struct SnpServiceRefs<'a, P: PeerTransportFactory> {
        pub ma_evidence: &'a dyn MaEvidenceProvider,
        pub collateral: &'a dyn SnpCollateralProvider,
        pub verifier: &'a dyn SnpReportVerifier,
        pub peer_transport: &'a mut dyn PeerTransportFactory<Session = P::Session>,
        pub peer_clock: &'a dyn PeerClockV1,
        pub host_control: &'a mut dyn SnpHostControlTransportV1,
        pub host_context: &'a mut dyn HostControlContextAuthorityV1,
        pub replay: &'a mut dyn DurableTenantReplayStoreV1,
        pub firmware_state: &'a mut dyn CurrentTenantFirmwareStateV1,
        pub platform_keys: &'a dyn PlatformKeyProvider,
        pub migration_install: &'a dyn SnpMigrationKeyInstaller,
        pub bindings: &'a mut dyn MaBindingManagerV1,
        pub handoff_authority: &'a mut dyn LocalHandoffAuthorityV1,
        pub handoff_secrets: &'a mut dyn ProtectedHandoffSecretProviderV1,
        pub randomness: &'a mut dyn RandomSource,
    }

    /// Owns one immutable provider selection for shared SNP orchestration.
    /// Neither construction nor a working RNG means the runtime is qualified.
    ///
    /// ```compile_fail
    /// use pal::composition::snp::{SnpEmuAzure, SnpHardwareProvider};
    /// fn production_only(_: SnpHardwareProvider) {}
    /// production_only(SnpEmuAzure::unavailable());
    /// ```
    ///
    /// ```compile_fail
    /// use pal::composition::snp::SnpHardware;
    /// use pal::random::SystemRandomSource;
    /// let mut hardware = SnpHardware::compose();
    /// hardware.randomness = SystemRandomSource::default();
    /// ```
    pub struct SnpProviderSet<C: SnpComposition, P: PeerTransportFactory> {
        services: SnpServiceProviders<P>,
        verifier: UnavailableSnpReportVerifier,
        platform_keys: UnavailablePlatformKeyProvider,
        randomness: SystemRandomSource,
        composition: PhantomData<C>,
    }

    impl<C: SnpComposition, P: PeerTransportFactory> SnpProviderSet<C, P> {
        pub const fn spec(&self) -> CompositionSpec {
            C::PLATFORM.spec()
        }

        pub fn services(&mut self) -> SnpServiceRefs<'_, P> {
            SnpServiceRefs {
                ma_evidence: self.services.ma_evidence.as_ref(),
                collateral: self.services.collateral.as_ref(),
                verifier: &self.verifier,
                peer_transport: &mut self.services.peer_transport,
                peer_clock: self.services.peer_clock.as_ref(),
                host_control: self.services.host_control.as_mut(),
                host_context: self.services.host_context.as_mut(),
                replay: self.services.replay.as_mut(),
                firmware_state: self.services.firmware_state.as_mut(),
                platform_keys: &self.platform_keys,
                migration_install: self.services.migration_install.as_ref(),
                bindings: self.services.bindings.as_mut(),
                handoff_authority: self.services.handoff_authority.as_mut(),
                handoff_secrets: self.services.handoff_secrets.as_mut(),
                randomness: &mut self.randomness,
            }
        }
    }

    #[cfg(any(feature = "snp-fixture", test))]
    impl SnpEmuAzure {
        pub fn compose<P: PeerTransportFactory>(
            services: SnpServiceProviders<P>,
        ) -> SnpProviderSet<Self, P> {
            SnpProviderSet {
                services,
                verifier: UnavailableSnpReportVerifier,
                platform_keys: UnavailablePlatformKeyProvider,
                randomness: SystemRandomSource::default(),
                composition: PhantomData,
            }
        }

        /// A non-operational composition, not a successful emulator fallback.
        pub fn unavailable() -> SnpProviderSet<Self, UnavailablePeerTransportFactoryV1> {
            Self::compose(unavailable_services())
        }
    }

    /// The closed production bundle, not the legacy hardware MA-report adapter.
    /// Linux MA acquisition is selected explicitly; collateral, AAS/layout and
    /// Phase 5 effect gates remain unavailable. This is not qualification.
    #[cfg(any(feature = "snp-linux-hardware", test))]
    pub type SnpHardwareProvider = SnpProviderSet<SnpHardware, UnavailablePeerTransportFactoryV1>;

    #[cfg(any(feature = "snp-linux-hardware", test))]
    impl SnpHardware {
        /// Production cannot accept emulator-root injection.
        ///
        /// ```compile_fail
        /// use pal::composition::snp::{SnpEmuAzure, SnpHardware};
        /// SnpHardware::compose(SnpEmuAzure::unavailable());
        /// ```
        pub fn compose() -> SnpHardwareProvider {
            let services = unavailable_services();
            #[cfg(feature = "snp-linux-hardware")]
            let services = SnpServiceProviders {
                ma_evidence: Box::new(crate::snp::hardware::SnpHardwareProvider),
                ..services
            };
            SnpProviderSet {
                services,
                verifier: UnavailableSnpReportVerifier,
                platform_keys: UnavailablePlatformKeyProvider,
                randomness: SystemRandomSource::default(),
                composition: PhantomData,
            }
        }
    }

    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    struct UnavailableEvidence;
    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    impl MaEvidenceProvider for UnavailableEvidence {
        fn acquire_ma_evidence(
            &self,
            _: &MaEvidenceRequest,
        ) -> Result<MaEvidence, MaEvidenceError> {
            log::error!("SNP composition MA evidence provider unavailable");
            Err(MaEvidenceError::ProviderUnavailable)
        }
    }
    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    impl SnpCollateralProvider for UnavailableEvidence {
        fn acquire_snp_collateral(
            &self,
            _: &SnpCollateralRequest<'_>,
        ) -> Result<SnpVerificationCollateral, SnpCollateralError> {
            log::error!("SNP composition collateral provider unavailable");
            Err(SnpCollateralError::ProviderUnavailable)
        }
    }

    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    struct UnavailableClock;
    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    impl PeerClockV1 for UnavailableClock {
        fn unix_seconds(&self) -> Result<u64, PeerProviderErrorV1> {
            log::error!("SNP composition trusted clock unavailable");
            Err(PeerProviderErrorV1::Unavailable)
        }
    }

    #[cfg(any(feature = "snp-fixture", feature = "snp-linux-hardware", test))]
    /// Explicit unavailable defaults for trusted emulator composition roots.
    /// This does not open the closed production constructor to injection.
    pub fn unavailable_services() -> SnpServiceProviders<UnavailablePeerTransportFactoryV1> {
        SnpServiceProviders {
            ma_evidence: Box::new(UnavailableEvidence),
            collateral: Box::new(UnavailableEvidence),
            peer_transport: UnavailablePeerTransportFactoryV1,
            peer_clock: Box::new(UnavailableClock),
            host_control: Box::new(UnavailableSnpHostControlTransportV1),
            host_context: Box::new(UnavailableHostControlContextAuthorityV1),
            replay: Box::new(UnavailableTenantReplayStoreV1),
            firmware_state: Box::new(UnavailableTenantFirmwareStateV1),
            migration_install: Box::new(UnavailableMigrationKeyInstallerV1),
            bindings: Box::new(UnavailableMaBindingManagerV1),
            handoff_authority: Box::new(UnavailableLocalHandoffServicesV1),
            handoff_secrets: Box::new(UnavailableLocalHandoffServicesV1),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::snp::host_control::{
            HostControlBodyV1, HostControlErrorV1, HostControlFrameV1, HostControlKindV1,
            HostOperationPhaseV1,
        };
        use crate::snp::peer_channel::{PeerFailureV1, PeerSessionRequestV1};
        use crate::snp::purpose_binding::{LocalHandoffBindingV1, SnpOperationStageV1};
        use crate::snp::report_data_context::{
            ReportDataContextV1, SnpEvidencePurposeV1, SnpMaRoleV1, SnpMigrationAlgorithmV1,
        };
        use crate::snp_report::{
            SnpCollateralInput, SnpEvidenceInput, SnpReportVerificationError,
            SnpReportVerificationRequest, SnpRevocationInput, SnpTrustDomain,
        };
        use crate::tenant_replay::{
            ReplayTerminalOutcomeV1, ReplayTerminalResultV1, TenantReplayErrorV1,
            TenantReplaySnapshotV1,
        };
        use crate::traits::PalError;
        use crate::types::{
            HostRequestId, MaEvidenceBinding, ManagedGuestHandle, MigrationId, MigrationRole,
            SnpOperationContext,
        };

        struct CapturedEvidence;
        impl MaEvidenceProvider for CapturedEvidence {
            fn acquire_ma_evidence(
                &self,
                _: &MaEvidenceRequest,
            ) -> Result<MaEvidence, MaEvidenceError> {
                Ok(MaEvidence::new(
                    [0x33; 1184],
                    MaEvidenceBinding::CapturedFixture,
                ))
            }
        }

        fn check_unavailable<C: SnpComposition, P: PeerTransportFactory>(
            set: &mut SnpProviderSet<C, P>,
        ) {
            let services = set.services();
            let evidence = MaEvidence::new([0; 1184], MaEvidenceBinding::RequestedReportData);
            assert!(matches!(
                services
                    .collateral
                    .acquire_snp_collateral(&SnpCollateralRequest::new(&evidence)),
                Err(SnpCollateralError::ProviderUnavailable)
            ));
            assert_eq!(
                services.peer_clock.unix_seconds(),
                Err(PeerProviderErrorV1::Unavailable)
            );
            assert_eq!(
                services.host_control.receive(),
                Err(HostControlErrorV1::ProviderUnavailable)
            );
            assert_eq!(
                services.replay.load_authenticated(2),
                Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
            );
            assert_eq!(
                services.replay.commit(
                    0,
                    &TenantReplaySnapshotV1 {
                        revision: 1,
                        records: vec![],
                    },
                ),
                Err(TenantReplayErrorV1::ProductionReplayStateUnavailable)
            );
            let context = SnpOperationContext::new(
                HostRequestId::new(7),
                MigrationId::new(8),
                MigrationRole::Source,
                ManagedGuestHandle::new(9),
            );
            assert_eq!(
                services.host_context.reserve_operation(&context),
                Err(HostControlErrorV1::ProviderUnavailable)
            );
            assert_eq!(
                services.host_context.finish_before_proofs(
                    &context,
                    ReplayTerminalResultV1 {
                        outcome: ReplayTerminalOutcomeV1::Failed,
                        result_digest: [0; 48],
                    },
                ),
                Err(HostControlErrorV1::ProviderUnavailable)
            );
            assert_eq!(
                services.host_control.respond(&HostControlFrameV1 {
                    kind: HostControlKindV1::Query,
                    response: true,
                    operation: context,
                    body: HostControlBodyV1::Status {
                        phase: HostOperationPhaseV1::AwaitingEvidence,
                        terminal: None,
                    },
                }),
                Err(HostControlErrorV1::ProviderUnavailable)
            );
            let local = ReportDataContextV1 {
                evidence_purpose: SnpEvidencePurposeV1::InterNodeSessionV2,
                role: SnpMaRoleV1::Source,
                request_id: context.request_id.value(),
                negotiated_migration_version: 1,
                algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
                tenant_binding_id: [0x33; 32],
                th1: [0; 48],
                purpose_binding_digest: [0x44; 48],
                ma_policy_identity_digest: [0x55; 48],
            };
            let mut peer = local.clone();
            peer.role = SnpMaRoleV1::Destination;
            let request = PeerSessionRequestV1::inter_node(context, local, peer, 20).unwrap();
            assert_eq!(
                services.peer_transport.establish(&request).err(),
                Some(PeerFailureV1::Provider(PeerProviderErrorV1::Unavailable).into())
            );
            assert!(matches!(
                services.platform_keys.prepare_key(&context),
                Err(PalError::NotAvailable)
            ));
        }

        #[test]
        fn both_compositions_share_typed_fail_closed_effects() {
            let mut emulator = SnpEmuAzure::unavailable();
            assert!(matches!(
                emulator
                    .services()
                    .ma_evidence
                    .acquire_ma_evidence(&MaEvidenceRequest::new([0x44; 64])),
                Err(MaEvidenceError::ProviderUnavailable)
            ));
            check_unavailable(&mut emulator);
            // Do not issue real /dev/sev-guest ioctls in a host unit test.
            check_unavailable(&mut SnpHardware::compose());
        }

        fn check_two_process_scenarios<C: SnpComposition, P: PeerTransportFactory>(
            set: &mut SnpProviderSet<C, P>,
        ) {
            let mut local = ReportDataContextV1 {
                evidence_purpose: SnpEvidencePurposeV1::InterNodeSessionV2,
                role: SnpMaRoleV1::Source,
                request_id: 7,
                negotiated_migration_version: 1,
                algorithm: SnpMigrationAlgorithmV1::Aes256GcmMigrationV1,
                tenant_binding_id: [0x33; 32],
                th1: [0; 48],
                purpose_binding_digest: [0x44; 48],
                ma_policy_identity_digest: [0x55; 48],
            };
            for (role, local_role, peer_role) in [
                (
                    MigrationRole::Source,
                    SnpMaRoleV1::Source,
                    SnpMaRoleV1::Destination,
                ),
                (
                    MigrationRole::Destination,
                    SnpMaRoleV1::Destination,
                    SnpMaRoleV1::Source,
                ),
            ] {
                let operation = SnpOperationContext::new(
                    HostRequestId::new(7),
                    MigrationId::new(8),
                    role,
                    ManagedGuestHandle::new(9),
                );
                local.role = local_role;
                let mut peer = local.clone();
                peer.role = peer_role;
                let request =
                    PeerSessionRequestV1::inter_node(operation, local.clone(), peer, 20).unwrap();
                assert_eq!(
                    set.services().peer_transport.establish(&request).err(),
                    Some(PeerFailureV1::Provider(PeerProviderErrorV1::Unavailable).into())
                );
            }
            local.evidence_purpose = SnpEvidencePurposeV1::LocalPlannedHandoffAuthorization;
            local.algorithm = SnpMigrationAlgorithmV1::LocalHandoffSecretV1;
            local.tenant_binding_id = [0; 32];
            let binding = LocalHandoffBindingV1 {
                purpose: local.evidence_purpose,
                stage: SnpOperationStageV1::PrepareAuthorization,
                attempt_number: 1,
                operation_id: [1; 16],
                request_id: local.request_id,
                operation_epoch: 2,
                deadline_unix_seconds: 20,
                previous_ma_report_id: [3; 32],
                new_ma_report_id: [4; 32],
                tenant_set_digest: [5; 48],
                ma_policy_identity_digest: local.ma_policy_identity_digest,
                firmware_result_set_digest: [0; 48],
            };
            for (local_role, peer_role) in [
                (SnpMaRoleV1::Outgoing, SnpMaRoleV1::Incoming),
                (SnpMaRoleV1::Incoming, SnpMaRoleV1::Outgoing),
            ] {
                local.role = local_role;
                let mut peer = local.clone();
                peer.role = peer_role;
                let request = PeerSessionRequestV1::local_handoff(
                    binding.clone(),
                    local.clone(),
                    peer,
                    [6; 48],
                )
                .unwrap();
                assert_eq!(
                    set.services().peer_transport.establish(&request).err(),
                    Some(PeerFailureV1::Provider(PeerProviderErrorV1::Unavailable).into())
                );
            }
        }

        #[test]
        fn inter_node_and_local_handoff_compositions_fail_closed_in_both_roles() {
            check_two_process_scenarios(&mut SnpEmuAzure::unavailable());
            check_two_process_scenarios(&mut SnpHardware::compose());
        }

        #[test]
        fn emulator_injection_does_not_modify_production_or_create_claims() {
            let mut services = unavailable_services();
            services.ma_evidence = Box::new(CapturedEvidence);
            let mut emulator = SnpEmuAzure::compose(services);
            assert_eq!(emulator.spec(), PlatformComposition::SnpEmuAzure.spec());
            let evidence = emulator
                .services()
                .ma_evidence
                .acquire_ma_evidence(&MaEvidenceRequest::new([0x44; 64]))
                .unwrap();
            assert_eq!(evidence.binding(), MaEvidenceBinding::CapturedFixture);
            assert_eq!(evidence.report(), &[0x33; 1184]);
            check_unavailable(&mut SnpHardware::compose());
        }

        #[test]
        fn no_composition_has_an_authenticated_aas_adapter_yet() {
            let raw = SnpEvidenceInput::RawAmdReport {
                report: Box::new([0; 1184]),
            };
            let emulator =
                SnpEvidenceInput::EmulatorV1(Box::new(crate::snp_report::SnpEmulatorEvidenceV1 {
                    report: [0; 1184],
                    supplement: [0; 220],
                    supplement_signature: [0; 96],
                }));
            for trust in [SnpTrustDomain::Fixture, SnpTrustDomain::ProductionAmd] {
                let collateral = SnpCollateralInput {
                    expected_trust_domain: trust,
                    leaf_certificate_der: vec![],
                    intermediate_certificate_der: vec![],
                    root_certificate_der: vec![],
                    revocation: SnpRevocationInput::FixtureNotApplicable,
                    verification_time_unix_seconds: 0,
                };
                for evidence in [&raw, &emulator] {
                    for verifier in [
                        SnpEmuAzure::unavailable().services().verifier,
                        SnpHardware::compose().services().verifier,
                    ] {
                        for request in [
                            SnpReportVerificationRequest::HostRequestedTenant {
                                evidence,
                                collateral: &collateral,
                            },
                            SnpReportVerificationRequest::GuestRequestedTenant {
                                evidence,
                                collateral: &collateral,
                                expected_vmpl: 1,
                                expected_report_data: [1; 64],
                            },
                            SnpReportVerificationRequest::GuestRequestedMa {
                                evidence,
                                collateral: &collateral,
                                expected_vmpl: 2,
                                expected_report_data: [2; 64],
                            },
                        ] {
                            assert_eq!(
                                verifier.verify(request),
                                Err(SnpReportVerificationError::ProviderUnavailable)
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn both_snp_compositions_use_the_real_shared_random_service() {
            let mut emulator = SnpEmuAzure::unavailable();
            let mut hardware = SnpHardware::compose();
            for randomness in [
                emulator.services().randomness,
                hardware.services().randomness,
            ] {
                let mut bytes = [0; 32];
                randomness.fill_random32(&mut bytes).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_compositions_preserve_platform_mode_and_trust_boundaries() {
        let cases = [
            (
                PlatformComposition::TdxHardware,
                "TDX hardware",
                RustMode::NoStd,
            ),
            (PlatformComposition::AzCvmEmu, "AzCVMEmu", RustMode::Std),
            (
                PlatformComposition::SnpEmuAzure,
                "SnpEmuAzure",
                RustMode::Std,
            ),
            (
                PlatformComposition::SnpHardware,
                "SnpHardware",
                RustMode::Std,
            ),
        ];
        for (composition, name, mode) in cases {
            assert_eq!(composition.name(), name);
            assert_eq!(composition.spec().rust_mode, mode);
        }
        for composition in [
            PlatformComposition::TdxHardware,
            PlatformComposition::AzCvmEmu,
        ] {
            let spec = composition.spec();
            assert_eq!(spec.platform, PlatformType::Tdx);
            assert_eq!(spec.randomness, RandomnessProvider::ExistingTdxSystemRandom);
            assert_eq!(spec.snp_profile, None);
            assert_eq!(spec.snp_trust, None);
        }
        for (composition, family, profile, trust) in [
            (
                PlatformComposition::SnpEmuAzure,
                ProviderFamily::SnpEmulator,
                SnpEvidenceProfile::SnpEmulatorV1,
                SnpTrustDomain::Fixture,
            ),
            (
                PlatformComposition::SnpHardware,
                ProviderFamily::SnpProduction,
                SnpEvidenceProfile::FirmwareAbi159V6,
                SnpTrustDomain::ProductionAmd,
            ),
        ] {
            let spec = composition.spec();
            assert_eq!(spec.platform, PlatformType::AmdSnp);
            assert_eq!(spec.providers, family);
            assert_eq!(spec.randomness, RandomnessProvider::LinuxSystemRandom);
            assert_eq!(spec.snp_profile, Some(profile));
            assert_eq!(spec.snp_trust, Some(trust));
        }
    }
}
