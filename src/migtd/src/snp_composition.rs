// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Selected SNP providers and the explicitly isolated legacy fixture bridge.

#[cfg(feature = "SnpHardware")]
pub fn selected_provider_set() -> pal::composition::snp::SnpHardwareProvider {
    pal::composition::snp::SnpHardware::compose()
}

#[cfg(feature = "SnpHardware")]
#[derive(Debug)]
pub enum SnpRuntimeStartError {
    HostControl(pal::snp::host_control::HostControlErrorV1),
    ExchangeNotActivated,
}

/// Bootstrap only: consume the selected host boundary, never activate Task 3.
#[cfg(feature = "SnpHardware")]
pub fn start_selected_runtime(
    mut providers: pal::composition::snp::SnpHardwareProvider,
) -> Result<core::convert::Infallible, SnpRuntimeStartError> {
    providers
        .services()
        .host_control
        .receive()
        .map_err(SnpRuntimeStartError::HostControl)?;
    log::error!("SNP Task 3 exchange is not activated; refusing host operation");
    Err(SnpRuntimeStartError::ExchangeNotActivated)
}

#[cfg(all(test, feature = "SnpHardware"))]
mod hardware_tests {
    #[test]
    fn selected_startup_returns_the_real_unavailable_host_error() {
        assert!(matches!(
            super::start_selected_runtime(super::selected_provider_set()),
            Err(super::SnpRuntimeStartError::HostControl(
                pal::snp::host_control::HostControlErrorV1::ProviderUnavailable
            ))
        ));
    }
}

#[cfg(all(feature = "SnpEmu", not(feature = "SnpHardware")))]
pub fn selected_provider_set() -> pal::composition::snp::SnpProviderSet<
    pal::composition::snp::SnpEmuAzure,
    pal::snp::peer_channel::UnavailablePeerTransportFactoryV1,
> {
    let mut services = pal::composition::snp::unavailable_services();
    services.ma_evidence = Box::new(snp_emu::provider_fixture::SnpFixtureProvider);
    services.collateral = Box::new(snp_emu::provider_fixture::SnpFixtureProvider);
    pal::composition::snp::SnpEmuAzure::compose(services)
}

#[cfg(feature = "SnpEmu")]
mod legacy_fixture {
    use std::{cell::RefCell, rc::Rc};

    use pal::composition::snp::{SnpEmuAzure, SnpProviderSet};
    use pal::snp::fixture::{encode_legacy_ma_blob, platform_services};
    use pal::snp::peer_channel::UnavailablePeerTransportFactoryV1;
    use pal::snp::qvl::{validate::AttestationVerificationParams, verify::SnpQvl};
    use pal::traits::{MigrationKeyInstaller, PalError, QvlLibrary};
    use pal::types::{MaEvidenceRequest, SnpCollateralRequest, SnpOperationContext};

    /// One process-owned selection, shared by WFR and both SPDM roles. Borrows
    /// end before awaits; neither compatibility service is a V2 implementation.
    pub struct SnpEmuRuntime {
        selected: RefCell<SnpProviderSet<SnpEmuAzure, UnavailablePeerTransportFactoryV1>>,
        legacy_qvl: SnpQvl,
        legacy_installer: platform_services::MockMigrationKeyInstaller,
    }

    pub type SnpRuntimeProviders = Rc<SnpEmuRuntime>;

    pub fn selected_runtime_provider_set() -> SnpRuntimeProviders {
        Rc::new(SnpEmuRuntime {
            selected: RefCell::new(super::selected_provider_set()),
            legacy_qvl: SnpQvl,
            legacy_installer: platform_services::MockMigrationKeyInstaller,
        })
    }

    impl SnpEmuRuntime {
        pub fn legacy_report_blob(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, PalError> {
            let mut selected = self.selected.borrow_mut();
            let services = selected.services();
            let evidence = services
                .ma_evidence
                .acquire_ma_evidence(&MaEvidenceRequest::new(*report_data))
                .map_err(|error| {
                    log::error!("selected MA evidence acquisition failed: {error:?}");
                    PalError::NotAvailable
                })?;
            let collateral = services
                .collateral
                .acquire_snp_collateral(&SnpCollateralRequest::new(&evidence))
                .map_err(|error| {
                    log::error!("selected SNP collateral acquisition failed: {error:?}");
                    PalError::NotAvailable
                })?;
            encode_legacy_ma_blob(&evidence, &collateral)
        }

        /// Explicit legacy SDK verification; never a fallback from the common
        /// verifier and never an authenticated V6 claim or live TH1 binding.
        pub fn verify_legacy_fixture_quote(
            &self,
            quote: &[u8],
            context: &SnpOperationContext,
        ) -> Result<(), PalError> {
            use pal::types::SNP_ATTESTATION_REPORT_SIZE;

            platform_services::trace_qvl_verification(context, "begin", "pending");
            let result = (|| {
                let report = quote
                    .get(..SNP_ATTESTATION_REPORT_SIZE)
                    .ok_or(PalError::InvalidInput)?;
                let mut offset = SNP_ATTESTATION_REPORT_SIZE;
                let mut cert_chain = Vec::with_capacity(2);
                for _ in 0..2 {
                    let length_bytes = quote
                        .get(offset..offset + 4)
                        .ok_or(PalError::InvalidInput)?;
                    offset += 4;
                    let length = u32::from_le_bytes(
                        length_bytes
                            .try_into()
                            .map_err(|_| PalError::InvalidInput)?,
                    ) as usize;
                    if length == 0 || length > pal::snp::limits::MAX_SNP_CERTIFICATE_SIZE {
                        return Err(PalError::InvalidInput);
                    }
                    let end = offset.checked_add(length).ok_or(PalError::InvalidInput)?;
                    let certificate = quote.get(offset..end).ok_or(PalError::InvalidInput)?;
                    cert_chain.push(certificate.to_vec());
                    offset = end;
                }
                if offset != quote.len() {
                    return Err(PalError::InvalidInput);
                }
                let mut fixture_report_data = [0; 48];
                fixture_report_data.copy_from_slice(&report[0x50..0x80]);
                let params =
                    AttestationVerificationParams::crypto_only(report, &fixture_report_data);
                self.legacy_qvl.verify(&params, &cert_chain)?;
                Ok(())
            })();
            let outcome = if result.is_ok() { "success" } else { "failure" };
            platform_services::trace_qvl_verification(context, "end", outcome);
            if let Err(error) = &result {
                log::error!("selected legacy fixture verification failed: {error:?}");
            } else {
                eprintln!(
                    "[MA] FIXTURE_LIMITATION: the selected QVL verified the captured report signature and \
                     certificate chain; live TH1 report_data binding was not claimed"
                );
            }
            result
        }

        pub fn install_legacy_key(
            &self,
            context: &SnpOperationContext,
            key: &[u8],
        ) -> Result<(), PalError> {
            self.legacy_installer.set_migration_info(context, key)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::Cell;

        use pal::composition::snp::unavailable_services;
        use pal::snp_report::{
            SnpCollateralInput, SnpEvidenceInput, SnpReportVerificationError,
            SnpReportVerificationRequest, SnpRevocationInput, SnpTrustDomain,
        };
        use pal::traits::{MaEvidenceProvider, SnpCollateralProvider};
        use pal::types::{
            HostRequestId, MaEvidence, MaEvidenceError, ManagedGuestHandle, MigrationId,
            MigrationRole, SnpCollateralError, SnpVerificationCollateral,
        };

        fn context() -> SnpOperationContext {
            SnpOperationContext::new(
                HostRequestId::new(7),
                MigrationId::new(8),
                MigrationRole::Source,
                ManagedGuestHandle::new(9),
            )
        }

        struct CountedEvidence {
            calls: Rc<Cell<usize>>,
            fail: bool,
        }
        impl MaEvidenceProvider for CountedEvidence {
            fn acquire_ma_evidence(
                &self,
                request: &MaEvidenceRequest,
            ) -> Result<MaEvidence, MaEvidenceError> {
                self.calls.set(self.calls.get() + 1);
                if self.fail {
                    return Err(MaEvidenceError::DeviceIo);
                }
                snp_emu::provider_fixture::SnpFixtureProvider.acquire_ma_evidence(request)
            }
        }

        struct CountedCollateral {
            calls: Rc<Cell<usize>>,
        }
        impl SnpCollateralProvider for CountedCollateral {
            fn acquire_snp_collateral(
                &self,
                _: &SnpCollateralRequest<'_>,
            ) -> Result<SnpVerificationCollateral, SnpCollateralError> {
                self.calls.set(self.calls.get() + 1);
                Err(SnpCollateralError::ProviderUnavailable)
            }
        }

        #[test]
        fn legacy_callers_use_selected_evidence_and_collateral_without_fallback() {
            for fail_evidence in [false, true] {
                let evidence_calls = Rc::new(Cell::new(0));
                let collateral_calls = Rc::new(Cell::new(0));
                let mut services = unavailable_services();
                services.ma_evidence = Box::new(CountedEvidence {
                    calls: evidence_calls.clone(),
                    fail: fail_evidence,
                });
                services.collateral = Box::new(CountedCollateral {
                    calls: collateral_calls.clone(),
                });
                let providers = selected_runtime_provider_set();
                providers.selected.replace(SnpEmuAzure::compose(services));
                let other_role = providers.clone();
                assert!(Rc::ptr_eq(&providers, &other_role));
                for root in [&providers, &other_role] {
                    assert!(matches!(
                        root.legacy_report_blob(&[0x55; 64]),
                        Err(PalError::NotAvailable)
                    ));
                }
                assert_eq!(evidence_calls.get(), 2);
                assert_eq!(collateral_calls.get(), if fail_evidence { 0 } else { 2 });
            }
        }

        #[test]
        fn selected_blob_preserves_exact_captured_legacy_segments() {
            use snp_emu::report_emu::{fixture_ask_der, fixture_report_bytes, fixture_vcek_der};

            let providers = selected_runtime_provider_set();
            let mut expected = fixture_report_bytes().to_vec();
            for certificate in [fixture_vcek_der(), fixture_ask_der()] {
                expected.extend_from_slice(&(certificate.len() as u32).to_le_bytes());
                expected.extend_from_slice(certificate);
            }
            for requested_data in [[0; 64], [0x55; 64], [0xff; 64]] {
                assert_eq!(
                    providers.legacy_report_blob(&requested_data).unwrap(),
                    expected
                );
            }
        }

        #[test]
        fn legacy_success_cannot_enable_common_verification_or_effects() {
            use pal::snp::host_control::HostControlErrorV1;
            use pal::snp::peer_channel::PeerProviderErrorV1;
            use pal::tenant_replay::TenantReplayErrorV1;

            let providers = selected_runtime_provider_set();
            let quote = providers.legacy_report_blob(&[0x44; 64]).unwrap();
            providers
                .verify_legacy_fixture_quote(&quote, &context())
                .unwrap();
            providers
                .install_legacy_key(&context(), &[0x55; 32])
                .unwrap();
            assert!(matches!(
                providers.install_legacy_key(&context(), &[0x55; 31]),
                Err(PalError::InvalidInput)
            ));

            let evidence = SnpEvidenceInput::RawAmdReport {
                report: Box::new(quote[..1184].try_into().unwrap()),
            };
            let collateral = SnpCollateralInput {
                expected_trust_domain: SnpTrustDomain::Fixture,
                leaf_certificate_der: vec![],
                intermediate_certificate_der: vec![],
                root_certificate_der: vec![],
                revocation: SnpRevocationInput::FixtureNotApplicable,
                verification_time_unix_seconds: 1,
            };
            let mut selected = providers.selected.borrow_mut();
            let services = selected.services();
            assert_eq!(
                services
                    .verifier
                    .verify(SnpReportVerificationRequest::GuestRequestedMa {
                        evidence: &evidence,
                        collateral: &collateral,
                        expected_vmpl: 1,
                        expected_report_data: [0x44; 64],
                    }),
                Err(SnpReportVerificationError::ProviderUnavailable)
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
                services.peer_clock.unix_seconds(),
                Err(PeerProviderErrorV1::Unavailable)
            );
            let mut key = zeroize::Zeroizing::new([0; 32]);
            services.randomness.fill_random32(&mut key).unwrap();
        }

        #[test]
        fn selected_legacy_verifier_rejects_truncation_trailers_and_tampering() {
            let providers = selected_runtime_provider_set();
            let quote = providers.legacy_report_blob(&[0; 64]).unwrap();
            for length in 0..quote.len() {
                assert!(
                    matches!(
                        providers.verify_legacy_fixture_quote(&quote[..length], &context()),
                        Err(PalError::InvalidInput)
                    ),
                    "truncation at {length}"
                );
            }
            let mut trailing = quote.clone();
            trailing.push(0);
            assert!(matches!(
                providers.verify_legacy_fixture_quote(&trailing, &context()),
                Err(PalError::InvalidInput)
            ));
            let mut oversized = quote.clone();
            oversized[1184..1188].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(matches!(
                providers.verify_legacy_fixture_quote(&oversized, &context()),
                Err(PalError::InvalidInput)
            ));
            let mut tampered = quote;
            tampered[0x50] ^= 1;
            assert!(providers
                .verify_legacy_fixture_quote(&tampered, &context())
                .is_err());
        }
    }
}

#[cfg(feature = "SnpEmu")]
pub use legacy_fixture::{selected_runtime_provider_set, SnpEmuRuntime, SnpRuntimeProviders};
