# Frozen Rust ownership and provider interfaces

T4.20 records implemented types, not proposed platform adapters. Availability
and downstream obligations are in the [freeze](task4-freeze.md) and
[consumer matrix](consumer-readiness-matrix.md).

## Selected ownership

```mermaid
classDiagram
    class SnpProviderSet {
        private service providers
        private unavailable common verifier
        private disabled platform key provider
        private owned SystemRandomSource
        services() SnpServiceRefs
    }
    class SnpServiceProviders {
        owned boxed services
        generic PeerTransportFactory
    }
    class SnpServiceRefs {
        borrowed selected service references
    }
    class UnavailableSnpReportVerifier {
        verify() ProviderUnavailable
    }
    class SnpReportVerifier {
        <<interface>>
        verify() AuthenticatedSnpClaims
    }
    class HostPushedTenantEvidenceSource {
        operation-local package and receipt
        replay journal and current-state provider
    }
    class TenantEvidence {
        private construction
        common claims and complete provenance
    }
    class SnpHostOperationV1 {
        operation and immutable correlation
        tenant source and terminal state
    }
    SnpProviderSet *-- SnpServiceProviders
    SnpProviderSet *-- UnavailableSnpReportVerifier
    SnpProviderSet --> SnpServiceRefs : lends services
    UnavailableSnpReportVerifier ..|> SnpReportVerifier
    SnpHostOperationV1 *-- HostPushedTenantEvidenceSource
    HostPushedTenantEvidenceSource --> SnpReportVerifier : borrows selected verifier
    HostPushedTenantEvidenceSource *-- TenantEvidence : retains only after verification
```

The [provider set](../../../src/pal/src/composition.rs) is generic over a
composition marker and peer factory. Its owned boxes are not an `Arc` plugin
registry. Emulator construction accepts trusted services, not a replacement
verifier or RNG. Hardware construction is closed. Borrowed `SnpServiceRefs`
does not permit replacing selections.

The [process root](../../../src/migtd/src/snp_composition.rs) shares the
selected emulator root explicitly with WFR and both SPDM roles. Its
single-threaded `Rc<RefCell<...>>` handle is not the ownership type of every
PAL service. Tenant evidence is operation-local, not a provider-set field.

## Frozen service surfaces

```mermaid
flowchart LR
    SET["SnpServiceProviders"]
    SET --> E["MaEvidenceProvider / SnpCollateralProvider"]
    SET --> P["PeerTransportFactory / PeerClockV1"]
    SET --> H["HostControlTransport / HostControlContextAuthorityV1"]
    SET --> R["DurableTenantReplayStoreV1 / CurrentTenantFirmwareStateV1"]
    SET --> I["SnpMigrationKeyInstaller"]
    SET --> B["MaBindingManagerV1"]
    SET --> L["LocalHandoffAuthorityV1 / ProtectedHandoffSecretProviderV1"]
    V["SnpReportVerifier"] --> C["AuthenticatedSnpClaims"]
    C --> T["TenantEvidence / common identity projection"]
    T --> A["Separate policy, binding, replay and firmware admission"]
```

Evidence acquisition, verification, policy approval, durable authorization and
effects are distinct capabilities. The selected common verifier cannot yet
produce claims. Receipt/private-constructor checks are not a claim that the
unavailable production services exist.

## Secret and effect ownership

```mermaid
flowchart LR
    RNG["Owned SystemRandomSource"] --> MSK["Source-owned MigrationKeyV2"]
    RNG --> HS["Independent outgoing HandoffSecretV1"]
    MSK --> PD["Promoted inter-node protected I/O"]
    MSK --> IR["Borrowed MigrationInstallRequestV1"]
    IR --> FW["SnpMigrationKeyInstaller: role-correct effect"]
    HS --> PL["Promoted local protected I/O"]
    HS --> BR["Borrowed BindingSecretRequestV1"]
    BR --> BM["MaBindingManagerV1: set / clear"]
    FW --> OUT["Correlated completion or explicit partial / unknown error"]
```

These are implemented contracts and logical transitions, not active V2
transport or firmware effects. Secrets are owned/zeroizing and redacted;
borrowed requests do not clone them. Host control never carries either
secret. No `MigrationStateStore`, injected tenant-provider slot,
`AzureSnpEvidenceVerifier`, or operational Underhill peer implementation is
asserted by this diagram.
