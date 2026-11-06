# Q162 Task 4 SNP Provider Architecture

## Status

This directory defines the target provider architecture for Q162 Task 4.
The diagrams are editable Mermaid sources embedded in Markdown and are the
version-controlled architecture reference for the implementation.

Current firmware-command assumptions are governed by the
[Firmware ABI 1.59 / ARG v1.20 current addendum](q162-arg-v120-command-addendum.md#current-p02-addendum-2026-11-02).
Evidence verification is software validation, not the removed
`MSG_VERIFY_REPORT` operation. Hardware installation retains
`MSG_SET_MIGRATION_INFO` (ARG v1.20 section 8.2).
The current addendum also covers local handoff/recovery commands, all fourteen
Venice ETCB components, and the unresolved Version 6 physical-layout conflict;
the earlier 2026-10-24 addendum body is historical.

The current secret protocol is the user-directed
[T4.14-PRE direct-random amendment](t4.14-pre-direct-random.md):
source-only random32 MSK, independent outgoing random32 handoff secret,
protected acceptance receipts and separate correlated firmware outcomes.
V1 contribution/commitment/HKDF/HMAC definitions and approvals are historical,
not active requirements. The pre-step, T4.14 secret services and T4.15 typed
provider sets were accepted within their documented bounded scopes.
T4.16 feature isolation was accepted within its documented bounded scope and
exclusions at `2026-11-05T16:11:10.268Z`. T4.17 interface/provider conformance
passed bounded validation at `2026-11-05T17:21:34.964Z` and was explicitly
accepted within its documented bounded scope and exclusions at
`2026-11-05T17:27:38.397Z`. Its 55 feature/public-API checks and full
local regression gates pass; see the
[coverage and exclusions](../approval-decision-technical-note.md#26-t417-interface-and-provider-conformance).
Common-claims policy work is identity projection, not authentication,
full policy admission or effectful caller activation.
Shared SNP/std and Underhill runtime capabilities are
independent of fixtures, production rejects mixed providers, and TAV is
removed from the workspace graph. Production startup fails explicitly while
its providers/common AAS Version 6 adapter remain unavailable. See the
[current T4.16 disposition](../../q162-revised-master-execution-plan.md#t416-feature-selection)
and [feature-selection diagram](feature-selection-diagram.md).
No effectful V2 activation or production qualification is implied.

The SDK dependency was separately updated to 0.2.0 at
`8774be30f452060c56372d34ccbe34c3d3f3c577`, retaining explicit native
verification. Its [maintenance validation](../approval-decision-technical-note.md#28-sdk-8774be3-update-and-regression)
records the successful full rerun, native SDK/TPM tests and required serial
registered-library invocation. Accepted T4.17 evidence remains unchanged.

T4.18 caller integration was authorized at `2026-11-05T18:20:16.530Z` and
validated within its bounded scope at `2026-11-05T18:58:22.061Z`. The user
accepted completion within its documented bounded scope and exclusions at
`2026-11-05T19:04:48.267Z`. A process-owned root is shared explicitly by WFR and
both SPDM roles. It routes separate selected MA evidence/collateral and isolates
legacy SDK/key-only mock compatibility from common V6 verification and V2
effects. The closed hardware root selects existing Linux MA acquisition, not
qualified production attestation; bootstrap exits 2 at its unavailable host
seam without calling the report ioctl. All 27 final local gates pass, including
57 feature/public-API checks, 32 firmware builds, six tools, 14 EMU scenarios
and rebuilt musl Stage A/B. The initial entry-root failure was repaired;
existing legacy lint/vendor-wide formatting limitations remain explicit.
See [the caller register and validation](../approval-decision-technical-note.md#29-t418-caller-integration).
See [the bounded acceptance record](../approval-decision-technical-note.md#30-t418-bounded-completion-acceptance).
Existing exclusions remain unchanged. T4.19 was separately authorized and
validated within its bounded scope at `2026-11-05T20:12:53.102Z`; the user
accepted completion within its documented bounded scope and exclusions at
`2026-11-05T23:49:26.373Z`. Its 26 final local command gates pass, including the
57 feature/API checks, PAL/interface/library suites, 32 firmware builds, six
tools, 14 EMU scenarios and rebuilt musl Stage A/B. New regression covers both
roles/directions of the two distinct two-process compositions at their
unavailable typed peer boundary, not a local-handoff runtime.
Separate explicit release ELF inventories and production scans pass.
See [the T4.19 coverage and deferred gates](../approval-decision-technical-note.md#31-t419-task-4-regression).
No full Task 3 activation, P2.2 bundle qualification or broader acceptance is
implied. See [the bounded acceptance record](../approval-decision-technical-note.md#32-t419-bounded-completion-acceptance).
Existing exclusions remain unchanged. T4.20 is DONE - ACCEPTED AND FROZEN within
its documented bounded scope and exclusions at `2026-11-06T00:32:02.025Z`;
conditions: None. See the
[bounded acceptance record](../approval-decision-technical-note.md#34-t420-bounded-completion-acceptance).
The
[Task4 audit and freeze](task4-freeze.md),
[consumer-readiness matrix](consumer-readiness-matrix.md) and
[source/feature/dependency/image inventory](freeze-inventory.json) record the
handoff, including separate [emulator](image-content/SnpEmuAzure.json) and
[production](image-content/SnpHardware.json) ELF manifests.
The user authorized only a documentation freeze commit; the audited source
remains uncommitted and hash-identified. The commit is not a reproducible source
snapshot. Fresh documentation/provenance checks do not relabel accepted T4.19
runtime tests as new runs. The Phase1 interface-level gate is satisfied only
within those bounds; P2.1 was separately authorized at
`2026-11-06T00:34:35.144Z` and is recorded in the central execution log.
P2.2 is separately authorized and IN PROGRESS at `2026-11-06T00:49:32.416Z`;
the user subsequently authorized the separate accepted-prerequisite commit
`5d6a4ad302d2c5b17a8a80d11286657559ad126d` for fresh-source validation. The
[bundle contract](../../snp-bundles.md) is implemented; final fresh-checkout
validation remains pending. The external consumer conversion is
`700e22aae1bcf09aff7d591cffc5ea6a39b4169c`; nested source was moved intact after
actual old/new VM runs and explicit approval of the stale-assertion change.
No qualification or P2.2 acceptance is inferred. Historical
inventory/validation/commit receipts retain their original snapshot status.
The T4.20 acceptance itself made no new commit; the separately authorized P2.1
naming commit is recorded below. No push, production qualification or Task12
reactivation is implied.

P2.1 is DONE - ACCEPTED AND FROZEN within its documented bounded naming-only
scope and exclusions at `2026-11-06T00:47:34.984Z`; conditions: None. Commit:
`1dbb3e6bf8e9f3666d9a5ead2dbb6e66b6d15481`.
Canonical runners/environment/diagnostics and compatibility aliases are in the
[scenario guide](../../snp-migration-scenarios.md). Eight naming tests pass in
both the working and isolated rename-only index snapshots; all four actual
canonical/alias frozen-ELF regressions pass. Prerequisite implementation and
acceptance changes remain uncommitted. Historical records/manifests are
unchanged; no runtime/provider activation or P2.2 start is claimed. See
[technical-note section35](../approval-decision-technical-note.md#35-p21-descriptive-migration-scenario-terminology).
Explicit acceptance is recorded in
[technical-note section36](../approval-decision-technical-note.md#36-p21-bounded-completion-acceptance).
All exclusions remain unchanged. Historical validation/commit snapshots are
preserved; no tests are rerun, new commit/push made or P2.2 execution authorized.

Task 4 defines interfaces, provider composition, fail-closed selection,
conformance implementations, and caller integration. It does not activate the
Task 3 MA/tenant evidence VDM exchanges or implement the full behavior owned by
Q162 Tasks 5-12.

T4.10 resolves the V1 platform-key operation set as empty: the accepted
direct-random MSK and handoff recipes require no
firmware-derived key. `MSG_KEY_REQ` remains a valid Firmware ABI service, not
a mandatory migration step. `PlatformKeyProvider` is retained only as a disabled
compatibility boundary; `UnavailablePlatformKeyProvider::prepare_key` returns
`PalError::NotAvailable`. It is not a required provider-set slot or runtime call.
Future platform-secret uses require a separately approved purpose-scoped typed
contract and hardware qualification. The canonical
[T4.10 contract](../../q162-revised-master-execution-plan.md#t410-platform-key-provider)
governs this disposition.

T4.11 adds the bounded typed
`pal::snp::migration_install::SnpMigrationKeyInstaller` contract, validated
borrowed request, correlated local results/errors and explicit
`UnavailableMigrationKeyInstallerV1`. It does not activate a runtime installer.
The old key-only `pal::traits::MigrationKeyInstaller` and mock remain legacy
compatibility code, not adapters to this new boundary. See the
[approved T4.11 contract](../../q162-revised-master-execution-plan.md#t411-migration-key-and-history-installer).
Stateful emulation and actual OHCL/kernel effects remain later work.

T4.12 adds the approved bounded
[`SnpHostOperationV1`](../../../src/pal/src/snp/host_control.rs),
the historical `InstallExchangeSequenceV1` and
[`MaBindingManagerV1`](../../../src/pal/src/snp/binding_manager.rs).
Its versioned host framing is separate from the legacy TCP encoding and from
any future OHCL UAPI/GHCB encoding. A pre-proof context authority closes the
restart gap before P0.6 has a verified binding; no production implementation
or empty-state fallback is selected.

T4.14-PRE replaces that historical sequence with
[`InstallExchangeSequenceV2`](../../../src/pal/src/snp/direct_exchange.rs):
key delivery/acceptance, destination completion and source completion/ack.
There is no application HMAC confirmation. Historical V1 controllers are
test-only; fresh purpose3 remains deferred. Original conformance scope is in the
[T4.12 contract](../../q162-revised-master-execution-plan.md#t412-host-control-and-ma-binding-interfaces).
The bounded implementation was accepted on 2026-11-04; real provider/transport
activation, production storage and hardware qualification remain separate gates.

T4.13 adds the bounded
[`peer_channel`](../../../src/pal/src/snp/peer_channel.rs) boundary:
trusted `PeerTransportFactory`/`PeerSession`, a bootstrap owner and distinct
`InterNodeMigrationPeerSession`/`LocalMaHandoffPeerSession` application owners.
Actual backend TH1 and existing verified MA/policy evidence are required for
promotion; current backend authority is checked around application I/O.
An unavailable production factory and test-only backends are supplied, not
activated TCP/Underhill providers. The inter-node registry lookup is shared
with MigTD's static validator; local metadata/secret operations remain logical
protected records without a new wire ABI. Recovery needs no old-MA peer.
See the [T4.13 contract](../../q162-revised-master-execution-plan.md#t413-peer-channel-boundary)
and [production actions](../../snp-production-readiness.md#pa-007-t413-peer-channel-qualification-actions).
The bounded implementation was separately accepted at 2026-11-04T18:25:34Z;
production transport/policy composition, local wire and hardware remain gated.

## Provisional Task 4 image inventories

Run the inventory controls and create a fresh, separate pair of release ELF
inventories (the output directory must not already exist):

```bash
python3 -m unittest discover -s sh_script/test -p test_snp_task4_inventory.py -v
AS=nasm AR=llvm-ar CC=clang RUSTUP_TOOLCHAIN=1.90.0 \
  python3 sh_script/test/snp_task4_inventory.py \
  --target x86_64-unknown-linux-gnu \
  --output-dir target/task4-image-inventory-new-run
```

The [inventory tool](../../../sh_script/test/snp_task4_inventory.py) builds
`SnpEmuAzure` and `SnpHardware` explicitly with defaults disabled, archives each
ELF before building the other, and records target/environment, source/image
hashes and normal/build dependency features in separate manifests.
Production byte/symbol scans reject the three captured assets, both P0.10
synthetic roots and named fixture/mock/test/TDX symbols. The emulator's captured
assets are a positive control; the genuine public AMD ARK is not forbidden.
The production startup check requires exit 2 with the selected unavailable
host-control diagnostic and never exercises report acquisition.

These are provisional ELF-only image-content inventories, not a deployment
bundle schema, kernel/initramfs inventory or P2.2 qualification. Successful
scans do not prove that the linked image has operational hardware or common
AAS V6 capability. The unavailable V6 adapter and actual composed-claims
conformance remain deferred to AAS1A-M.

## Artifacts

| Artifact | Purpose |
|---|---|
| [Rust type and provider diagram](rust-type-provider-diagram.md) | Traits, concrete providers, ownership, and realization relationships |
| [Provider-set diagram](provider-set-diagram.md) | Complete emulator and hardware provider compositions |
| [Feature-selection diagram](feature-selection-diagram.md) | Compile-time product configurations and fail-closed rules |
| [Sequence diagrams](sequence-diagrams.md) | Host control, peer channel, evidence, verification, key installation, and post-install flows |
| [Direct-random pre-step](t4.14-pre-direct-random.md) | Current V2 secrets, evidence/session bindings, receipts, exact wire and historical supersession |
| [P0.5 contribution wire addendum and result](p0.5-contribution-wire-addendum.md) | Historical V1 allocations/conformance, explicitly superseded for active secret establishment |

## Layering

```text
MigTD SNP runtime
  owns:
    SnpRuntime
    SnpProviderSet
    HostControlTransport
    PeerTransport
    workflow/session state

PAL
  owns:
    platform-service traits
    platform-neutral provider requests/results/errors
    fixture and hardware platform implementations

snp_emu
  owns:
    fixture data and emulator-specific implementations
  implements:
    PAL provider traits
```

`pal` must not import MigTD runtime types. Its typed provider set aggregates PAL
service seams; MigTD composition roots select the set once. T4.18 wires existing
callers without promoting legacy frames, SDK results or mock installation into
V2 admission. Full runtime host/peer exchange remains a later activation gate.

## Provider contract inventory

The exact Rust signatures are frozen in Task 4 Steps 5-14. The architecture
requires the following workflow-facing operations.

| Boundary | Required operation | Fixture/emulator provider | Hardware provider | Full behavior owner |
|---|---|---|---|---|
| MA evidence | `acquire_ma_evidence(request)` | Signed/captured fixture source | Live SNP report source | Tasks 6-7 |
| Tenant evidence | `acquire_tenant_evidence(request)` | Signed tenant fixture source | Production tenant-report source | Tasks 6 and 8 |
| Collateral | `get_collateral(request)` | Fixture VCEK/VLEK and ASK | Certificate table/host collateral source | Tasks 6-8 |
| Evidence verification | `verify_evidence(request)` | AAS or explicit test-root verifier | AAS production trust | Tasks 7-9 |
| Platform-derived key | None required in V1 | Unavailable compatibility boundary only | No approved adapter or operation | Future purpose-specific contract |
| Migration-key installation | `SnpMigrationKeyInstaller::install_migration_info(request)` | Unavailable now; later stateful provider | Unavailable now; later OHCL/ARG provider | Task 11 / H5 |
| Host control | `wait_for_request()` and `report_status(response)` | TCP/synthetic transport | BASE team/Underhill transport | Shared; hardware integration later |
| Peer channel | connect/listen/read/write/shutdown | TCP emulation | Underhill transport | Shared transport; Tasks 7-10 consume it |
| Randomness | `fill(destination)` | Deterministic test or system provider | Cryptographically secure provider | Task 10 |
| Migration state | load/store/update non-secret state | In-memory/test store | Production state provider | Tasks 9 and 11 |

## Ownership hierarchy

```text
SnpRuntime
  owns Arc<SnpProviderSet>
  creates one SnpSession per accepted PrepareMigration request

SnpProviderSet
  owns immutable Arc<dyn Trait + Send + Sync> providers

SnpSession
  owns:
    SnpOperationContext
    peer-session handle
    protocol state
    ephemeral secrets

Providers
  may own synchronized implementation state
  must not depend on process-global active-operation variables
```

## Current-to-target mapping

| Current dependency | Target boundary / T4.18 disposition |
|---|---|
| Direct `SnpFixtureProvider` construction | Removed from SPDM/WFR; selected MA and collateral seams in one owned root |
| Direct `SnpQvl` construction | Removed from SPDM; isolated legacy SDK bridge, never the unavailable common V6 verifier |
| Combined report plus certificate blob | Separate selected evidence/collateral; encoding only at the legacy boundary |
| Historical `MockPlatformKeyProvider` prerequisite | Removed by T4.10; no required platform-key slot or call |
| `MockMigrationKeyInstaller` constructed in session code | Removed; explicit root-owned legacy service, not a fabricated-input V2 installer |
| Global active operation context | Explicit `SnpOperationContext` owned by session |
| Compile-time legacy `TransportType` alias | Compatibility retained; frozen V2 peer/host transport remains unavailable |
| TDX-shaped legacy `StartMigration` input | Preserved compatibility, not yet authenticated V2 `PrepareMigrationRequest` |
| `SnpUnderhill -> SnpEmu` | Distinct emulator and hardware provider-set features |

## Compatibility boundaries

Existing TCP opcode `1` remains a legacy compatibility encoding. Its current
adapter still produces the inherited `StartMigration` input; a later V2
activation must map it to authenticated internal `PrepareMigration`, not
invent the missing proofs, state or installation inputs.

Current scenario names are `SingleProcessMigration`,
`InterNodeTwoProcessMigration`, and `LocalMaHandoffTwoProcess`.
Use the [canonical runners and environment variables](../../snp-migration-scenarios.md).
The first two retain the existing autostart and WFR/controller behavior;
the local-handoff name is reserved for the future Phase4 runtime.
Old script paths/environment names are compatibility aliases only.
Historical validation summaries, hashes and frozen execution records above
retain their original terminology and bytes.

## Deferred behavior

Task 4 does not:

- remove inherited TDX/TDCALL dependencies from the active SNP workflow;
- activate `SnpMaEvidenceV1` or `SnpTenantEvidenceV1` exchange;
- generate synthetic signed reports or certificate hierarchies;
- activate the SNP direct-random key-delivery/acceptance protocol;
- implement complete stateful migration-key persistence;
- implement the OHCL ioctl or BASE team GHCB ABI;
- qualify Venice hardware.

The interfaces must nevertheless make those later tasks implementable without
adding another top-level platform boundary.

## Review rule

If a Task 5-12 consumer requires a direct platform call, a TDX field in a
shared SNP request, an undefined provider operation, or fixture fallback in a
hardware configuration, the Task 4 architecture is incomplete.
