# T4.20 Task4 interface and composition freeze

Status: IMPLEMENTED AND VALIDATED WITHIN BOUNDED SCOPE; explicit user acceptance
pending. Freeze identifier: `T4.20-Task4Freeze-2026-11-05`.
Authorization: `2026-11-05T23:50:40.311Z`.

This freezes the audited typed contracts, selected compositions and explicit
consumer obligations inherited from accepted T4.9-T4.19. It does not activate
their missing providers or declare Phase1 accepted. P2.1/P2.2 remain NOT
STARTED, pending the canonical acceptance/authorization gates.

## Provenance and commit boundary

The user selected: **commit only T4.20 freeze documents; identify the audited,
still-uncommitted implementation by hashes**. No source, Cargo files, scripts,
fixtures, submodules or unrelated worktree changes belong in that commit.
Some freeze-related documents were previously untracked; their first commit
necessarily includes existing historical contents, not only T4.20 additions.
No push is authorized.

- Audited source identifier: `T4.20-AuditedImplementation-20261105T235040Z`.
- Pre-freeze HEAD: `90acaff28de9277e35a017f4b07a05003a852d1e`.
- [Freeze inventory](freeze-inventory.json): exact audited non-document input
  hashes, submodule revisions, feature gate results, production dependency
  inventory and separate emulator/production ELF content manifests.
- [Central execution record](../../implementation_record.log) and
  [technical-note section33](../approval-decision-technical-note.md#33-t420-task-4-freeze)
  record execution and bounded validation.
- Detailed local evidence:
  `target/t4.20-task4-freeze/20261105T235040Z/`.
  `validation-manifest.json` records pre-commit verification; `commit.json`
  records the actual documentation commit and post-commit verification.

The documentation commit alone is **not a reproducible committed source tree**
for the audited implementation. Hashes identify worktree bytes, not source
availability in that commit. Future publication must commit the implementation
and re-establish source/build provenance; no implementation commit is invented.
The inventory is a Task4 evidence record, not a P2.2 deployment-manifest schema.

## Authority and version separation

The [accepted direct-random V2 amendment](t4.14-pre-direct-random.md) governs
active consumers: purpose6 session proof, purpose7 reciprocal authorization325,
independently reconstructed session703, source final random32 MSK, independent
outgoing random32 handoff secret, protected delivery/acceptance and correlated
firmware completion. Historical purpose1/2, contribution, HKDF and application
HMAC records retain their original bytes and meanings; none is a V2 fallback.
No `MSG_KEY_REQ`, `MSG_VERIFY_REPORT` or new derived-key prerequisite exists.

Task12/fresh purpose3 persisted-state evidence remains **DEFERRED FUTURE WORK**.
It is not a present Task13/14 or milestone-readiness prerequisite. Reactivation
requires separate approval and an authenticated actual persisted-state source.
Firmware completion receipts are not attested persistence.

P0.9A1/B1/C1/D/E are accepted frozen contracts/tracking, not deployment approval.
One MA/Policy collateral bundle explicitly distinguishes exact-identity
`FixedReleaseV1` from `OrderedReleaseV1` with authenticated release mappings and
initial authorization. No SVN is inferred from measurement, GUEST_SVN, date,
collateral sequence or missing mapping. Accepted A2/B2/C2 formats remain
separate from their unqualified production providers and activation.
The [PA ledger](../../snp-production-readiness.md#selected-tracker-and-accountability)
is the selected P0.9E tracker; no public Issue or invented upstream approval is
required. No PA row is qualified by this freeze.

## Audit disposition

PASS below means the frozen seam and bounded evidence agree. It does not mean
the future executable or deployment condition has passed.

| Audit surface | Frozen/current disposition | Deferred executable or qualification owner |
|---|---|---|
| Shared platform independence | Typed SNP requests use logical handles, roles, report identities and explicit provider calls; no TD UUID, TDCS, ServTD or platform address is required by these seams | Task5 removes inherited TDX behavior from the separate legacy workflow |
| Host/peer/effect separation | Bounded correlated host codec carries intent, evidence, status and local control, never MSK/handoff secret; promoted peer APIs carry protected application records; platform services own effects | Tasks7-14, Phase4 and H5.1/H5.3/H5.5 |
| Composition ownership | `SnpProviderSet` owns boxed service providers, common unavailable verifier, disabled platform-key compatibility and system RNG; `services()` borrows them; hardware construction is closed | No host-selected verifier/RNG, plugin registry or implicit fallback |
| Tenant source | `HostPushedTenantEvidenceSource` is operation-local; common claims/provenance checks precede private `TenantEvidence` receipts; host-zero and guest-provided bindings are distinct | AAS1A-M must provide authentic common output; runtime lifecycle remains downstream |
| Replay/current state | Durable authenticated anchored load/atomic CAS and authoritative current-state traits are explicit; private receipts cannot be manufactured by decoding stored bytes | H5.4 production durability/rollback/restart; no absent-file => empty state |
| Separate MA evidence/collateral | `MaEvidenceProvider` and `SnpCollateralProvider` are independently selected; hardware report request is for calling MA, not arbitrary tenant | Task6/AAS1A-M/H5.1/H5.2 |
| Common verifier selection | Both compositions select `UnavailableSnpReportVerifier`, returning `ProviderUnavailable` without claims; neither selects TAV | AAS1A-M implements common V6 authentication; AAS1A owns base integration |
| Emulator V6 contract | Signed base plus exact220 supplement/P-384 signature and fixture provenance are frozen requirements, not current common-adapter execution | Task6 creates complete fixtures; AAS1A-M authenticates every byte |
| Existing emulator compatibility | Captured raw v5 report/DER chain and isolated SDK/key-only mock bridge remain; this is neither signed V6 supplement support nor production trust qualification | Task5 cleanup and Tasks6-14 activation |
| Production V6 contract | Fixture supplement/roots forbidden; raw V6 migration-data/ETCB overlap remains named; no partial/default claims | AAS1A-M failure tests and PA-009/H5.0 physical authority |
| Earliest production failure | Startup returns `HostControl(ProviderUnavailable)`, exit2, before MA report ioctl; selected common verifier would separately return unavailable | H5.1 host ABI; do not claim startup exercised a layout error |
| Policy/history | Verified fixed/ordered collateral and policy receipts remain distinct from decoded records; history64 preserves full Venice mitigation/ETCB and immutable initial MA identity | Tasks7-9/11, Phase4 and H5.2/H5.6 |
| Secret lifecycle | Operation-owned zeroizing/redacted MSK/handoff owners; system RNG is selected, deterministic test sources are not; explicit errors on entropy failure | Tasks10/11 and Phase4 own durable once-only generation, retry and cleanup; hardware RNG qualification remains open |
| Protected peer services | Typed inter-node versus local bindings, actual TH1, role/epoch/attempt/stage, deadlines and private I/O receipts are frozen; selected final peers remain unavailable | Tasks7/8/10/13 and R4.2-R4.6; H5.5 production transport |
| Installer/binding effects | Validated borrowed requests, role-correct firmware REPORT_ID, exact key32/history64 and correlated no/partial/unknown effects; unavailable implementations return errors | Task11 stateful emulator; H5.3/H5.5 actual effects/reconciliation |
| Local planned/recovery split | Independent local protected session and outgoing secret versus incoming-only no-secret recovery; exact tenant set, history and authoritative no-old-binding shutdown obligations | R4.1-R4.7; H5.5/H5.7; no current local two-process runtime claim |
| Features/dependencies/images | Four top-level build selections and independent capability guards; no production fixture/TAV graph or named fixture/synthetic-root ELF hits in accepted inventory | P2.2 atomic deployment contents and H5.7 actual hardware; real AMD ARK is not a synthetic root |

The actual interfaces are in [composition](../../../src/pal/src/composition.rs),
[traits](../../../src/pal/src/traits.rs), [types](../../../src/pal/src/types.rs),
[common reports](../../../src/pal/src/snp_report.rs),
[tenant source](../../../src/pal/src/snp/tenant_source.rs),
[replay](../../../src/pal/src/tenant_replay.rs),
[host control](../../../src/pal/src/snp/host_control.rs),
[policy](../../../src/pal/src/snp/ma_policy.rs),
[ordered collateral](../../../src/pal/src/snp/ordered_collateral.rs),
[history](../../../src/pal/src/snp/migration_data.rs),
[direct authorization](../../../src/pal/src/snp/direct_authorization.rs),
[direct key](../../../src/pal/src/snp/direct_key.rs),
[direct exchange](../../../src/pal/src/snp/direct_exchange.rs),
[peer channel](../../../src/pal/src/snp/peer_channel.rs),
[installation](../../../src/pal/src/snp/migration_install.rs),
[binding manager](../../../src/pal/src/snp/binding_manager.rs) and
[local handoff](../../../src/pal/src/snp/local_handoff.rs).
Legacy `AttestationProvider`, combined blobs and key-only
`MigrationKeyInstaller` are explicitly not these frozen final SNP seams.

## Feature, dependency and image record

The [feature diagram/matrix](feature-selection-diagram.md) records TDX/no_std,
AzCVMEmu/std, SnpEmuAzure/std and SnpHardware/std plus independent Underhill/PAL
capabilities. Production builds disable defaults explicitly. The committed
inventory contains the complete 57 accepted feature/API gate results and
separate resolved normal/build dependency inventories: emulator237,
production187. It retains each original manifest's limits and source hashes.

| Accepted artifact, Rust1.90 native release | SHA256 | Bytes |
|---|---|---|
| SnpEmuAzure ELF | `fcb1710527bdc4f9ae0be8c236a22840e7fa3f8643244cce0d82b1e3e57633c1` | 7183264 |
| SnpHardware ELF | `ba5cc3594058d4c42921dc6ce29751abc36cf2714f0b9a0c9e587694aae767ea` | 375648 |

These T4.19 artifacts are reused evidence, not rebuilt T4.20 outputs. Production
linker elimination of an adapter does not prove execution or qualification.
The separate ELF inventories do not include kernel/initramfs/deployment files.
P2.2 owns their schema, atomic bundle, provenance and content qualification.
No new parser, protocol, hardware, deployment or hosted-CI result is claimed.

## Consumer handoff and deferred verifier tests

The [consumer-readiness matrix](consumer-readiness-matrix.md) is part of this
freeze. It names each later consumer, producer seam, required admission/effect
checks and unavailable/deferred owner. T4.17-T4.19 common-verifier obligations
remain mandatory at AAS1A-M before Task7, including:

1. Authenticated positive signed V6 MA, host-zero tenant and guest-bound tenant
   cases in the same common adapter, with exact kind/VMPL/REPORT_DATA/history.
2. Tampered/missing/substituted base, supplement, supplement signature,
   collateral, root, profile and provenance rejection; no report-self-echo or
   fixture production fallback.
3. Explicit production fixture rejection and named unresolved raw V6 layout
   errors without partial/default claims, and executable both-role V2 purpose6/7
   handoffs rather than old purpose1/2 reinterpretation.

The preserved `deferred-verifier-tests.json` contains the exact inherited rows;
this list does not close them. Current conformance doubles and unavailable
composition tests are not cryptographic or local-runtime evidence.

## Documentation reconciliation and validation

The audit corrected active Task5/AAS1A-M and related handoff instructions that
still required bilateral contributions, purpose1/2, authorization421 or HMAC.
The existing accepted V2 amendment is the authority; no frozen bytes or
protocol semantics changed. Original historical implementation records and
technical-note sections remain byte-preserved.

All four diagrams now use actual owned/borrowed services and operation-local
tenant ownership, not `Arc` fields, invented stores/verifier names or
operational target-only transport APIs. Current fail-closed paths and future
sequences are labeled separately.

Fresh T4.20 checks verify audited input/evidence hashes, accepted image bytes,
feature/dependency data, source symbols and consumer coverage, relative links,
diagram structure, historical prefixes, the exact37-step order, documentation
commit scope and post-commit content. Existing T4.19 26 command gates,
32 firmware builds and14 EMU scenarios are inherited verified evidence, **not
fresh executions**. Documentation-only T4.20 does not rerun runtime tests.
No broader acceptance, production readiness, Task12 reactivation, P2.1/P2.2
execution, implementation commit or push is implied.
