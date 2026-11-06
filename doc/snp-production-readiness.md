# SNP production-readiness index

Status: DONE - ACCEPTED AND FROZEN REPOSITORY-LEDGER TRACKING SCOPE.
Accepted on 2026-11-03T17:40:06Z; conditions: None.
Freeze identifier: `P0.9E-ReadinessLedgerV1-2026-11-03`.
The tracking mechanism/record schema is frozen; current requirement statuses,
evidence and ownership remain maintained through dated log entries, not frozen
against future updates. Publication and production qualification remain open.

This is the P0.9E index required by the
[canonical execution plan](q162-revised-master-execution-plan.md#p09e-production-readiness-tracking).
Execution and acceptance remain append-only in
[implementation_record.log](implementation_record.log).

Current secret requirements are superseded by
[T4.14-PRE direct-random V2](snp/task4/t4.14-pre-direct-random.md).
Source random32 delivery/acceptance and independent outgoing random32 handoff
replace contributions/HKDF/application HMAC, without relaxing any production
qualification. Relevant amendment regressions and full local CI command parity
pass, including all 14 EMU scenarios with CI's Rust 1.88.0 toolchain.
T4.14-PRE was accepted and frozen within its bounded scope and exclusions at
2026-11-05T02:22:07.036Z; conditions: None; freeze identifier
`T4.14-PRE-DirectRandomV2-2026-11-05`. Separately authorized advisory
and workspace strict-Clippy remediation pass without waivers or lint suppression.
No row is qualified by that maintenance or bounded acceptance.
T4.14 secret services passed bounded validation and were separately accepted
within their documented bounded scope at 2026-11-05T03:02:37.597Z.
No additional conditions were specified; existing exclusions remain in force.
Acceptance is tracked centrally, not supplied by PRE acceptance. No production
row, effectful runtime or hardware qualification is implied.
T4.15 explicit provider sets passed bounded validation and were accepted within
their documented bounded scope and exclusions at 2026-11-05T13:51:09.902Z.
No additional conditions were specified. Both Linux SNP sets select existing
`SystemRandomSource`; deterministic scripting remains unit-test-only.
Production provider/AAS/layout unavailability is explicit. Feature/image
isolation remains T4.16; runtime activation and production qualification remain
downstream. Separately authorized pin-utils dependency remediation removes
the new advisory without waivers; the final lockfile passed local CI.
No row is qualified by this composition work or maintenance.
T4.16 feature selection passed bounded validation at
2026-11-05T16:05:02.185Z and was accepted within its documented bounded scope
and exclusions at 2026-11-05T16:11:10.268Z. No additional conditions were
specified; existing exclusions remain in force.
Shared SNP/std and runtime-only Underhill gates are independent of fixtures;
the production graph excludes TDX/emulator providers and rejects mixed
compositions. TAV is removed from the workspace graph; local AAS is the sole
selected SNP backend. Its legacy captured-fixture path is not a live Version 6
adapter. Production startup explicitly refuses unavailable services (exit2).
Forty feature/dependency checks, PAL/SNP/library and strict checks, 32 firmware
builds, six tools, 14 EMU scenarios and rebuilt musl Stage A/B pass.
Prior consumer/import regressions were repaired and failed stages rerun;
the original eight generated fixtures were restored byte-for-byte.
Evidence: `target/t4.16-feature-selection/20261105T151207Z/`.
No production AAS/layout/provider activation, RNG/hardware qualification,
readiness-row qualification or GitHub-hosted CI is implied.
T4.17 interface/provider conformance was authorized at
2026-11-05T16:22:33.174Z and passed bounded validation at
2026-11-05T17:21:34.964Z. The user accepted T4.17 within its documented bounded
scope and exclusions at 2026-11-05T17:27:38.397Z. No additional conditions
were specified; existing exclusions remain in force.
Fifty-five compile/dependency/public-API checks, PAL and SNP/library suites,
independent references, strict checks, 32 firmware builds, six tools,
14 EMU scenarios and rebuilt musl Stage A/B pass. The external fixture
consumer exposed a missing explicit `zeroize/alloc` declaration; it was
repaired without a lockfile or package-resolution change.
Common-claims policy coverage is the unchanged identity projection, not
full common-claims admission or caller activation. The actual AAS Version 6
adapter and composed-claims qualification remain AAS1A-M obligations.
Evidence: `target/t4.17-interface-conformance/20261105T162233Z/`;
the [coverage register](snp/approval-decision-technical-note.md#26-t417-interface-and-provider-conformance)
distinguishes real crypto, controlled interfaces and downstream qualification.
The eight generated fixtures were restored byte-for-byte. No readiness row
is qualified. The current T4.18 disposition is recorded below.
Execution/acceptance is recorded centrally;
no commit or push.

Separate SDK maintenance passed validation at `2026-11-05T18:01:29.016Z`.
MigTD now pins SDK/azure-tpm 0.2.0 at
`8774be30f452060c56372d34ccbe34c3d3f3c577`, with explicit `native,verify`
selection preserving the former backend. Full local regression, native
SDK/TPM tests and strict checks pass. The registered-library rerun uses
`RUST_TEST_THREADS=1` because of pre-existing cross-module global logging
interference; the parallel failure and existing ignored tests are retained,
not waived or represented as passes. See
[technical-note section 28](snp/approval-decision-technical-note.md#28-sdk-8774be3-update-and-regression).
No readiness row or production adapter is qualified.

### T4.18 caller integration

Authorized at `2026-11-05T18:20:16.530Z`; bounded validation recorded at
`2026-11-05T18:58:22.061Z`. The user accepted completion within its documented
bounded scope and exclusions at `2026-11-05T19:04:48.267Z`.
One process-owned emulator root now supplies selected typed MA evidence and
collateral to WFR/SPDM, with separate named legacy SDK and key-only mock
compatibility services. These services do not produce common V6 claims or
activate V2 installation, replay, binding or handoff. The hardware root selects
the existing Linux MA acquisition adapter but does not qualify or exercise it;
startup reports the unavailable selected host-control boundary and exits 2
before accepting an operation. Collateral, common V6/AAS/layout and production
transport/state/effect gates remain unavailable, with no fixture/TAV fallback.

The 57 compile/dependency/public-API checks, PAL and SNP/library suites,
independent references, workspace/scoped strict checks, 32 firmware builds,
six tools, 14 EMU scenarios (28 zero exits) and rebuilt musl Stage A/B pass.
The required registered suites use the documented serial invocation. Existing
legacy SNP lint warnings and an extra vendor-wide formatter discrepancy are
retained, not reported as repaired; the actual repository/CI formatter passes.
The first binary entry-root regression was fixed and its failed log preserved.
All eight generated fixtures were restored, and prior accepted evidence,
lockfile, frozen corpora and phase order remain unchanged.

Evidence: `target/t4.18-caller-integration/20261105T182016Z/`;
see [technical-note section 29](snp/approval-decision-technical-note.md#29-t418-caller-integration).
No readiness row, hardware/RNG/deployment, AAS or hosted-CI qualification is
claimed. Acceptance is recorded in
[technical-note section 30](snp/approval-decision-technical-note.md#30-t418-bounded-completion-acceptance)
and the central log; existing exclusions remain unchanged.
T4.19 was separately authorized; its current bounded disposition is below.
No broader acceptance, commit or push.

### T4.19 Task 4 regression

Authorized at `2026-11-05T19:45:40.638Z`; bounded validation recorded at
`2026-11-05T20:12:53.102Z`. The user accepted completion within its documented
bounded scope and exclusions at `2026-11-05T23:49:26.373Z`.
All 26 final local command gates pass: PAL/interface and serial registered
libraries, 57 feature/API checks, independent references, strict checks,
32 firmware builds, six tools, 14 EMU scenarios and rebuilt musl Stage A/B.
Both inter-node roles and local-handoff directions fail explicitly at the
unavailable selected peer seam in both composition tests; no local two-process
handoff execution is claimed.

Explicit emulator and production release builds have separate provisional ELF
inventories. Named captured assets/synthetic roots/forbidden symbols are absent
from production, and its selected host boundary refuses startup with exit 2.
This does not qualify hardware acquisition, V6 authentication or deployment
contents; P2.2 still owns versioned/qualified bundles. The real public AMD ARK
is not classified as a synthetic fixture root.

Evidence: `target/t4.19-task4-regression/20261105T194540Z/`;
see [technical-note section 31](snp/approval-decision-technical-note.md#31-t419-task-4-regression)
for exact coverage, tool controls, repaired attempts and deferred AAS1A-M tests.
Existing serial-test, ignored-test and legacy lint limitations remain explicit.
Eight generated fixtures were restored and prior accepted evidence is preserved.
No readiness row, production transport/state/effect, hardware/RNG/deployment,
full Task 3 or hosted-CI qualification is claimed. Bounded acceptance is recorded
in [technical-note section 32](snp/approval-decision-technical-note.md#32-t419-bounded-completion-acceptance)
and the central log; existing exclusions remain unchanged.
T4.20 is DONE - ACCEPTED AND FROZEN within its documented bounded
documentation-freeze scope and exclusions at `2026-11-06T00:32:02.025Z`;
conditions: None. See the
[bounded acceptance record](snp/approval-decision-technical-note.md#34-t420-bounded-completion-acceptance),
[audit/freeze](snp/task4/task4-freeze.md),
[consumer matrix](snp/task4/consumer-readiness-matrix.md) and
[source/feature/dependency/image inventory](snp/task4/freeze-inventory.json).
The user authorized a documentation-only commit, not an implementation commit
or push. Exact audited worktree inputs are hash-identified; the documentation
commit alone cannot reproduce them. Accepted T4.19 regression/ELF evidence is
preserved and reused, not relabeled as fresh execution. No PA row, production
service/layout/RNG/deployment/hardware qualification, broader acceptance,
Task12 reactivation or P2.1/P2.2 start is claimed. The Phase1 gate is satisfied
at the documented interface level only. P2.1 was separately authorized at
`2026-11-06T00:34:35.144Z`; its naming-only execution is recorded centrally.
P2.2 still requires P2.1 and separate authorization. No new commit or push is
made for this acceptance; historical evidence/inventory snapshots are unchanged.

## Status and evidence rules

P2.1 is DONE - ACCEPTED AND FROZEN within its documented bounded naming-only
scope and exclusions at `2026-11-06T00:47:34.984Z`; conditions: None.
The separate commit is
`1dbb3e6bf8e9f3666d9a5ead2dbb6e66b6d15481`; prior implementation and acceptance
changes remain uncommitted. See the [scenario guide](snp-migration-scenarios.md)
and [technical-note section35](snp/approval-decision-technical-note.md#35-p21-descriptive-migration-scenario-terminology).
Eight naming tests pass in each working/index snapshot and four sequential
canonical/compatibility runs pass on the same accepted frozen ELF/controller
(12 zero process exits). This is not common V6/V2 or local-handoff/production
qualification. No PA row advances. Explicit acceptance is recorded in
[technical-note section36](snp/approval-decision-technical-note.md#36-p21-bounded-completion-acceptance).
At P2.1 acceptance, P2.2 was READY for separate authorization, NOT STARTED.
That acceptance reran no tests/builds and made no new commit or push.
P2.2 is DONE - ACCEPTED AND FROZEN within its documented scope and exclusions at
`2026-11-06T15:39:00.609Z`, following implementation under
separate authorization at
`2026-11-06T00:49:32.416Z`. The user subsequently authorized the separate accepted
prerequisite baseline commit `5d6a4ad302d2c5b17a8a80d11286657559ad126d`;
the external consumer conversion is `700e22aae1bcf09aff7d591cffc5ea6a39b4169c`.
The [bundle contract](snp-bundles.md) now passes both fresh-checkout builds,
24 targeted unit tests and19 real-bundle controls at source commit
`bb1a2fccb2e42062378d4ef454718b6a1b5eadd5`. The first fresh build exposed an
ignored corpus dependency; the existing137-entry PUBLIC TEST ONLY P0.10 corpus
was independently verified and tracked without changing its bytes.
Both actual VMs also complete the legacy workflow using the fresh emulator
bundle. Actual old/new VM parity and the explicitly approved obsolete assertion
change do not grant migration qualification. Nested source was moved intact
to its approved session archive. See
[technical-note section37](snp/approval-decision-technical-note.md#37-p22-atomic-artifact-producer-and-bundle-consumer).
Explicit bounded acceptance and Phase2 closure are recorded in
[technical-note section38](snp/approval-decision-technical-note.md#38-p22-bounded-acceptance-and-phase2-closure).
Remaining relocation changes are committed in the harness as
`4a10dafd9125457616d09589f618cef1d3ff9e68` and MigTD as
`af17a246a2ec6117e0872b63e7d750e7dbe71165`. No PA row or production
qualification advances. Task5 remains NOT STARTED pending separate authorization;
no push is authorized. Historical validation/commit snapshots remain unchanged.

Statuses are `DESIGN_REQUIRED`, `EXTERNAL_DEPENDENCY`, `READY`, `IN_PROGRESS`,
`IMPLEMENTED`, `QUALIFIED`, or `BLOCKED`. Implementation/model tests are not
qualification. Only `QUALIFIED` with the required approval, deployment and
acceptance evidence permits the corresponding production claim.

### Selected tracker and accountability

On 2026-11-03 the user approved this repository ledger, with stable per-PA
anchors, as the tracking mechanism and confirmed
[@mvasantarao](https://github.com/mvasantarao) as the accountable tracking owner
for **PA-001 through PA-011**. This supersedes the earlier issue-only blocker.
GitHub Issues remain disabled; no public issue or repository setting change is
required. A linked GitHub Issue, Azure DevOps work item or other explicitly
approved durable tracker is also acceptable, but no external work-item links
have been supplied. The ledger anchors below are the selected tracker links,
not placeholders for invented external work items.

The tracking owner maintains status, follows up dependencies and obtains the
required evidence and technical approvals. External technical authorities
listed below are required counterpart roles, not assignments or approvals
made on their behalf. Their named contacts and exact private target repository
URLs remain pending where not supplied.

Tracking coverage and requirement completion are separate:

- A tracked row has a stable record, confirmed accountable tracking owner,
  status, target/dependencies, gate/version impact, explicit PR/commit state
  and evidence/qualification disposition. Missing evidence is recorded, not
  hidden by an empty cell or treated as success.
- A requirement is complete only after its linked implementation, tests and
  required authority acceptance justify `QUALIFIED`. No row is qualified now.
- Repository publication is **pending**: T4.20 authorizes a local documentation
  freeze commit only, with the exact result in its `commit.json` evidence.
  The audited implementation remains uncommitted. No PR or push is authorized
  or claimed; relative ledger/source links are not claims that the current
  implementation is published upstream. Future implementation publication
  must record its actual source commit/PR and re-establish provenance.
- The [central log](implementation_record.log) is the append-only execution
  and acceptance authority. Preserve stable IDs/anchors; record dated status,
  ownership, dependency, evidence and qualification changes there and update
  the current ledger. The owner must carry both records into repository
  history; the ledger does not provide external assignment notifications.
- Raw `target/` evidence is local/ignored. Preserve commands, freeze IDs,
  manifest hashes and dispositions centrally; publish a sanitized durable
  evidence bundle or approved private link before any qualification relying
  on those logs. Do not upload keys, tenant reports or private work-item data.

### Current requirement index

`PR: none; commit: none` below describes these P0.9 changes, not the absence of
all prior repository history. Evidence-register links separate the accepted
contract/model results from the missing production qualification.

| ID | Requirement and rationale | Status | Accountable tracking owner | Target repository / upstream | Blocking milestone | Interface/version impact | Durable tracker | PR / commit links | Test evidence / qualification |
|---|---|---|---|---|---|---|---|---|---|
| PA-001 | Approved custom collateral publication/deployment; signature ownership must be authoritative | IN_PROGRESS | @mvasantarao | MigTD + Microsoft policy publishing authority; exact external repository pending | H5.0 review, H5.2 | Custom signed SNP v1; no CoRIM requirement | [PA-001](#pa-001) | PR: none; commit: none; publication pending | [E-02](#e-02), [E-03](#e-03); NOT QUALIFIED |
| PA-002 | Authenticated identity-to-combined-SVN mapping; host, guest SVN and ETCB cannot supply release rank | IN_PROGRESS | @mvasantarao | MigTD + Microsoft release/policy publishing upstream; exact external repository pending | H5.2/H5.6 | Immutable signed `MaPolicyTcbMapping`; frozen identity unchanged | [PA-002](#pa-002) | PR: none; commit: none; publication pending | [E-02](#e-02); NOT QUALIFIED |
| PA-003 | Retain authentic original MA authorization; current release approval cannot erase history | IN_PROGRESS | @mvasantarao | MigTD + Microsoft policy/BASE integration; exact external repositories pending | R4.3 cross release, H5.6 | Signed 416-byte `InitialMaAuthorizationV1` and trusted history/store providers | [PA-003](#pa-003) | PR: none; commit: none; publication pending | [E-02](#e-02), [E-03](#e-03); NOT QUALIFIED |
| PA-004 | Revocation and key/root rotation must preserve or explicitly reject historical authority | IN_PROGRESS | @mvasantarao | MigTD + Microsoft PKI/policy upstream; exact external repository pending | H5.2/H5.6 | Purpose/epoch registry, terminal release revocation, non-resetting sequence | [PA-004](#pa-004) | PR: none; commit: none; publication pending | [E-02](#e-02); NOT QUALIFIED |
| PA-005 | Provisioned roots and signer purposes must exclude fixture authority | EXTERNAL_DEPENDENCY | @mvasantarao | MigTD + Microsoft PKI/deployment upstream; exact external repository pending | C1/C2 production composition, H5.2 | `MaPolicySignerVerifierV1`, `CollateralKeyProviderV1`; no invented root/OID | [PA-005](#pa-005) | PR: none; commit: none; publication pending | [E-01](#e-01), [E-02](#e-02); production PKI evidence absent; NOT QUALIFIED |
| PA-006 | Composite verification must authenticate platform, MA/Policy, tenant and history together | EXTERNAL_DEPENDENCY | @mvasantarao | MigTD + Azure/azure-guest-attestation-sdk + MAA/relying-party integration | P0.12B/AAS1B/H5.6 | Composite evidence/common authenticated claim and approval adapters | [PA-006](#pa-006) | PR: none; commit: none; publication pending | [E-03](#e-03) handoff only; composite qualification absent; NOT QUALIFIED |
| PA-007 | BASE tenant sidecar must survive migration/rebind without loss or rollback | EXTERNAL_DEPENDENCY | @mvasantarao | MigTD + BASE/OHCL Linux; exact kernel checkout/revision pending | Task 8, H5.1/H5.3/H5.5; Task 12 evidence exchange deferred | Tenant delivery/history/replay and durable host-control interfaces | [PA-007](#pa-007) | PR: none; commit: none; publication pending | [E-03](#e-03) handoff only; real persistence evidence absent; NOT QUALIFIED |
| PA-008 | Real hardware installation/rebind must preserve firmware effects and recovery identity | EXTERNAL_DEPENDENCY | @mvasantarao | MigTD + AMD/platform + BASE/OHCL; exact external repositories pending | H5.0-H5.7 | Hardware command/adapters; no readiness from approval alone | [PA-008](#pa-008) | PR: none; commit: none; publication pending | Hardware acceptance absent; [E-03](#e-03) boundary only; NOT QUALIFIED |
| PA-009 | Resolve Version 6 ETCB/MIGRATION_DATA field and valid-bit conflicts before production parsing | BLOCKED | @mvasantarao | AMD firmware/ARG specification upstream + AAS parser; authoritative document/URL pending | H5.0 and dependent production report paths | Authoritative layout/selector/erratum/version; no fixture reinterpretation | [PA-009](#pa-009) | PR: none; commit: none; publication pending | AMD resolution/production vectors absent; NOT QUALIFIED |
| PA-010 | Approved closed policy schema/canonicalization must reject ambiguous or unauthorized policy | EXTERNAL_DEPENDENCY | @mvasantarao | MigTD + Microsoft policy authority; exact external repository pending | C1 production composition, Tasks 7/9 | `LmPolicyVerifierV1`; frozen semantic digest recipe unchanged | [PA-010](#pa-010) | PR: none; commit: none; publication pending | [E-01](#e-01) model only; approved schema vectors absent; NOT QUALIFIED |
| PA-011 | Trusted time and anchored durable state must prevent rollback and ambiguous success | EXTERNAL_DEPENDENCY | @mvasantarao | MigTD + deployment trusted-state/BASE upstream; exact external repositories pending | C1/C2 deployment, Tasks 7/9, H5.2 | Time, fixed/ordered durable revision-CAS provider contracts | [PA-011](#pa-011) | PR: none; commit: none; publication pending | [E-01](#e-01), [E-02](#e-02) models only; NOT QUALIFIED |

## Requirement records

Dependencies below identify readiness evidence/providers that must be followed
up together. They do not reorder the canonical 37-step sequence or replace
the blocking milestones in the index. The confirmed owner for every record
is the tracking owner in its row; external technical assignment is unconfirmed.

### PA-001

**Publication and deployment authority.** Microsoft policy publishing
authority and MigTD maintainers must approve actual signing/publication and
relying-party use. The custom v1 contract is selected, not organizationally
approved for deployment. Follow up [PA-005](#pa-005) authority/provisioning and
[PA-010](#pa-010) policy interoperability.

Evidence: [E-02](#e-02) defines/test-verifies signature coverage, bounds and
mapping lifecycle; [E-03](#e-03) defines consumers. Still required: approval
record, authenticated publication/acquisition, production signed
interoperability vectors and relying-party acceptance. Qualification: pending.

### PA-002

**Release ranking.** Microsoft release authority must publish exact-identity
mappings; MigTD verifies them rather than use host metadata, `GUEST_SVN`,
platform ETCB or allowlist sequence. Dependencies:
[PA-005](#pa-005) keys, [PA-010](#pa-010) authenticated publisher/floor policy
and [PA-011](#pa-011) validity/rollback state.

Evidence: [E-02](#e-02) includes immutable mapping/conflict, missing mapping,
floor and inter-node/planned-handoff upgrade/downgrade tests. Still required:
real approved release inventory, signed publication and production lifecycle
and consumer integration tests. Qualification: pending.

### PA-003

**Initial-MA authorization.** Microsoft policy/history authority and BASE
integration must retain authenticated original evidence and preserve
tenant/initial-MA/original-policy/SVN bindings through renewal and migration.
Dependencies: [PA-002](#pa-002) mapping, [PA-004](#pa-004) historical key rules,
[PA-009](#pa-009) physical history layout and [PA-011](#pa-011) retention/state.

Evidence: [E-02](#e-02) verifies exact signed records, tenant/history binding,
renewal immutability, rollback and revocation using models. Still required:
actual original-evidence appraisal/signing authority, authorized durable
retention/retrieval, restart and migration/handoff continuity. Qualification:
pending; a current approval is not proof of original authorization.

### PA-004

**Revocation and rotation.** Microsoft PKI/policy authority must administer
leaf/intermediate/root authorization, current revocation freshness and
historical verification/renewal. Dependencies: [PA-005](#pa-005) provisioned
authority and [PA-011](#pa-011) trusted time/anchored epochs and sequence.

Evidence: [E-02](#e-02) covers model registry key/epoch transitions, purpose
separation, terminal release revocation and no sequence reset. Still required:
real certificate-chain and revocation-service tests, authenticated root-update
administration, expired/revoked historical signing keys and recovery.
Qualification: pending; registry fixtures do not qualify certificate rotation.

### PA-005

**Production PKI.** Microsoft PKI/deployment owners must supply approved roots,
fixed-profile signer EKU, ordered key purposes, bounded chain/key constraints
and authenticated update administration. No Microsoft root, OID or private
upstream assignment has been invented.

Evidence: [E-01](#e-01)/[E-02](#e-02) use explicit test-only keys and trusted
adapter boundaries; defaults fail closed. Still required: provisioned
production trust configuration, authorized chain/key/update vectors and proof
that fixture roots/purposes cannot authorize production. Qualification: pending.

### PA-006

**Composite relying-party verification.** AAS/MAA integration owners and
MigTD must agree actual composite packaging/acquisition and verification,
including history, rather than treat a policy receipt as a complete report.
Dependencies: [PA-002](#pa-002), [PA-003](#pa-003), [PA-004](#pa-004),
[PA-005](#pa-005), [PA-009](#pa-009) and [PA-010](#pa-010).

Evidence: [E-03](#e-03) records P0.12B/H5.6 handoff obligations, not composite
qualification. Still required: approved composite contract, accepted/pinned
AAS implementation, real report/chain/endorsement/history verification,
freshness/substitution vectors and relying-party acceptance. Qualification:
pending; no production composite result claimed.

### PA-007

**Tenant sidecar persistence.** BASE/OHCL Linux and MigTD integration owners
must preserve authenticated delivery, handle-to-GCTX correlation, tenant
identity/history and replay state across migration/rebind. Dependencies:
[PA-009](#pa-009) authentic production history and [PA-011](#pa-011)
crash-safe anchored state; exact external kernel repository remains pending.

Evidence: [E-03](#e-03) assigns consumers; local delivery/replay contracts are
not kernel implementation or persistence evidence. Still required:
authenticated acquisition, cache lifecycle, rollback/crash/restart and
migration/rebind continuity against actual BASE integration. Qualification:
pending.

#### PA-007 T4.12 OHCL/BASE host-control integration actions

Added 2026-11-04. These actions track production dependencies of
[T4.12](q162-revised-master-execution-plan.md#t412-host-control-and-ma-binding-interfaces);
they do not start or accept T4.12. The accountable tracking owner remains the
PA-007 owner. BASE, OHCL kernel and OpenHCL/MigTD userspace authorities must
approve their respective interfaces; named external contacts remain pending.
All actions are unqualified, with PR: none; commit: none; implementation and
production acceptance evidence pending.

`[OHCL]` identifies the selected integration architecture, not an
AMD-prescribed Linux API. Host-control describes logical requests/status, not
a kernel bypass. If the confirmed production transport uses GHCB/VMGEXIT,
the guest-side kernel/lower-layer implementation must provide that path.
Existing emulator TCP behavior is not evidence of production transport support.
Do not invent an ioctl, GHCB operation number or notification mechanism.
Inspect and reuse existing support first; document exact missing capabilities
before proposing kernel or BASE changes.

| Action | Required work / closure evidence | Target and dependency | Current disposition |
|---|---|---|---|
| PA-007-OHCL-01 [OHCL] | Pin actual OHCL-Linux-Kernel, OpenHCL/userspace and BASE integration revisions/configurations. Inspect host-control support and document the end-to-end request, response and notification path, including whether and where GHCB/VMGEXIT is used. Identify existing APIs and exact gaps; obtain counterpart technical acceptance. | BASE/OHCL/OpenHCL integration; T4.12 contract and H5.1 | EXTERNAL_DEPENDENCY; kernel checkout, confirmed transport/API and external acceptance absent |
| PA-007-OHCL-02 [OHCL] | Agree versioned userspace/kernel and BASE transport contracts for prepare, cancel, abort, query and status. Specify framing, bounded lengths, buffer ownership, delivery/notification, access control, concurrency, timeout and teardown behavior. Reuse existing APIs or implement only confirmed gaps; preserve accepted logical records and coordinate opcode allocation. | OHCL kernel, BASE endpoint and userspace adapter; OHCL-01 and T4.12 | DESIGN_REQUIRED; no new UAPI or GHCB encoding approved |
| PA-007-OHCL-03 [OHCL] | For the selected transport, validate/copy untrusted shared-buffer contents safely, check sizes and reserved fields, prevent mutation races and retain request/response correlation. Keep MSKs and handoff secrets out of host-control payloads. Kernel transport delivery must not imply MA authorization or firmware success. | OHCL kernel/lower-layer transport, BASE and MA parser; OHCL-01/02 | DESIGN_REQUIRED; implementation and boundary-test evidence pending |
| PA-007-OHCL-04 [OHCL] | Qualify BASE-owned target routing and handle lifetime, stale/wrong-target rejection, actual tenant-report acquisition and delivery/cache/reference association. Both prepare requests must supply the same complete source evidence before purpose 1; keep purpose-2 authorization distinct. Cross-link target resolution with PA-008 rather than exposing physical addresses in the MA logical contract. | BASE routing/report source, OHCL adapters and MA; P0.5/P0.6, T4.9 and PA-008-OHCL-02 | EXTERNAL_DEPENDENCY; actual acquisition/routing and production evidence absent |
| PA-007-OHCL-05 [OHCL] | Preserve one operation context across retries and prepare/cancel/abort/query/status. Define disconnect/restart and terminal-query behavior without repeating effects or trusting host-reported completion. Restore authenticated replay metadata/outcomes or fail closed; host/kernel buffers alone are not rollback protection. | BASE and MA lifecycle/state providers; P0.6, P0.8, PA-011 and OHCL-02 | DESIGN_REQUIRED; durable restart and idempotent-delivery qualification pending |
| PA-007-OHCL-06 [OHCL] | Connect protected V2 key-delivery acceptance, MA-authored firmware outcomes and P0.11 local binding operations to the approved control lifecycle. Keep inter-node SPDM, local protected handoff, host control and firmware effects separate. Use the T4.14-PRE replacement, not historical HMAC/persisted-state admission; propagate rejected/partial/unknown effects without blind retry or unsolicited success. | MigTD/OpenHCL, BASE and binding/installer adapters; T4.11-T4.14-PRE, P0.11 and PA-008 | DESIGN_REQUIRED; final composition and binding APIs pending; fresh purpose-3 exchange remains deferred |
| PA-007-OHCL-07 [OHCL] | Publish end-to-end kernel/userspace/BASE tests covering malformed/oversized frames, shared-buffer mutation, unauthorized callers, wrong/stale handles, duplicates, reordered/lost responses, cancel/abort races, disconnect/restart, terminal queries and firmware rejection/uncertain effects. Record exact API versions, actual PR/commit links, sanitized durable evidence and counterpart acceptance. | BASE/OHCL/MigTD integration; OHCL-01 through OHCL-06, PA-008/PA-011, H5.1/H5.3/H5.5/H5.7 as applicable | EXTERNAL_DEPENDENCY; no production qualification evidence |

T4.12 implementation update, 2026-11-04 (bounded conformance accepted at
17:41:29Z; production gates retained): bounded SNP host-frame codecs,
operation-local lifecycle, now-amended protected acceptance/completion scheduling and
binding-provider interfaces now exist in MigTD. They do not implement the
production BASE/GHCB transport or close any action above. In particular,
PA-007-OHCL-05 and [PA-011](#pa-011) must qualify both the existing P0.6
verified replay journal and the new pre-proof
`HostControlContextAuthorityV1`: an operation can lose its live session before
purpose1 has produced a replay binding. Its anchored reservation must survive
restart and prevent that empty journal from permitting a replacement session.
The supplied production context/transport/binding services are unavailable,
not volatile storage or success-only fallbacks.

Closure requires the supported T4.12 workflows to work through the actual
production transport and effect adapters, not merely an API inventory or
successful emulator tests. These actions supplement [PA-008](#pa-008)
installation/rebinding work and [PA-011](#pa-011) trusted durable state; they
neither duplicate those approvals nor establish firmware effects by host
acknowledgement.

#### PA-007 T4.13 peer-channel qualification actions

Added 2026-11-04 for approved contract
`T4.13-PurposeSeparatedPeerBoundaryV1`. Accountable tracking owner remains
PA-007; external counterpart acceptance, PRs/commits and production qualification
are pending. Bounded T4.13 conformance was accepted at 2026-11-04T18:25:34Z;
no action below is qualified by that acceptance.
`[OHCL]` denotes selected integration dependencies, not an
AMD-mandated kernel API. Kernel changes are conditional on inspection of actual
revisions/API gaps; T4.13 does not establish that a new kernel API is needed.

| Action | Required work / closure evidence | Current disposition |
|---|---|---|
| PA-007-PEER-01 [OHCL] | Pin actual BASE/OHCL kernel/OpenHCL userspace and peer-routing revisions. Confirm existing network/channel APIs, access control, route/handle lifetime, buffer ownership and whether any lower layer uses GHCB/VMGEXIT. Reuse existing support; specify exact missing kernel/userspace capabilities only after inspection. Keep host control, guest firmware messages and encrypted peer delivery separate. | EXTERNAL_DEPENDENCY; APIs/revisions and counterpart acceptance pending |
| PA-007-PEER-02 [USERSPACE] | Implement a real SPDM backend returning actual engine session ID/TH1 and full operation correlation. Protect bootstrap and application records with confidentiality/integrity; reject changed/replaced engine sessions. Implement bounded framing/allocation, deadline-aware async or blocking I/O, cancellation/unblocking, teardown and secret-copy/queue erasure. No plaintext fallback or auto-reconnect after loss. | DESIGN_REQUIRED; unavailable factory/test backends are not production SPDM |
| PA-007-PEER-03 [USERSPACE] | Freeze/review actual planned-local peer framing and metadata/secret scheduling without borrowing inter-node opcodes or plaintext host controls. Preserve complete authenticated metadata/replay transfer, same-snapshot acknowledgements, outgoing-only prepare-stage secret transfer and incoming-only recovery with no failed-old-MA session. Qualify firmware-slot cleanup separately under PA-008. | DESIGN_REQUIRED; logical typed records only, no local wire ABI approved |
| PA-007-PEER-04 [USERSPACE] | Compose real evidence verification and current fixed/ordered-release admission with policy expiry, roots/profile, actual current TH1 and exact operation/role/binding/epoch/attempt/stage. Use V2 purposes6/7,325/703-byte nonsecret preimages, source-only random32 delivery and protected acceptance, with separate correlated firmware outcomes and durable replay gates. Qualify independent RNG draws, once-only generation/same-secret retry and absence of old-profile downgrade. Do not equate transport establishment, decoded acceptance or a matching digest with these authorities, key-possession proof or firmware installation. | DESIGN_REQUIRED; T4.14-PRE bounded amendment is not real crypto/policy/provider composition |
| PA-007-PEER-05 [OHCL] [USERSPACE] | Publish end-to-end wrong/stale route, crossed-purpose/role, malformed/oversized/partial frame, duplicate/unsolicited/lost response, engine replacement, timeout/cancel, cleanup failure and restart tests on confirmed adapters. Demonstrate host-visible ciphertext, bounded allocation and erasure. Record versions, actual PRs/commits and counterpart acceptance; qualify anchored no-new-session restart under PA-011 and hardware effects under PA-008. | EXTERNAL_DEPENDENCY; no production/hardware qualification evidence |

These actions supplement PA-007-OHCL-01/02/03/06/07 and
[PA-011](#pa-011). No production item is closed by bounded T4.13 conformance.
Wrapper pre/post deadline checks cannot interrupt a backend stuck in I/O.
Drop/abort observation is not proof of firmware slot cleanup or durable outcome.

### PA-008

**Hardware effects and recovery.** AMD/platform and BASE/OHCL integration
owners must demonstrate real firmware authorization/install/rebind effects,
unchanged recovery identity and verified persisted state. Dependencies:
[PA-006](#pa-006) appraisal, [PA-007](#pa-007) sidecar integration,
[PA-009](#pa-009) parser and [PA-011](#pa-011) durable state.

Current-scope clarification, 2026-11-04: hardware effect/persistence
qualification is distinct from the fresh inter-node purpose-3 attestation
exchange. That exchange and its readiness gate remain
[deferred by the canonical plan](q162-revised-master-execution-plan.md#current-scope-override-fresh-post-install-attestation-deferred);
the actions below do not reactivate it. Firmware completion is not a claim of
independently attested persistence.

T4.11 now supplies the bounded
[`SnpMigrationKeyInstaller` interface](../src/pal/src/snp/migration_install.rs)
with exact typed operands, correlated outcomes and an unavailable provider.
Its recording/failure tests qualify logical boundary behavior only; they do
not close PA-008, supply the hardware adapter or authorize a retry. The legacy
key-only mock is not an implementation of this new boundary.

#### PA-008 OHCL/Linux installation integration actions

These are tracked production obligations, not completed T4.11 work or approved
kernel API definitions. `[OHCL]` denotes a dependency of the selected Linux/
OpenHCL architecture, not an AMD-prescribed userspace API. Tracking owner
remains the PA-008 owner; external technical acceptance is still required.

| Action | Required work / closure evidence | Target and dependency | Current disposition |
|---|---|---|---|
| PA-008-OHCL-01 [OHCL] | Obtain and pin the actual OHCL-Linux-Kernel source revision, target configuration and responsible integration authority. Inspect existing installation support and select/approve its userspace contract before proposing a new ioctl or message. | BASE/OHCL kernel integration; H5.3, before a real installer adapter | EXTERNAL_DEPENDENCY; kernel checkout/revision and technical acceptance absent |
| PA-008-OHCL-02 [OHCL] | Define the logical target handle, caller access, lifetime and stale-handle rejection. Establish how the kernel/lower-layer authority resolves the intended guest context without MA-supplied GCTX_PADDR; correlate completion to the request. | MigTD, BASE routing and OHCL kernel; PA-007 and OHCL-01 | DESIGN_REQUIRED; exact routing/API not established |
| PA-008-OHCL-03 [OHCL] | Reuse existing kernel installation support if present; otherwise implement the approved UAPI and handler. Marshal MSK32, opaque migration-data64, REPORT_ID and role/algorithm; zero reserved fields, use protected firmware messaging and retain authoritative firmware binding/state checks. Kernel must not calculate Venice history or migration policy. | OHCL kernel/platform firmware path; OHCL-01/02 and accepted ARG command contract | EXTERNAL_DEPENDENCY; need for a kernel patch remains conditional, not verified |
| PA-008-OHCL-04 [OHCL] | Implement a typed userspace binding for the confirmed kernel API and connect the MigTD hardware installer. Preserve separate transport/kernel and firmware outcomes, raw status and uncertain effects. Do not retry unknown-effect operations blindly or substitute a success-only mock. | OpenHCL userspace and MigTD hardware adapter; OHCL-01/03, T4.11 and H5.3 | EXTERNAL_DEPENDENCY; no installation wrapper found in inspected OpenVMM revision |
| PA-008-OHCL-05 [OHCL] | Protect key material across the boundary: authorized access, protected firmware payload handling, no secret logs, and cleanup of secret-bearing temporary buffers on success/failure. Verify ownership and cleanup in both userspace and kernel changes. | MigTD/OpenHCL/OHCL kernel; OHCL-02/03/04 | DESIGN_REQUIRED; implementation and evidence pending |
| PA-008-OHCL-06 [OHCL] | Test request sizing/encoding, target/role/identity rejection, firmware guest-state/active-session rejection, unsupported algorithm, raw status, transport loss and possible effects. Demonstrate exact migration-data forwarding and safe failure/retry behavior; qualify supported hardware end to end. Publish sanitized results and actual PR/commit/version links. | MigTD/OpenHCL/kernel/platform tests; OHCL-01 through OHCL-05, H5.3/H5.7 | EXTERNAL_DEPENDENCY; no kernel/hardware qualification evidence |

Inspection evidence, 2026-11-04: the supplied local OpenVMM checkout
`/home/murthy/repos/openvmm` was clean at
`8daf1d537602c70c849b42402072c42c29e9e245`. Its
`Guide/src/dev_guide/getting_started/build_ohcl_kernel.md` identifies the kernel
as a separate OHCL-Linux-Kernel repository; it is not a kernel-source checkout.
The inspected `support/sev_guest_device/src/lib.rs` exposes report, derived-key
and TIO bindings, not a migration-installation method. No
`MSG_SET_MIGRATION_INFO` implementation was found in that checkout.
This establishes a userspace integration gap in the inspected source, not
proof that the separate kernel lacks support. No ioctl number, kernel
structure, target-resolution mechanism or exact kernel patch is assumed.
No OpenVMM or kernel source was changed.

Evidence: no hardware qualification supplied. [E-03](#e-03) explicitly
excludes readiness/effects from approval receipts. Still required: production
image hygiene, real reports and purpose bindings, exact installed migration
data, failure/partial-effect recovery and end-to-end hardware results under
H5.7. Qualification: pending; legacy emulator regressions do not satisfy it.

### PA-009

**Authoritative AMD layout.** AMD firmware/ARG specification authorities must
resolve the Firmware ABI 1.59 / ARG v1.20 Version 6 ETCB/MIGRATION_DATA overlap
and valid-bit conflict. An authoritative document/erratum/selector/version and
its acceptance link are still absent.

Evidence: the [canonical blocker](q162-revised-master-execution-plan.md)
remains open; fixture supplement contracts do not resolve physical layout.
Still required: authoritative resolution, exact citations, independent
production-profile parser vectors, accepted/pinned AAS parser/adapter and
fixture-rejection conformance. Qualification: BLOCKED. Production parsing
must fail closed without partial/default claims.

### PA-010

**Approved LM-policy schema.** Microsoft policy authority must approve the
closed JSON schema, signature/purpose rules and RFC 8785 semantic
canonicalization. Contract/model policy bytes are not that approval.

Evidence: [E-01](#e-01) verifies the frozen semantic digest recipe through a
test adapter; [E-03](#e-03) defines provider ownership. Still required: approved
schema and real canonicalization, duplicate/unknown-field, signature, purpose,
profile and malformed-policy vectors. Coordinate [PA-005](#pa-005) production
signer configuration. Qualification: pending.

### PA-011

**Trusted time and rollback-resistant storage.** Deployment trusted-state
and BASE integration owners must provide trusted time plus independently
anchored authenticated state and atomic durable revision-CAS, including
identical retries and ambiguous writes.

Evidence: [E-01](#e-01)/[E-02](#e-02) cover unavailable-provider errors and
model sequence/CAS behavior; [E-03](#e-03) defines revalidation obligations.
Still required: trusted-time/certificate validity, namespace isolation,
crash/restart/rollback/ambiguous-write recovery and retention tests on the
actual providers. Qualification: pending; missing/corrupt state cannot become
provisioned empty state.

## Prohibited production claims

- No AMD ABI/layout conformance for the conflicting physical report fields,
  production readiness, hardware qualification or successful deployment.
- No approved Microsoft policy schema, provisioned authorization PKI or
  production signature-chain verification from the unit-test policy/PKI adapters.
- No durable persistence, restart security or rollback anchor from the model store.
- No ordered-release SVN, upgrade ranking or historical initial-MA authorization
  from fixed-release approval or allowlist sequence.
- No active SPDM policy admission, installation or migration readiness from a
  `VerifiedMaPolicyCollateral` receipt. Tasks 7/9 and the later firmware gates
  must wire and qualify the live consumers.
- No requirement completion or production qualification from ledger tracking
  alone; pending implementation, publication and acceptance evidence remains pending.

## Evidence register

### E-01

**P0.9 fixed-release implementation evidence.**

The user accepted and froze bounded fixed-release contract/control-flow
conformance on 2026-11-03T04:21:50Z, with no conditions:
`P0.9-FixedReleaseCollateralV1-2026-11-03`. That acceptance retained
external-provider, production and tracking gates; the selected repository
tracker now supplies the tracking mechanism and accountable owner, not
qualification or closure of any PA requirement above.

[ma_policy.rs](../src/pal/src/snp/ma_policy.rs) implements the exact 280-byte
identity input and 320-byte allowlist, actual P-384/SHA-384 allowlist signature
verification, operation-bound sealed approvals, current-platform comparison
and atomic sequence-control flow. The fixed profile has no dummy SVN; ordered
claims use a separate typed profile and signed contract.

[ma_policy_tests.rs](../src/pal/src/snp/ma_policy_tests.rs) uses real generated
P-384 signing keys, independently generated digest vectors and explicitly
test-only report/schema/PKI/store adapters. These tests are contract/control-flow
evidence, not acceptance evidence for the production requirements above.
All missing default providers return explicit errors; the current fixed-release
verification entry point also rejects production authorization profiles.

### E-02

**Intended-production custom ordered collateral.**

The user selected a custom versioned SNP collateral format and requested
P0.9A2/B2/C2 contract implementation with fixture verification on 2026-11-03.
The [inline contract](q162-revised-master-execution-plan.md#p09a2-orderedreleasev1-mapolicy-endorsement)
replaces the open CoRIM-or-equivalent choice. This is not a requirement to
convert to CoRIM later; changing formats would require an explicit versioned
decision.

[ordered_collateral.rs](../src/pal/src/snp/ordered_collateral.rs) implements
bounded canonical publisher snapshots, purpose-separated historical records,
real P-384 signatures, immutable identity/SVN mapping, monotonic release status,
sequence/epoch conflict rejection and current tenant/history-bound ordered
admission. Fixed wire bytes and SNP-specific platform/report checks are retained.

[ordered_collateral_tests.rs](../src/pal/src/snp/ordered_collateral_tests.rs)
uses separate explicitly pinned test-only release/historical keys and model
trust/history/state providers. They do not qualify production PKI, root-update
administration, durability or real hardware history.
Evidence is under `target/p0.9-ordered-validation/20261103T153417Z/`.
Production authorization still fails explicitly. No PA row becomes `QUALIFIED`
from this implementation or repository acceptance alone.

Bounded contract/fixture scope accepted and frozen at
2026-11-03T15:49:03Z as `P0.9-OrderedCollateralV1-2026-11-03`, conditions: None.
This acceptance retains every production qualification gate above and does
not authorize a next milestone or live production admission.

### E-03

**P0.9D consumer/provider contract evidence.** The
[inline D handoff](q162-revised-master-execution-plan.md#p09d-freeze-gates-and-consumer-dependencies)
was accepted at 2026-11-03T16:13:49Z as
`P0.9D-ConsumerContractsV1-2026-11-03`, conditions: None.
Three sealed-contract compile-fail doctests passed; fixed/ordered source hashes
and the exact execution order were preserved. The durable execution reference
is the [central log](implementation_record.log); raw local evidence is under
`target/p0.9d-validation/20261103T160603Z/`.
This is documentation/contract evidence, not live integration or qualification.

### E-04

**P0.9E tracking evidence.** Repository-ledger tracking and accountable owner
were explicitly selected on 2026-11-03. All eleven records, metadata, anchors,
evidence links and honest qualification states passed structural/link checks;
accepted sources, the D freeze, execution order and prior log were preserved.
The user accepted this bounded tracking scope at 2026-11-03T17:40:06Z as
`P0.9E-ReadinessLedgerV1-2026-11-03`, conditions: None. Evidence is recorded
centrally and locally under
`target/p0.9e-validation/20261103T162359Z/`.
All eleven requirements remain unqualified. External work-item links, PRs,
commits, named external technical contacts and durable evidence publication
are explicitly pending, not fabricated or prerequisites to use this selected
tracker.
