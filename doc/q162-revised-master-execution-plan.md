# Q162 Integrated Master Execution Plan

Status: Accepted canonical implementation plan; bounded Phase 0 provider gate reconciled; T4.9-T4.16 bounded implementations accepted

Last reconciled: 2026-11-05

## Current-scope amendment: T4.14-PRE direct-random secrets

Status: bounded V2 infrastructure implemented; relevant regressions and full
local CI command parity PASS, including the complete EMU matrix with CI's
Rust 1.88.0 toolchain. Separately authorized dependency and workspace
strict-Clippy remediation pass without advisory waivers or lint suppression.
T4.14-PRE accepted and frozen at 2026-11-05T02:22:07.036Z; conditions: None.
Freeze identifier: `T4.14-PRE-DirectRandomV2-2026-11-05`.
Acceptance is limited to the documented bounded scope and exclusions.
T4.14 progress and completion acceptance are tracked in its own section below.

User-directed supersession, 2026-11-04: replace bilateral migration-key
contributions, commitments and HKDF with a source-generated fresh random
32-byte MSK delivered over the authorized encrypted SPDM session. Replace
planned-handoff seed/HKDF generation with an independently generated outgoing
MA random 32-byte secret. Incoming-only recovery is unchanged.

The user separately selected explicit SPDM-protected delivery acceptance
receipts, removing application HMAC confirmations. Acceptance is not proof
of application key possession or firmware installation. Both correlated
role-specific firmware outcomes remain required; partial/unknown effects,
durable replay, tenant/history/policy association and cleanup remain gates.
New protocol meanings must be version-distinct and must reject legacy
contribution/confirmation messages, not reinterpret them or zero-fill them.

This amendment overrides conflicting *active* requirements below. Retained
P0.3/P0.6/P0.7/P0.8/P0.10/P0.11 and T4.12/T4.13 design, approval and test
records describe their historical bounded contracts, not validation of the
replacement. Preserve those records; do not erase or retroactively reapprove
them. Current documentation and implementation must be reconciled before
this amendment can close.

This is a named prerequisite of T4.14, not an additional numbered entry or
renumbering of the canonical 37-step sequence. T4.14's separate bounded
implementation was accepted at 2026-11-05T03:02:37.597Z.
No runtime/production/hardware qualification is implied.

Exact active contracts, historical disposition and implementation:
[T4.14-PRE direct-random amendment](snp/task4/t4.14-pre-direct-random.md).

## Current-scope override: fresh post-install attestation deferred

User-approved disposition, 2026-11-04: defer fresh post-install attestation.
It is not a current implementation, installation-success, readiness or phase
completion gate. This override governs conflicting requirements below,
including the preserved P0.3/P0.8/P0.10 contracts, TDX/SNP reconciliation,
Task 4 models, Task 12 and canonical sequencing.

Specifically deferred: generating, exchanging and verifying fresh inter-node
purpose-`0x03` evidence of actual persisted state, its peer-verification
acknowledgement, and making typed installation success/readiness depend on
that exchange. Task 12 is retained as deferred future work, not a prerequisite
for Task 13, Task 14 or subsequent milestones at this stage.

This is an application-protocol scope decision, not removal of an AMD ABI
requirement. Firmware completion is distinct from independently attested
persisted state. Current success/readiness must remain correlated to successful
role-specific installation on both sides and all other active authorization,
history, protected acceptance and firmware-state gates; do not claim independent
attestation of persistence. Failure, partial or indeterminate effects must
remain explicit and must not authorize readiness.

Historical freezes, purpose identifiers, wire layouts, vectors and accepted
conformance results remain unchanged as historical/interface evidence. Existing
P0.8 code still enforces its original persisted-evidence-before-success sequence:
it is not activated, bypassed or reinterpreted by this documentation change.
Before activating a current-scope typed result flow, explicitly reconcile its
success-admission/scheduling API with this deferral; do not supply a fake
verifier or manufacture a persistence receipt.

Future reactivation requires a separate explicit decision establishing the
evidence source, what firmware state it authenticates, its freshness/binding
and executable verification. An MA-signed digest alone does not establish
firmware persistence. No runtime, OHCL integration or production qualification
is implemented or newly accepted by this override.

Execution-order clarification addendum: 2026-11-02. This revision reconciles
prerequisites, architectural versus executable gates, tenant-evidence
sequencing, and production-parser completion. It does not change frozen wire
layouts, numeric registries, identity encodings, or evidence profiles.
Previously approved freezes remain accepted; their execution-order entries
require implementation and conformance evidence, not a second contract freeze.

Starting point:

```text
Task 4 Steps 1-8: complete and accepted
Task 4 Step 9 onward: not yet complete
MigTD feature worktree: contains substantial uncommitted implementation
```

Current readiness:

```text
P0.1 active-worktree baseline:             DONE; BASELINE ACCEPTED
P0.2 current ABI command/report freeze:    DONE; APPROVED AND FROZEN
P0.3 frozen-contract conformance:          DONE; LATER QUALIFICATION GATES OPEN
P0.4 VeniceV1 contract conformance:         DONE; LATER QUALIFICATION GATES OPEN
P0.3 ReportDataContextV1:                  APPROVED AND FROZEN
P0.9A1 FixedReleaseV1 encoding:            APPROVED AND FROZEN
P0.9 fixed-release conformance:           DONE; LATER QUALIFICATION GATES OPEN
P0.9 ordered contract/fixture scope:      ACCEPTED AND FROZEN; PRODUCTION GATED
P0.9D consumer-contract consolidation:    DONE; ACCEPTED AND FROZEN
P0.9E repository-ledger tracking:         DONE; ACCEPTED AND FROZEN
P0.12A/P0.12A1 common verifier boundary:   APPROVED AND FROZEN
remaining Phase 0 contracts and vectors:   GATED / TO FREEZE
T4.9 tenant-evidence implementation:       DONE; BOUNDED IMPLEMENTATION ACCEPTED
T4.10 platform-key disposition:            DONE; BOUNDED IMPLEMENTATION ACCEPTED
production Version 6 physical parser:      BLOCKED ON AMD
```

The 2026-10-23 Tasks 4-14 feasibility audit is closed as an active blocking
record. Its findings remain historical evidence, but the accepted decisions
and freeze addenda in this plan supersede its instruction to pause T4.9.

## 1. Purpose

This document is the single canonical forward execution plan for the AMD
SEV-SNP Migration Agent implementation. It replaces the previous revision of
this file and integrates:

- the accepted Q162 security and semantic requirements;
- the frozen Task 2 and Task 3 contracts;
- accepted Task 4 Steps 1-8;
- AMD SEV-SNP Firmware ABI 1.59;
- AMD ARG ABI v1.20;
- Design Review Problems 1-5;
- Technical Notes Q169-Q172;
- the selected Microsoft protocol and policy decisions;
- the migration emulator;
- the local MA handoff and recovery emulator;
- the boundary between emulator qualification and production integration.

The selected final build matrix is:

```text
TDX production       -> no_std
SNP production       -> std
TDX emulator         -> std
SNP emulator         -> std
```

For SNP, `std` is not the emulator boundary. `SnpEmuAzure` and `SnpHardware`
both target the MigTD-owned `SnpReportVerifier` contract and a Linux/Underhill
userspace runtime. `SnpEmuAzure` composes the accepted AAS base-report verifier
with the MigTD fixture-supplement verifier. `SnpHardware` uses the production
AAS adapter but fails closed at the named Version 6 physical-layout conflict
until AMD publishes an authoritative layout. They remain separate
compositions because they select different evidence, collateral, transport,
firmware-state, randomness, installation, rebind, persistence, and packaging
providers. No TAV verifier is part of either final SNP composition.

The plan is ordered by actual prerequisite. A later phase must not begin until
the preceding gate is satisfied, except where a step explicitly permits
parallel work.

Historical execution records remain historical. Any correction to a frozen
contract must be recorded as a versioned addendum, wire-version change, or
newly frozen contract rather than silently rewriting prior records.

## 2. Authoritative source hierarchy

For all new implementation and review:

```text
1. AMD SEV-SNP Firmware ABI 1.59
2. AMD ARG ABI v1.20
3. Accepted Design Review decisions for Problems 1-5
4. Accepted Q162 security requirements and Microsoft policy
5. Accepted Task 2 semantic contract and approved addenda
6. Task 3 Version 1 wire contract and approved extensions
7. Accepted Task 4 provider architecture
8. This integrated master execution plan
9. Individual execution and freeze records
```

Important ABI corrections:

- `MSG_VERIFY_REPORT` is not a current ARG ABI v1.20 operation.
- Firmware ABI 1.59, not 1.58, defines the Venice `ETCB_VERSION`.
- Attestation-report Version 6 carries the ETCB fields used by this plan.
- `SNP_REBIND_MA` is a host/hypervisor firmware command, not an MA guest
  message.

## 3. Selected Design Review decisions

| Problem | Selected design |
|---|---|
| 1. Migration history | Choice A: exact 64-byte `VeniceV1` profile |
| 2. Tenant-report acquisition | Option A: BASE host-driven/push |
| 3. Tenant-report binding | Choice B: zero-`REPORT_DATA` report with additional authenticated binding |
| 4. Migration-key establishment | T4.14-PRE supersession: source-generated random32; protected delivery/acceptance; no contributions, commitments, HKDF or application HMAC |
| 5. MA rebind | Emulator handoff/recovery may proceed without real firmware support; production `SNP_REBIND_MA` remains a later integration gate |

Problem 3 intentionally does not require tenant-controlled `REPORT_DATA`.
The host-requested tenant report is zero-filled, and its canonical digest is
bound into fresh MA evidence containing the SPDM transcript, request, roles,
tenant identity, and policy. This prevents tenant substitution and
cross-operation reuse without claiming that the tenant report itself is
session-bound.

Version 1 does not require first-use freshness of the tenant report. It accepts
a bounded replay model using durable report-digest state, explicit idempotent
retry rules, and firmware-state validation. Phase 5 qualifies the production
durability and rollback resistance of that state; it does not require tenant
cooperation or caller-selected tenant `REPORT_DATA`.

## 3A. Feasibility-audit closure

The historical `q162-tasks4-14-feasibility-audit.md` identified the correct
reasons to pause T4.9 in October. Those design blockers now have accepted
owners and dispositions:

| Audit area | Canonical resolution |
|---|---|
| Removed `MSG_VERIFY_REPORT` | Software verification through the frozen `SnpReportVerifier` boundary |
| Tenant acquisition | BASE host-push under P0.5 and T4.9 |
| Zero-bound tenant report | P0.6 digest binding, replay state, and fresh MA evidence |
| Complete `REPORT_DATA` validation | `P0.3-ReportDataContextV1-2026-11-01` |
| Contribution and confirmation wire records | P0.7-P0.8 and Task 3 addenda |
| TDX-shaped SNP runtime | Task 5 replacement matrix after provider freeze |
| Migration installation | T4.11 and Task 11 exact adapter/state model |
| Emulator/production isolation | T4.15-T4.20 and separate Phase 5 qualification |
| Version 6 offset collision | P0.12A/P0.12A1 emulator profile; PA-009/AMD for production |

The audit no longer blocks T4.9 as an unresolved design decision. T4.9 remains
an unimplemented provider-architecture step and begins only after the Phase 0
gate is satisfied.

## 4. Status and qualification labels

Task status:

```text
READY       prerequisites are complete
GATED       contract direction is accepted, but named prerequisites remain
BLOCKED     a named prerequisite or decision is incomplete
DEFERRED    outside the current milestone
IN PROGRESS implementation is active
DONE        accepted and persistently recorded
```

A heading written as `Status: READY after <prerequisites>` is a dependency
expression. Its current state is `GATED` until those prerequisites are
complete.

Capability:

```text
GREEN   currently implementable from approved contracts
YELLOW  requires BASE, tenant, policy, or product integration
RED     no documented production primitive or incompatible contract
BLUE    fixture or emulator capability only
```

Qualification:

```text
Fixture-verified
Migration-emulator-verified
Rebind-emulator-verified
Compile-only hardware boundary
Hardware-integrated
Hardware-qualified
```

No fixture or emulator result may be reported as hardware qualification.

## 5. Global execution rules

1. Every implementation step identifies:
   - inputs and outputs;
   - caller and target;
   - state preconditions;
   - trust boundary;
   - error domain;
   - retry and idempotency behavior;
   - secret lifetime and cleanup.
2. Every AMD operation cites the ABI version, section, request layout, and
   status mapping.
3. Hardware providers fail closed. They never fall back to fixtures, synthetic
   roots, TCP emulation, TDX operations, test randomness, or success-shaped
   mocks.
4. Software verifies attestation reports. It validates signatures, certificate
   chains, trust anchors, complete `REPORT_DATA`, identities, TCB/ETCB,
   migration data, policy, role, request, freshness classification, and replay
   state.
5. Host metadata is routing and orchestration data, not cryptographic proof.
6. Physical GCTX addresses remain host-internal. Shared MA logic uses managed
   handles and typed operation identifiers.
7. Host control never transports migration-key contributions, confirmation
   tags, SPDM session keys, handoff secrets, or plaintext protected metadata.
8. Every state-changing operation returns an explicit typed success or failure.
   There are no silent defaults or success-shaped fallbacks.
9. Frozen contracts receive:

   ```text
   versioned addendum or new version
   exact layout and registry update
   golden vectors
   malformed-input tests
   compatibility decision
   audit and freeze record
   ```

## 6. Communication-plane model

The implementation has distinct communication planes.

### Inter-node migration

```text
HostControlTransport:
    BASE host <-> local MA orchestration and status

InterNodePeerTransport:
    source-node MA <==== authenticated encrypted SPDM ====> destination-node MA
```

### Local planned MA handoff

```text
HostControlTransport:
    BASE host <-> old local MA and new local MA

LocalHandoffPeerTransport:
    old local MA <==== authenticated encrypted SPDM ====> new local MA

Firmware command path:
    Hypervisor ---------------- SNP_REBIND_MA ----------------> PSP
```

The remote node's MA has no direct role in a local `SNP_REBIND_MA`. If a
cross-node migration is active during local handoff, the new local MA must
establish a fresh inter-node SPDM session and be re-attested before the
migration is restarted or explicitly resumed.

## 7. Terminology

Use distinct names for the two different two-process arrangements:

```text
InterNodeTwoProcessMigration:
    source-node MA and destination-node MA

LocalMaHandoffTwoProcess:
    old MA and new MA on the same node
```

Do not use an unqualified "Two-Process Model" where the meaning could be
ambiguous.

---

# Phase 0 - Baseline and Freeze Corrected Contracts

Goal: establish a clean implementation baseline and freeze every contract
required by Tasks 4-14 and the rebind emulator.

## P0.1 Baseline the active MigTD worktree

Status: DONE; baseline accepted on 2026-11-02

Execution evidence: `doc/implementation_record.log`, Phase 0 / P0.1,
record `P0.1-baseline-20261102T191909Z`. All pre-existing changes are preserved
as user-owned work in progress. Acceptance is limited to the inventory and
ownership review, not acceptance of incomplete implementation contracts.

Before modifying implementation paths, record:

```text
branch and baseline commit
all dirty paths
owner and intent of each uncommitted change
existing tests and results
accepted versus experimental changes
overlap with this plan
```

Specifically audit existing work for:

```text
SnpKeyContributionV1
opcodes 0x26 and 0x27
element type 0x0104
SnpAuthorizationResultV1
complete 64-byte REPORT_DATA validation
MigrationKeyInstaller
```

Acceptance:

- no existing work is overwritten without ownership review;
- accepted work is linked to its owning step;
- incomplete work is either completed by this plan or explicitly superseded.

## P0.2 Freeze current ABI command and report profile

Status: DONE; APPROVED AND FROZEN on 2026-11-02

Freeze identifier: `P0.2-CurrentAbi159Arg120-2026-11-02`.

Deliverable:
[current Firmware ABI 1.59 / ARG v1.20 addendum](snp/task4/q162-arg-v120-command-addendum.md#current-p02-addendum-2026-11-02).
Execution evidence: `doc/implementation_record.log`, Phase 0 / P0.2.
The freeze is documentation-only; it does not implement firmware adapters,
enable production parsing of conflicting fields, or close PA-009.

Actions:

1. Remove `MSG_VERIFY_REPORT` from all current hardware paths and diagrams.
2. Preserve older flows only as pre-v1.20 historical material.
3. Freeze the current command matrix for:

   ```text
   SNP_HV_REPORT_REQ
   MSG_REPORT_REQ
   MSG_SET_MIGRATION_INFO
   MSG_SET_HANDOFF_SECRET
   SNP_REBIND_MA
   SNP_ARG_BEGIN_MIGRATION
   ```

4. Add Firmware ABI 1.59 attestation-report Version 6 fields:

   ```text
   CURRENT_TCB         0x038
   REPORTED_TCB        0x180
   COMMITTED_TCB       0x1E0
   LAUNCH_TCB          0x1F0
   LAUNCH_MIT_VECTOR   0x1F8
   CURRENT_MIT_VECTOR  0x200
   CURRENT_ETCB        0x220
   LAUNCH_ETCB         0x240
   COMMITTED_ETCB      0x260
   ```

5. Freeze the authoritative Venice ETCB component layout:

   ```text
   111:104 ARG
   103:96  DPE_DRIVER
   95:88   FHP_DRIVER
   87:80   ASP_OS_DRIVER
   79:72   SOC_DRIVER
   71:64   MICROCODE
   63:56   TMPM
   55:48   PRE_ESID
   47:40   BOOT_DRIVER
   39:32   HAD_DRIVER
   31:24   ART_RT
   23:16   ART_FMC
   15:8    MP1
   7:0     IP_KEY_MANAGER
   255:112 reserved
   ```

Known physical-layout blocker:

```text
Firmware ABI 1.59:
    CURRENT_ETCB  0x220-0x23f
    LAUNCH_ETCB   0x240-0x25f

ARG ABI v1.20:
    MIGRATION_DATA[64]  0x208-0x247
```

These ranges overlap in the same Version 6 signed body. P0.12A freezes a
test-only `SnpEmulatorV1` evidence profile without treating it as the
authoritative AMD layout. Production raw-report parsing of both claim groups
remains blocked until AMD publishes a corrected layout, selector, erratum, or
new report version.

Deliverable:

```text
current ABI command/report addendum
```

## P0.3 Complete `REPORT_DATA` validation

Active inter-node update: purposes6/7 and the nonsecret V2 binding/preimages
are specified in [T4.14-PRE](snp/task4/t4.14-pre-direct-random.md).
The full64 REPORT_DATA rule and local purposes4/5 remain. Contribution-purpose
and confirmation definitions below preserve historical V1 contracts only.

Status: APPROVED AND FROZEN on 2026-11-01

Freeze identifier: `P0.3-ReportDataContextV1-2026-11-01`

Implementation conformance: DONE; targeted validation passed; user accepted
contract conformance on 2026-11-02 with mandatory later qualification gates
retained and no additional conditions. Implementation freeze:
`P0.3-ContractConformance-2026-11-02`. Execution evidence is in
`doc/implementation_record.log`, Phase 0 / P0.3. The original contract approval
remains unchanged. See the
[current Step 7 addendum](snp/task4/p0.3-step7-addendum.md#current-p03-conformance-addendum-2026-11-02).

Execution qualification boundary: current codec/binding-helper conformance and
legacy-backend regressions do not qualify the future common `SnpReportVerifier`
compositions, authenticated synthetic-report supplement, production parser, or
recovery state machine. Those executable surfaces are scheduled under
P0.12A/Task 4/AAS1A-M, H5.0, and Phase 4. Their requirements below remain open;
the user accepted closing this early contract-conformance step with those
later qualification gates explicitly deferred, not waived. No runtime recovery
success or production hardware qualification is claimed.

Guest-requested MA reports:

```text
ReportDataContextV1 = 220 bytes

Offset  Size  Encoding
0x000    28   DOMAIN = ASCII "AMD-SNP-MA-LM-REPORT-DATA-V1"
0x01c     2   CONTEXT_VERSION = 1, u16le
0x01e     1   EVIDENCE_PURPOSE
0x01f     1   ROLE
0x020     8   REQUEST_ID, u64le
0x028     2   MIGRATION_VERSION, u16le
0x02a     2   ALGORITHM, u16le
0x02c    32   TENANT_BINDING_ID
0x04c    48   TH1
0x07c    48   PURPOSE_BINDING_DIGEST
0x0ac    48   MA_POLICY_IDENTITY_DIGEST

expected =
    SHA384(exact ReportDataContextV1[220]) || zero[16]

compare all 64 report-data bytes
reject nonzero bytes 48-63
```

All integers in the context and purpose records are little-endian. Domain
strings are the displayed ASCII bytes without a trailing NUL. Unknown
versions, purposes, roles, algorithms, stages, and reserved values fail
closed.

The P0.3 freeze retains the existing 220-byte size but supersedes these older
Task 3 field names and semantics:

```text
tenant_report_id         -> TENANT_BINDING_ID
contribution_commitment  -> PURPOSE_BINDING_DIGEST
local_policy_digest      -> MA_POLICY_IDENTITY_DIGEST
```

The Task 3 codec, enum registries, vectors, and consumers must be updated
before the revised context is used. `LM_POLICY_DIGEST` is not duplicated
because it is transitively included in the frozen P0.9A1
`MA_POLICY_IDENTITY_DIGEST`.

### P0.3A Purpose, role, and algorithm registry

```text
EvidencePurpose:
    0x01  InterNodeKeyContribution
    0x02  InterNodeTenantAuthorization
    0x03  InterNodePostInstallConfirmation
    0x04  LocalPlannedHandoffAuthorization
    0x05  LocalRecoveryHandoffAuthorization

Role:
    0x00  Source
    0x01  Destination
    0x02  Outgoing
    0x03  Incoming

Algorithm:
    0x0000  None
    0x0003  Aes256GcmMigrationV1
    0x0004  LocalHandoffSecretV1

OperationStage:
    0x01  PrepareAuthorization
    0x02  FirmwareResultConfirmation
```

Legal combinations:

| Purpose | Legal roles | `TENANT_BINDING_ID` | `TH1` | Algorithm |
|---|---|---|---|---|
| `0x01` Inter-node key contribution | Source, Destination | verified tenant `REPORT_ID` | inter-node SPDM TH1 | `0x0003` |
| `0x02` Inter-node tenant authorization | Source, Destination | verified tenant `REPORT_ID` | inter-node SPDM TH1 | `0x0003` |
| `0x03` Inter-node post-install confirmation | Destination only | verified tenant `REPORT_ID` | inter-node SPDM TH1 | `0x0003` |
| `0x04` Local planned handoff | Outgoing, Incoming | `zero[32]` | local handoff SPDM TH1 | `0x0004` |
| `0x05` Local recovery handoff | Incoming only | `zero[32]` | `zero[48]` | `0x0000` |

For local operations the tenant set is bound through the exact 48-byte
`TENANT_SET_DIGEST` in the purpose record. A zero tenant-binding field does not
mean that the tenant set is unbound.

For purposes `0x01`-`0x03`, `MIGRATION_VERSION` is the negotiated inter-node
migration version. For purposes `0x04` and `0x05`, it is the local
handoff/recovery protocol version and must equal `1`.

The protocol wire addendum must carry these exact numeric registries, legal
combinations, stage rules, and failure behavior into the Task 3 codec, MA
evidence records, host-control messages, golden vectors, and protocol
documentation. It must not renumber existing `0x01`-`0x03` purposes or
`0x00`-`0x01` roles. Unknown and reserved values are never negotiated through
or preserved.

### P0.3B Purpose-specific binding digests

Purposes `0x01` and `0x02` continue to use the frozen P0.7 contribution
commitment and P0.6/P0.8 tenant-authorization context respectively. Their
domain-separated canonical digests occupy `PURPOSE_BINDING_DIGEST`.

Post-install confirmation uses:

```text
MIGRATION_DATA_DIGEST =
    SHA384(exact installed MigrationDataV1[64])

INSTALLATION_RESULT_DIGEST =
    SHA384(
        "SNP-LM-INSTALLATION-RESULT-v1" ||
        u16le(1) ||
        u32le(0) ||             // STATUS = Success
        u16le(0x0003) ||        // Aes256GcmMigrationV1
        0x01 ||                 // persisted = true
        zero[3] ||
        MIGRATION_DATA_DIGEST[48]
    )

PURPOSE_BINDING_DIGEST =
    SHA384(
        "SNP-LM-POST-INSTALL-v1" ||
        u16le(1) ||
        u64le(REQUEST_ID) ||
        TENANT_REPORT_ID[32] ||
        DESTINATION_MA_REPORT_ID[32] ||
        MIGRATION_DATA_DIGEST[48] ||
        INSTALLATION_RESULT_DIGEST[48]
    )
```

The outer context supplies the destination role, inter-node TH1, algorithm,
tenant binding, and MA/Policy identity. Post-install evidence is produced only
after persistence and cannot authorize the installation it confirms.

The canonical tenant set used by planned handoff and recovery is:

```text
canonical_tenant_set =
    u32le(count) ||
    verified tenant REPORT_ID[32] entries sorted in ascending byte order

TENANT_SET_DIGEST =
    SHA384(
        "SNP-LM-TENANT-SET-v1" ||
        canonical_tenant_set
    )
```

Duplicate tenant identities, an empty set, unsorted input, count mismatch, or
a provisional host routing identity fail.

The canonical firmware result set used by planned handoff and recovery is:

```text
canonical_firmware_result_set =
    u32le(count) ||
    entries sorted by TENANT_REPORT_ID[32], where each entry is:
        TENANT_REPORT_ID[32] ||
        u32le(raw SNP_REBIND_MA firmware status) ||
        BINDING_CHANGED[1] ||
        zero[3] ||
        PREVIOUS_MA_REPORT_ID[32] ||
        RESULTING_MA_REPORT_ID[32]

FIRMWARE_RESULT_SET_DIGEST =
    SHA384(
        "SNP-LM-REBIND-RESULT-SET-v1" ||
        canonical_firmware_result_set
    )
```

The result set must contain exactly one entry for every tenant in the frozen
tenant set. `BINDING_CHANGED` is `0x00` or `0x01`; any other value, duplicate,
omission, extra tenant, unsorted entry, status/binding inconsistency, or MA
identity mismatch fails.

Planned handoff uses:

```text
PURPOSE_BINDING_DIGEST =
    SHA384(
        "SNP-LM-PLANNED-HANDOFF-v1" ||
        u16le(1) ||
        OPERATION_STAGE[1] ||
        zero[1] ||
        u32le(ATTEMPT_NUMBER) ||
        HANDOFF_ID[16] ||
        u64le(REQUEST_ID) ||
        u64le(OPERATION_EPOCH) ||
        u64le(DEADLINE_UNIX_SECONDS) ||
        OUTGOING_MA_REPORT_ID[32] ||
        INCOMING_MA_REPORT_ID[32] ||
        TENANT_SET_DIGEST[48] ||
        MA_POLICY_IDENTITY_DIGEST[48] ||
        FIRMWARE_RESULT_SET_DIGEST[48]
    )
```

At `PrepareAuthorization`,
`FIRMWARE_RESULT_SET_DIGEST = zero[48]`. At
`FirmwareResultConfirmation`, it is SHA-384 over the canonical ordered
per-tenant `SNP_REBIND_MA` results. Both MAs use identical purpose bytes; the
outer context role distinguishes outgoing from incoming evidence.

Recovery uses:

```text
PURPOSE_BINDING_DIGEST =
    SHA384(
        "SNP-LM-RECOVERY-HANDOFF-v1" ||
        u16le(1) ||
        OPERATION_STAGE[1] ||
        zero[1] ||
        u32le(ATTEMPT_NUMBER) ||
        RECOVERY_ID[16] ||
        u64le(REQUEST_ID) ||
        u64le(OPERATION_EPOCH) ||
        u64le(DEADLINE_UNIX_SECONDS) ||
        FAILED_MA_REPORT_ID[32] ||
        REPLACEMENT_MA_REPORT_ID[32] ||
        TENANT_SET_DIGEST[48] ||
        MA_POLICY_IDENTITY_DIGEST[48] ||
        FIRMWARE_RESULT_SET_DIGEST[48]
    )
```

The displayed recovery preimage is the canonical authorization record carried
by `PrepareMaRecoveryRequest`; transport framing and opaque routing handles
are excluded. At `PrepareAuthorization`,
`FIRMWARE_RESULT_SET_DIGEST = zero[48]`. At
`FirmwareResultConfirmation`, it binds the canonical ordered per-tenant
recovery-mode `SNP_REBIND_MA` results.

### P0.3C Recovery without an outgoing MA

Recovery has no outgoing-MA evidence, outgoing signature, old/new SPDM
session, or handoff secret. The authoritative binding state supplies
`FAILED_MA_REPORT_ID`; verified replacement evidence supplies
`REPLACEMENT_MA_REPORT_ID`.

The replacement must:

1. match the policy-selected P0.9A1 fixed-release identity;
2. produce fresh purpose-`0x05`, role-`Incoming` prepare evidence;
3. reject stale epoch, deadline, attempt, tenant set, or recovery request;
4. permit BASE to invoke recovery-mode `SNP_REBIND_MA` only after readiness;
5. produce purpose-`0x05` result-confirmation evidence over exact firmware
   outcomes;
6. reattest successfully rebound tenants and preserve each tenant's immutable
   `INIT_MA_REPORT_ID`;
7. fail closed on identity, launch-state, tenant-set, firmware-result, replay,
   or partial-state disagreement.

Firmware-defined recovery identity and launch-state equality remains
mandatory. BASE may orchestrate and report outcomes but cannot manufacture MA
evidence or override firmware failure.

Host-requested tenant reports used by Version 1 migration:

```text
VMPL = 0xffffffff
REPORT_DATA = zero[64]
reject any nonzero REPORT_DATA byte
do not expect TH1, request_id, or another LM-session value in the tenant report
```

The tenant report's session association is established later by binding its
canonical digest into fresh MA evidence and the authorization context. The
guest-requested MA rule must not be applied to a host-requested tenant report.

Validate the shared `SnpReportVerifier` boundary in both `SnpEmuAzure` and
`SnpHardware` compositions. The emulator uses fixture collateral and its
authenticated supplement, while the production composition uses production
collateral providers and rejects fixture evidence. Common fields extracted
from the same authenticated base-report bytes have identical semantics; only
the emulator profile may add migration-data claims from its authenticated
supplement. No requirement asserts that fixture and production evidence are
byte-identical or interchangeable.

Acceptance:

- the exact 220-byte layout round-trips without implicit padding;
- every legal purpose/role/algorithm combination passes and every illegal
  combination fails;
- post-install, planned-handoff, and recovery golden preimages produce stable
  SHA-384 digests across implementations;
- changing any purpose-record field changes `REPORT_DATA`;
- prepare evidence rejects a nonzero firmware-result digest;
- result-confirmation evidence rejects a zero, incomplete, reordered, or
  mismatched firmware-result digest;
- recovery succeeds without an outgoing MA only through the frozen recovery
  path;
- an outgoing-MA evidence record, SPDM transcript, or handoff secret supplied
  to recovery is rejected;
- a valid digest with nonzero padding fails;
- a host-requested tenant report with any nonzero `REPORT_DATA` byte fails;
- a valid zero-filled host-requested tenant report passes without a
  caller-selected nonce or session digest;
- all valid reports continue to pass;
- the Task 4 Step 7 execution record receives an addendum.

## P0.4 Freeze `VeniceV1` migration history

Status: DONE - CONTRACT CONFORMANCE; APPROVED AND FROZEN on 2026-11-02.
Mandatory downstream executable qualification gates remain open.

Freeze identifier: `P0.4-VeniceV1-2026-11-02`.
Prerequisites: accepted P0.2 and P0.3 contract conformance.
User accepted the completed contract implementation, vectors and validation
with later qualification gates retained; additional conditions: none.

User-approved freeze choices (2026-11-02): `FORMAT_VERSION = 0x01`;
`TCB_ETCB_PROFILE = 0x03` (`VeniceV1`, appended after existing TCB profiles);
the tenant-policy full ETCB projection is `0x02`, without reassigning historical
`ArgSvnV1 = 0x01`. This step implements contract-conformance codecs, logical
history transitions and vectors, not runtime provider or installer activation.
Execution and acceptance are recorded centrally in `doc/implementation_record.log`,
Phase 0 / P0.4.

Define the exact 64-byte `MigrationDataV1` layout:

```text
Offset  Size  Field
0       1     FORMAT_VERSION
1       1     TCB_ETCB_PROFILE = VeniceV1
2       8     MIN_LAUNCH_TCB
10      8     MIN_LAUNCH_MIT_VECTOR
18      14    MIN_LAUNCH_ETCB_DEFINED_COMPONENTS
32      32    INIT_MA_REPORT_ID
```

All multi-byte integer fields in `MigrationDataV1` are encoded little-endian
on both source and destination. Implementations must not rely on native host
endianness.

This layout is the authoritative Version 1 profile and supersedes the Q165
`ArgSvnV1` projection layout. Q165 remains historical design rationale only.

Input validation:

```text
report version == 6
profile == VeniceV1
ETCB bits 255:112 == 0
all fourteen defined ETCB components decoded exactly
INIT_MA_REPORT_ID has expected length and identity semantics
unknown profile or layout version fails closed
```

First-migration initialization when `MIGRATION_DATA_VALID == 0`:

```text
ignore the existing 64 MIGRATION_DATA bytes

require:
    verified source tenant report version == 6
    source tenant LAUNCH_ETCB bits 255:112 == 0
    source_tenant.REPORT_ID_MA == verified_source_ma.REPORT_ID

initialize:
    MIN_LAUNCH_TCB =
        source_tenant.LAUNCH_TCB
    MIN_LAUNCH_MIT_VECTOR =
        source_tenant.LAUNCH_MIT_VECTOR
    MIN_LAUNCH_ETCB_DEFINED_COMPONENTS =
        source_tenant.LAUNCH_ETCB[111:0]
    INIT_MA_REPORT_ID =
        verified_source_ma.REPORT_ID
```

The invalid migration-data bytes are never parsed as `MigrationDataV1` and
are never interpreted as zero historical minima.

Subsequent-migration update rules when `MIGRATION_DATA_VALID == 1`:

```text
new_min_launch_tcb[i] =
    min(previous_min_launch_tcb[i],
        verified_report.launch_tcb[i])

new_min_launch_etcb[i] =
    min(previous_min_launch_etcb[i],
        verified_report.launch_etcb[i])

new_min_launch_mit_vector =
    previous_min_launch_mit_vector
    AND verified_report.launch_mit_vector

new_init_ma_report_id =
    previous_init_ma_report_id
```

The contributing values come from `LAUNCH_TCB`, `LAUNCH_ETCB`, and
`LAUNCH_MIT_VECTOR` in a successfully verified tenant attestation report.
Host-supplied desired launch values are not evidence.

`INIT_MA_REPORT_ID` immutability:

```text
first migration:
    establish INIT_MA_REPORT_ID from the authenticated source MA binding

subsequent migration:
    preserve all 32 bytes exactly
    reject any proposed replacement

planned handoff and recovery:
    preserve MIGRATION_DATA unchanged
    do not replace INIT_MA_REPORT_ID with the outgoing, incoming, replacement,
    or current MA REPORT_ID

installation:
    source and destination install byte-identical INIT_MA_REPORT_ID

initial-MA authorization:
    authorization.initial_ma_report_id ==
        MigrationDataV1.INIT_MA_REPORT_ID
```

Missing previously valid history, a changed identifier, source/destination
identifier disagreement, or authorization evidence naming another
`REPORT_ID` fails closed.

Additional policy:

```text
CURRENT_ETCB.ARG >= policy.minimum_arg_svn
```

The current ARG floor is an absolute policy check. It is separate from
historical launch-state aggregation. AMD supplies signed fields and firmware
rollback behavior; Microsoft defines the `MigrationDataV1` history rules.

Acceptance:

- exact fixed-size codec and typed component structures;
- decoding validates version, profile, exact length, reserved ETCB bits, and
  all fourteen defined ETCB components before exposing fields;
- encoding emits the canonical 64 bytes with no alternate `ArgSvnV1` form;
- first-migration codec vectors initialize `INIT_MA_REPORT_ID` only from the
  verified source tenant-to-MA binding;
- subsequent-migration codec vectors preserve all 32 identifier bytes;
- immutable `INIT_MA_REPORT_ID` across migration, planned handoff, and
  recovery;
- no historical minimum may increase;
- future nonzero reserved ETCB components require a new profile;
- golden vectors and malformed-profile tests pass.

### P0.4 implementation and frozen vectors

The [Venice codec and history helpers](../src/pal/src/snp/migration_data.rs)
encode TCB as `[FMC, TEE, SNP, zero[5]]` per Firmware ABI 1.59 section 2.3,
Table 3. Milan/Genoa and Turin TCB layouts must not be used for Venice.
ETCB component bytes are, in order:

```text
IP_KEY_MANAGER, MP1, ART_FMC, ART_RT, HAD_DRIVER, BOOT_DRIVER, PRE_ESID,
TMPM, MICROCODE, SOC_DRIVER, ASP_OS_DRIVER, FHP_DRIVER, DPE_DRIVER, ARG
```

Full report ETCB inputs are exactly 32 bytes; bytes 14-31 must be zero before
projection into the 14-byte history slot. All component values are unsigned
byte SVNs, not a single little-endian integer to compare. Mitigation vectors
are little-endian u64 values combined by bitwise AND.

The [tenant-policy descriptor](../src/pal/src/snp/tenant_policy_context.rs)
uses TCB profile `Venice = 0x03` with ETCB projection `VeniceV1 = 0x02`;
mixed old/new profile pairs and envelope/descriptor TCB disagreements fail.
Historical 16-byte descriptors retain their original allocations, but the
64-byte history codec accepts only version `0x01`, profile `0x03`. There is
no alternate `ArgSvnV1` history encoding. The legacy `SnpMigPolicy` 64-byte
emulator policy body is a different record and must not be reinterpreted as
this history.

Independent Python `struct`/`hashlib` vectors, reproduced by Rust tests:

```text
First migration:
  launch TCB = [9, 2, 11]
  launch mitigation = 0xf0f0ccccaaaa5555
  launch ETCB = [20, 21, ..., 33]
  authenticated source MA REPORT_ID = [0x80, 0x81, ..., 0x9f]
  MIGRATION_DATA_VALID = 0; opaque previous bytes ignored
  encoded[64] =
  010309020b00000000005555aaaaccccf0f01415161718191a1b1c1d1e1f2021808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
  SHA384 =
  d69a703a75c0acf4959fc952e18ee5328c5f78ef0a036f4efbf571598a7926e6d984aa2f9f305c8bd1f434ac62afe0e4

Subsequent migration:
  launch TCB = [8, 9, 10]
  launch mitigation = 0xccccf0f0ffff0f0f
  launch ETCB[i] = 10+i for even i; 40+i for odd i
  result TCB = [8, 2, 10]; original initial-MA identity retained
  encoded[64] =
  010308020a00000000000505aaaac0c0c0c00a150c170e19101b121d141f1621808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
  SHA384 =
  16e243fc1d85e72d417bbccdff5b50be403550489fea90da46c785bf986ae9b412f3e8b817e3dcc981f14c3791117f9f

Higher later launch:
  all defined launch SVNs = 255; mitigation = 0xffffffffffffffff
  encoded history and digest remain identical to the subsequent vector.

Zero later launch:
  defined launch SVNs and mitigation = zero; original identity retained
  encoded[64] =
  0103000000000000000000000000000000000000000000000000000000000000808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
  SHA384 =
  9cd1411b29f9aae117caa6c74b1c3cd0d95bcea88ea1fd21a41cad159cbc5a31314d947112d86cc81c052a8516832682
```

### P0.4 mandatory downstream qualification gates

Logical-input validation is not cryptographic report authentication. The
caller must supply authenticated report fields, the verified source MA ID,
and the signed validity flag/history. These helpers neither extract the
conflicting raw Version 6 fields nor implement replay storage, firmware
installation, or runtime handoff/recovery.

| Owning milestone | Required closure before that milestone can pass |
|---|---|
| P0.12A / Task 4 / AAS1A-M | Reconcile the existing four-field common TCB sketch with Venice's FMC/TEE/SNP representation; verify exact family-aware mapping. Do not silently call FMC a boot loader or invent a microcode claim. Feed history only from authenticated logical claims. |
| Task 6 / AAS1A-M | Signed Version 6/supplement fixtures authenticate launch/history fields, validity flag and tenant-to-MA binding; malformed reserved fields and old profiles fail. Pure codec vectors are not signed-provider qualification. |
| Task 9 | Wire this codec and transition logic into destination computation/source reconstruction; apply CURRENT_ETCB ARG floor separately from LAUNCH history; reject missing/changed history and identity. |
| Tasks 11-12 | Validate canonical accepted history before installation or purpose-0x03 generation; install and reattest the exact same 64 bytes on both sides, including all 32 initial-MA ID bytes. |
| R4.3 / R4.5 / R4.7 | Verify authoritative persisted history is unchanged across actual planned handoff, recovery, partial results, retries and restart; unit-level equality checks are insufficient. |
| H5.0 / H5.5 / H5.7 | Resolve the AMD physical-layout blocker; qualify real firmware parsing, installation, immutable history and hardware recovery. |

These are mandatory deferred executable gates, not waived acceptance criteria.
P0.4 contract acceptance does not claim that they passed.

## P0.5 Freeze host-push tenant evidence and identity lifecycle

Status: DONE - SHARED CONTRACT CONFORMANCE ACCEPTED; mandatory later
qualification gates remain open.

Accepted freeze: `P0.5-HostPushIdentityV1-2026-11-02`.
User acceptance: 2026-11-02T22:14:01Z; no conditions. Acceptance covers the
shared logical contract and current-verifier bridge, not later runtime/provider,
durable replay, production layout or hardware qualification.
Validation: default PAL 9 tests; Azure PAL 159 and TAV PAL 158 tests;
7 snp_emu tests per backend; 3 compile-fail identity/provenance doctests;
9 focused MigTD SNP tests; formatting, focused Clippy, default TDX compilation,
release-musl build, and legacy Stage A/B passed. Fourteen new unit tests cover
the shared contract and current verifier bridge. Existing warnings remain;
no warning remains in the P0.5 implementation. These results establish contract
conformance and legacy preservation, not signed live-Version-6, runtime-provider,
durable replay, production layout or hardware qualification.
Evidence and exact commands: `doc/implementation_record.log`, P0.5 VALIDATION;
raw local output: `target/p0.5-validation/20261102T220436Z/`.

Version 1 acquisition:

```text
BASE obtains a tenant report using SNP_HV_REPORT_REQ.
BASE creates PrepareMigrationRequest.
The request includes the report or an authenticated report reference.
The MA verifies the report before using its identity or fields.
```

There is no Version 1 MA-pull acquisition operation.

Identity states:

```text
ProvisionalTenantIdentity:
    host-routed identity used only for lookup and correlation

VerifiedTenantIdentity:
    REPORT_ID from a cryptographically verified tenant report
```

Rules:

- provisional identity cannot authorize migration;
- commitments, authorization, KDF, installation, and history use verified
  identity;
- BASE owns managed-handle-to-GCTX mapping;
- report delivery and request correlation are explicit and idempotent.

### P0.5 shared logical contract and conformance boundary

The user approved the inline report / SHA-384 cache-reference choice with no
conditions. No host-control opcode, transport framing, role renumbering, or
firmware acquisition interface is introduced here.

The shared `pal::tenant_identity` types are available without emulator features:

- `ProvisionalTenantIdentity` wraps the existing `ManagedGuestHandle` for routing
  only. The request derives it from `SnpOperationContext`; it cannot contain a
  second, conflicting handle or be passed as a verified identity.
- `VerifiedTenantIdentity` has no public raw-ID constructor. The existing
  `VerifiedTenantReportIdV1` is an alias of this same type, preserving P0.3
  canonical tenant-set and purpose-binding consumers rather than duplicating
  identity mechanisms. Transport codecs remain byte representations, not
  authority to construct verified identities or authorize migration.
- `PrepareMigrationRequestV1` reuses the complete existing `SnpOperationContext`:
  request ID, migration ID, source/destination role, managed handle, and optional
  peer, protocol and policy references. These routing references are not
  authenticated policy digests or firmware-proven handle-to-report mappings.
- Delivery is either an owned, exact 1184-byte base-report snapshot or a
  `TenantReportReferenceV1` containing `SHA384(exact_base_report_bytes)`.
  The reference is untrusted until the matching report passes cryptographic
  verification. A cache miss, digest mismatch, malformed length, or cache input
  accompanying an inline report returns an explicit typed error. No resolver
  callback, MA-pull provider, network operation or firmware command is invoked.
- The current SNP bridge enforces Version 6, host-requested VMPL `0xffffffff`,
  all 64 REPORT_DATA bytes zero, and locally selected verifier/trust before
  extracting REPORT_ID at `0x140..0x15f`. It rejects captured-fixture promotion
  and inconsistent verifier trust/binding metadata. Raw fields are not exposed
  as authenticated claims by the delivery wrapper.
- `VerifiedTenantReportDeliveryV1` privately couples the verified identity,
  exact report digest, complete operation context and verifier trust selection.
  `TenantReportCorrelationV1` accepts one such delivery, reports an exact
  redelivery as `IdempotentRetry`, and rejects changed identity, report bytes,
  trust or any operation field without replacing accepted state. Inline and
  matching cache-reference delivery are equivalent. Acceptance of a delivery is
  not migration authorization, key installation, or replay-journal commitment.

Independent SHA-384 reference vector: an otherwise-zero 1184-byte mock report
with Version 6, VMPL `0xffffffff`, and REPORT_ID `42` repeated 32 times yields:

```text
732aaa1ffd34613dfc2e2b9d1004d5aac713adb8c81d7188a9f69e9c5c2a7033
857d73ca5b354bc436860590991c1eb7
```

This is a digest/contract vector, not a signed Version 6 provider fixture.

### P0.5 mandatory downstream qualification gates

| Owning milestone | Required closure; not satisfied by P0.5 unit tests |
|---|---|
| P0.6 / Task 3 addendum | Bind the complete canonical verified tenant evidence to fresh MA evidence, TH1, request/roles and policy; enforce tenant-to-MA binding and durable replay/terminal-state rules. The base-report cache digest is not a substitute for this complete-evidence/session binding. |
| T4.9 / T4.12 | Finalize provider and host-control request/response/framing; wire these shared identity types and correlation semantics into acquisition, cache ownership, cancel/abort/status and active runtime. Retain one operation slot across retries; do not reconstruct an empty slot to bypass conflict detection. No MA-pull operation. |
| P0.12A / AAS1A-M / Task 6 | Adapt final common verified claims and complete evidence profiles. Authenticate the separately signed emulator supplement and bind it into full evidence/session/retry correlation; a reference to the base report authenticates no supplement claim. Qualify signed Version 6 vectors and production layout failure. |
| Tasks 7-12 | Admit only the verified identity into active commitments, authorization, KDF, installation and history; enforce source-MA binding and policy in addition to cryptographic identity extraction. Bare decoded REPORT_ID arrays and provisional handles are not authorization tokens. |
| H5.1 / H5.7 | Implement BASE SNP_HV_REPORT_REQ acquisition, managed-handle/GCTX mapping, real delivery/cache lifecycle and production/hardware request/retry outcomes. Any required OHCL integration is owned here, not claimed implemented or unnecessary by P0.5. |

## P0.6 Freeze zero-bound tenant-report operation binding

Active supersession: use the325-byte V2 authorization and purposes6/7 in
[T4.14-PRE](snp/task4/t4.14-pre-direct-random.md), not commitment fields or
the421-byte V1 preimage. Tenant/source-MA association, both-role proof
requirements and durable replay/current-state rules remain. The V1 acceptance
and validation record below is historical, not replacement validation.

Status: DONE - ACCEPTED CONTRACT/CONTROL-FLOW CONFORMANCE; later qualification gates remain mandatory.

Accepted freeze: `P0.6-ZeroBoundReplayV1-2026-11-02`.

Accepted at `2026-11-02T22:51:53Z`. User disposition: "Accept and freeze P0.6
contract/control-flow conformance; retain later qualification gates".
Conditions: None. This acceptance does not qualify production persistence,
independent rollback anchors, signed composite evidence, active protocol,
real restart/firmware recovery or hardware.
Validation: default PAL 25 tests and 5 compile-fail doctests; Azure PAL 185
and TAV PAL 184 tests, each with 7 snp_emu tests and 6 compile-fail doctests;
9 focused MigTD SNP tests; independent Python vectors; formatting, focused
Clippy, default TDX compilation, release-musl build and legacy Stage A/B passed.
Twenty-six unit tests and three compile-fail tests were added. Existing
warnings remain; no new warning remains in the P0.6 implementation.
These results qualify contracts/control flow and legacy preservation, not
physical persistence, real restart recovery, signed composite claims, active
protocol/provider deployment or hardware. Exact commands and evidence hashes
are recorded centrally in `doc/implementation_record.log`; final evidence is
under `target/p0.6-validation/20261102T221846Z/final/`.

Mandatory P0.5 closure: the local base-report cache reference and correlation
slot are not complete-evidence/session binding, durable replay protection, or
permission to retry after terminal outcomes. Bind all authenticated evidence
components, including the emulator supplement where applicable.

The host-requested tenant report has:

```text
REPORT_DATA = zero[64]
binding_classification = HostRequestedZeroReportData
```

Compute a canonical digest of the complete verified tenant report and bind it
into fresh session-bound MA evidence and the authorization context with:

```text
TH1
request_id
source and destination roles
verified tenant REPORT_ID
canonical tenant-report digest
policy identity
```

Cryptographic tenant-report verification and extraction of its verified
`REPORT_ID` precede contribution commitments and purpose-`0x01` MA evidence.
Tenant-to-MA correlation is checked after the source MA evidence is
authenticated. Purpose-`0x02` tenant-authorization MA evidence then attests the
tenant-report digest and authorization context. Both peers must acquire,
exchange, and verify that evidence before accepting tenant authorization.
The Task 3 addendum must freeze the report/reference delivery, correlation,
and purpose-`0x02` evidence exchange using these existing purpose semantics.

Required security behavior:

- reject tenant substitution;
- reject use with another request, role, session, or policy;
- persist a durable replay journal binding report digest, tenant, request,
  operation state, and terminal outcome;
- permit only protocol-defined idempotent retry for the same recorded
  operation;
- reject conflicting reuse, rollback of replay state, and reuse after a
  terminal outcome;
- validate current firmware identity, binding, and lifecycle state before
  authorizing migration;
- never claim the zero-bound report is itself session-bound.

Accepted Version 1 policy:

```text
First-use freshness of the tenant report is not required.
The protocol uses bounded replay with durable trusted state.
Session binding comes from fresh MA evidence over the tenant-report digest.
```

Phase 5 must qualify replay-journal persistence, rollback resistance,
idempotent retry, firmware-state revalidation, cleanup, and recovery. It does
not need to add caller-selected data to the tenant report.

### P0.6 implementation contract and scope

The accepted design choices are domain-separated complete-evidence/authorization
digests and a fail-closed durable-store contract. The user additionally approved
pinning both existing purpose-1 commitments. The bootstrap form was accepted
without override: both BASE requests carry the same source tenant evidence or
its already-pushed local reference before purpose 1. This avoids depending on
the later purpose-2 tenant record for initial identity verification.

Exact byte layouts, bootstrap delivery, existing-opcode purpose-2 ordering and
replay semantics are recorded in the current P0.6 section of the
[Task 3 addendum](snp/task4/p0.5-contribution-wire-addendum.md#current-p06-host-push-authorization-and-replay-addendum-2026-11-02).
The historical numbering in that file is not the current phase status.

Implemented surfaces:

- `pal::tenant_identity` verified receipts now retain authenticated REPORT_ID_MA
  and the canonical complete-evidence digest in addition to the unchanged P0.5
  base-report cache digest. All are extracted/derived after verification.
- `pal::snp::tenant_authorization` hashes the complete 1223-byte raw or 1539-byte
  emulator-input preimage. Its 421-byte authorization context includes request,
  version/algorithm, both roles, tenant ID, complete digest, TH1, both MA IDs,
  both MA/policy digests and both already-attested commitment digests.
- Cryptographic purpose-1 MA proofs gate tenant-to-source-MA correlation.
  Exactly one verified source and destination purpose-2 proof, matching the
  independently reconstructed full 64-byte REPORT_DATA and existing MA IDs,
  is required to construct the reciprocal authorization capability.
- The default-feature shared replay controller implements bounded
  Reserved/Authorized/Terminal transitions through an atomic trusted-store
  boundary. It pins the whole local operation, forbids conflicting report or
  request reuse and active-tenant forks, retains terminal outcomes, checks
  monotonic snapshots/readback and blocks ambiguous commit failures.
  It invokes current firmware validation on every authorization/retry.
- Missing durable storage or current-firmware providers return explicit errors.
  No production persistence backend, anchor, firmware query, kernel change,
  protocol activation, allowlist authorization or migration readiness is claimed.
  Hashing a supplement does not authenticate it; the current bridge promotes
  verified receipts only for raw reports.

Independent mock-input SHA-384 vectors:

```text
raw evidence, 1223 bytes:
788d3a6487ccce4313d85ca043911b1faf6f43656568398e2078969781157c12b
47c361b5e79b24667e1bc90f61f19bd
emulator evidence, 1539 bytes:
97470f8e891fdc2aa0b0ae66a667a4f9d1007c631a2712a4ce509bd72370ef19
043d4b03c7827957072bc9f2bd7b0e46
authorization context, 421 bytes:
45e7c0798149a61921f87a87d868236aad002a66557132577ca88c1b4dbff5d0
afdea7627cd056a3058609e173d40b97
```

These are fingerprint/binding vectors, not signed Version 6 fixtures.
Exact vector inputs and commands are retained with the centralized execution
record and local evidence under `target/p0.6-validation/20261102T221846Z/`.

### P0.6 mandatory downstream qualification gates

| Owning milestone | Required closure; not satisfied by mock stores/verifiers |
|---|---|
| P0.11 / T4.9 / T4.12 | Final provider/framing and complete-profile transport; both BASE requests carry the same complete source evidence before purpose 1; keep purpose-1/2 states distinct and preserve full local correlation. |
| P0.12A / AAS1A-M / Task 6 | Authenticate all signed supplement components before creating composite verified receipts; preserve digest encoding and expected trust/layout provenance; qualify real Version 6/role/identity/report-data vectors. |
| Tasks 7-10 | Wire verified tenant identity before contribution generation, actual fresh SPDM TH1, full MA/policy approval, both purpose-2 checks and exact authorization-result digest; these helpers do not implement policy, commitment preimages or KDF. |
| Tasks 8 / 11-13 | Select a real durable/anchored store and role-aware authoritative firmware-state provider; commit state before publishing authorization/effects, persist actual terminal results and test partial/ambiguous outcomes without repeated workflow effects. |
| Phase 4 / H5.4 / H5.7 | Preserve the stable replay namespace/tombstones/anchor across restart, planned handoff and recovery; qualify crash atomicity, sealing, rollback resistance, capacity/retention/cleanup and current firmware state on actual platforms. No memory/file fallback satisfies this gate. |
| H5.0 / H5.1 | Resolve physical report-layout blockers and implement actual BASE propagation, cache lifecycle, managed-handle/GCTX mapping and production delivery. No claim is made that OHCL kernel work is unnecessary. |

## P0.7 Freeze secret-contribution key establishment

HISTORICAL V1 SECRET CONTRACT: superseded for active use by
[T4.14-PRE](snp/task4/t4.14-pre-direct-random.md). The selected protocol uses
one source-generated random32 MSK and protected acceptance, with no bilateral
contribution or commitment verifier. Historical implementation is test-only.
The acceptance/results below remain true for their original bounded scope.

Status: DONE - ACCEPTED WIRE/STATE CONTRACT CONFORMANCE; commitment/runtime qualification gates remain mandatory.

Accepted freeze: `P0.7-ContributionWireStateV1-2026-11-02`.

Accepted at `2026-11-02T23:32:11Z`. User disposition: "Accept and freeze P0.7
wire/state conformance; retain commitment/runtime qualification gates".
Conditions: None. This acceptance does not qualify the missing commitment
construction, randomness, live SPDM contribution exchange, policy/durable
admission, KDF, confirmation, installation, restart or hardware.

The user approved wire/state conformance with commitment cryptography gated
on the authoritative Task 2 formula. The historical Task 3 addendum records
that formula as unavailable locally. No new commitment construction is
invented here. This scope does not activate contribution exchange or derive
keys.

Version 1 uses secret contributions, not ECDH.

Define `SnpKeyContributionV1` using the frozen Task 3 ranges:

```text
opcodes      0x26-0x2F
element type 0x0104-0x010F
```

The record binds:

```text
record version and type
request_id
role
negotiated migration version
algorithm
verified tenant identity or session-context reference
32-byte secret contribution
48-byte attested commitment or exact commitment reference
reserved fields = zero
```

Rules:

- exchange only inside authenticated encrypted inter-node SPDM;
- exactly one source and one destination contribution;
- reject wrong commitment, role, request, tenant, session, duplicate, replay,
  and reordering;
- zeroize decoded secret buffers after derivation or failure.

### P0.7 implementation and mandatory downstream gates

The existing explicit 272-byte `SnpKeyContributionV1` codec, record type
`0x0005`, source request `0x26`, destination response `0x27`, element
`0x0104`, and 282-byte application envelope are preserved unchanged.
The exact 220-byte purpose-1 context carries the full commitment reference.

`contribution_exchange::ContributionExchangeV1` starts only with the exact
P0.6 reciprocal purpose-2 proof matching the complete local replay binding,
not merely an equal authorization digest. It compares each complete
contribution context against that role's verified purpose-1 context, then
requires the trusted commitment verifier to check the actual secret.
The logical transcript is source request followed by destination response,
exactly once each; it includes both local and remote messages, not just
incoming network messages. Any codec/context/commitment/order error aborts
the instance, erases its retained secrets, and prevents resumption.
Payload decoding erases the supplied bytes on success and failure.
Completion yields a private, non-cloneable pair consumed once in fixed
source/destination order; this is neither a key nor installation permission.
Timeout, cancellation and session loss require abort/drop; callers remain
responsible for transport copies and consumer-created secret/derived copies.

`UnavailableContributionCommitmentVerifierV1` returns an explicit unavailable
error mapped to the existing `InternalError`, never success. Commitment
mismatch maps to `ReportDataBindingFailed`; structural/context/state errors
use existing statuses. There is no new wire status, provider fallback,
commitment algorithm, randomness provider, KDF or runtime dispatch.

Conformance includes independent Python struct/hashlib wire vectors and
15 new unit tests plus 3 compile-fail tests. The positive state tests use an
explicitly test-only secret oracle, not cryptographic commitment validation.
Raw evidence is under `target/p0.7-validation/20261102T232017Z/`; final
commands, outcomes and fingerprints are recorded in the central execution log.

Final validation: default PAL 25 unit tests and 5 compile-fail doctests;
Azure PAL 200 and TAV PAL 199 unit tests, each with 7 snp_emu tests and
9 compile-fail doctests; focused MigTD SNP 9 tests. Formatting, focused
Clippy (existing warnings only), default TDX compilation, release-musl build
and sequential legacy Stage A/B passed. Final evidence is in the `final/`
subdirectory. These regressions do not exercise an activated contribution
protocol, and no full repository CI or hardware qualification is claimed.

| Owning milestone | Required closure; not satisfied by this conformance implementation |
|---|---|
| P0.10 | Reconcile the authoritative Task 2 commitment construction and independently verify source/destination commitments, KDF and confirmation vectors. Wire hashes and the test oracle are not substitutes; full cryptographic-vector acceptance remains gated. |
| Task 7 | Use the authoritative commitment construction and a qualified randomness provider for fresh local contributions before purpose-1 evidence. Admit only verified tenant identities; retain approved MA/policy, session and trust provenance. |
| Tasks 8-10 / T4.12 | Require actual policy/history approval and durable replay admission in the current authenticated encrypted inter-node SPDM session. Map trusted opcode to direction; preserve logical local/remote ordering and full local operation correlation. Prevent reuse across controller instances/restarts; this controller is operation-local, not a durable replay journal. |
| Task 10 | Select the qualified commitment verifier; implement canonical KDF context, derivation and P0.8 reciprocal confirmation. On rejection, timeout, cancellation, disconnect or failure erase all transport, contribution and derived copies. Do not retry with old secrets or recreate a controller to bypass a terminal replay decision. |
| Tasks 11-13 / H5 | Retain actual installation/persistence, crash/recovery and hardware qualification. No P0.7 pair or model test proves these effects. |

## P0.8 Freeze reciprocal confirmation and installation result

HISTORICAL V1 CONFIRMATION CONTRACT: application HMAC confirmation is removed
from the active protocol by [T4.14-PRE](snp/task4/t4.14-pre-direct-random.md).
Protected acceptance is not key-possession proof; both correlated firmware
outcomes remain mandatory. Fresh persisted-state purpose3 remains deferred.
The V1 acceptance, codecs and state tests below remain historical only.

Status: DONE - ACCEPTED RECORD/STATE CONTRACT CONFORMANCE; crypto, persistence and SPDM scheduling gates remain mandatory.

Accepted freeze: `P0.8-ConfirmationResultV1-2026-11-02`.

Accepted at `2026-11-02T23:50:26Z`. User disposition: "Accept and freeze P0.8
record/state conformance; retain crypto, persistence and SPDM scheduling gates".
Conditions: None. This acceptance does not qualify HMAC/KDF, real persisted
evidence verification, active SPDM exchange, installation, readiness, restart
or hardware.

The user approved record/state conformance while retaining authoritative
Task 2 cryptography, persisted-state verification and actual SPDM scheduling
as mandatory later gates. No live confirmation or installation is activated.

Define:

```text
destination confirmation tag
source confirmation tag
destination installation result
```

Each record binds:

```text
request_id
role and direction
canonical session-context digest
typed status
48-byte HMAC-SHA384 tag where applicable
```

Required ordering:

```text
destination tag
source tag
destination installation result
```

### P0.8 exact record and state contract

The current Task 3 addendum contains exact byte layouts and independent
record vectors. New registry allocations are additive:

| Record | Record type | Element | Bytes | Single-element envelope |
|---|---|---|---|---|
| `SnpConfirmationV1`, both roles | `0x0006` | `0x0105` | 128 | 138 |
| `SnpInstallationResultV1`, destination only | `0x0007` | `0x0106` | 136 | 146 |

No new VDM opcode is allocated or activated; `0x28..0x2F` remains available
for the final request/response design. Existing opcodes cannot carry these
elements. SPDM polling, acknowledgements, post-install evidence verification
and typed-result delivery must be reconciled before runtime activation; do
not assume three logical records can be sent as unsolicited SPDM responses.
Existing allocations/layouts and the 8,192-byte cap are unchanged.

Both records bind request ID, exact sender role/direction and a 48-byte
canonical **session-context** digest. This is not the P0.6 authorization digest;
Task 10 must reconstruct it from trusted local inputs under the authoritative
Task 2 recipe. Repeating a peer-supplied digest authenticates nothing.
Confirmation status is `Confirmed = 1` or `Rejected = 2`; the 48-byte field is
an HMAC-SHA384 tag for confirmation, and exactly zero for rejection.
Role 0 sends source-to-destination direction 0; role 1 sends
destination-to-source direction 1. Local handoff roles are illegal here.

Installation outcomes are `Succeeded = 1`, `Failed = 2`, `Aborted = 3`,
`Indeterminate = 4`. Success requires an observed raw firmware status
`Some(0)` and the existing P0.3 installation-result digest from verified actual
persisted state. Failed requires an observed nonzero raw status. Aborted
requires no raw status and means known no installation effect; unknown or
partial effects must be classified Indeterminate. Indeterminate may retain
an observed status, including zero, without claiming persistence or readiness.
An explicit presence byte distinguishes absent status from observed zero;
absent raw bytes and non-success result digests are canonical zero.
All reserved bytes must be zero; unknown enums/versions, role/direction
mismatch, truncation and trailing bytes are rejected.

The operation-local `SnpConfirmationSequenceV1` enforces:

```text
destination tag verified
 -> source tag verified
 -> persisted-state evidence verified (existing P0.3 result digest retained)
 -> matching typed success result
 -> private destination-result receipt
```

Success cannot trigger evidence verification after the fact. The provider
must authenticate the fresh purpose-3 evidence and actual accepted history
in the separate preceding transition, before the typed result is admitted.
Negative installation results can terminate any nonterminal stage without
waiting for success-only evidence. They retain typed outcome and optional raw
status for diagnostics, return an explicit error and never yield a success
receipt. All rejection/order/verification failures abort without resumption.
Duplicate results do not overwrite or reverify the recorded terminal outcome.
The receipt is not source-side installation or permission to report readiness.

The sole supplied non-test confirmation and persistence verifiers return
explicit unavailable errors. Positive state tests use labeled test-only
oracles, not HMAC verification, firmware I/O or signed post-install evidence.
No key material is owned/derived by this helper; runtime must invalidate
sessions and clear provider-owned confirmation keys on abort/cancellation.
Raw evidence is under `target/p0.8-validation/20261102T233410Z/`; final
commands, counts and fingerprints are recorded in the central execution log.

Final validation: 26 new unit tests (25 PAL, 1 MigTD) and 2 new compile-fail
tests. Default PAL 25 unit/5 compile-fail; Azure PAL 225 and TAV PAL 224 unit
tests, each with 7 snp_emu tests and 11 compile-fail doctests; focused MigTD
SNP 10 tests passed. Formatting, PAL/emulator and MigTD Clippy (existing
warnings only), default TDX compilation, release-musl build and sequential
legacy Stage A/B passed. Final evidence is the `final/` subdirectory.
These are record/state and legacy regressions, not activated confirmation,
KDF, signed persisted-state verification, full CI or hardware qualification.

| Owning milestone | Required closure; not satisfied by record/state conformance |
|---|---|
| P0.10 / Task 10 | Reconcile authoritative session-context/HMAC/KDF preimages, direction-specific PRK-derived keys and labels; independently verify real tags. Opaque tag bytes and wire hashes are not crypto vectors. |
| P0.11 / T4.12 / Tasks 10-12 | Coordinate registry allocations without mixing local handoff and inter-node protocols; freeze actual authenticated encrypted SPDM request/response scheduling, evidence-verification acknowledgement and result delivery. Add opcode mappings/static validation before activation. |
| Tasks 8-11 | Enforce actual policy/history, durable replay admission and qualified P0.7 exchange/KDF before confirmation. No local transcript recreation may bypass terminal decisions or authorize firmware installation. |
| Task 12 | Supply a real fresh purpose-3 verifier for the same tenant/destination MA/session and exact accepted persisted history; reuse P0.3 result digest, verify before typed success, and confirm both role-specific installations before readiness. |
| Task 13 / H5 | Qualify duplicate/reordered tags/results, failure reporting, timeout/session loss, partial/indeterminate effects, effects-once recovery, provider key cleanup, restart and hardware. No file/model or local installer return substitutes for verified persistence. |

## P0.9 Freeze trust and policy contracts

Status: DONE - ACCEPTED BOUNDED CONTRACT/FIXTURE, CONSUMER AND TRACKING SCOPE.

Ordered-release extension: ACCEPTED AND FROZEN for bounded contract/fixture conformance under the 2026-11-03 user instruction
to implement P0.9A2/B2/C2 as a custom signed, intended-production SNP contract
with explicit fixture-key tests. Production deployment approval, provisioning,
real trusted providers and hardware qualification remain separate gates.

Accepted on 2026-11-03T04:21:50Z; conditions: None.
Freeze identifier: `P0.9-FixedReleaseCollateralV1-2026-11-03`.
At fixed-release acceptance the user retained external-provider, production
and tracking gates. The E section below records the subsequently selected
tracker/owner; no production qualification or Phase 0 gate closure follows.

Execution scope approved on 2026-11-03: implement exact fixed-release contracts
and verification using explicit trusted-provider boundaries. The approved
Microsoft closed policy schema, provisioned authorization PKI, trusted time
and qualified durable store are not supplied by test fixtures. Missing
providers fail closed; production authorization remains explicitly unavailable.
Execution, validation and explicit user acceptance are recorded in
[implementation_record.log](implementation_record.log).

Implemented and validated scope:

| Gate | Accepted result | Remaining boundary |
|---|---|---|
| P0.9A1 | Exact identity/allowlist codecs and frozen hashes/signing spans | Existing frozen bytes unchanged |
| P0.9B1 | Current Venice component/mitigation floors, exact identity and role/session-bound pair admission | No firmware recovery/history/readiness substitution |
| P0.9C1 | Real allowlist P-384 signatures and sealed verification results; trusted schema/PKI/time/store boundaries and atomic sequence control flow | Approved schema, real PKI/time/durable deployment providers remain unqualified and unavailable by default |
| P0.9D | Fixed/ordered consumer contracts accepted and frozen below | Tasks 7/8/9 and later consumers must wire and qualify runtime admission |
| P0.9E | Repository-ledger tracking accepted and frozen; PA-001-PA-011 assigned to @mvasantarao for tracking | Production qualification, external technical approval and repository publication remain open |

Validation: 25 new unit tests and two compile-fail tests; full Azure PAL
250 + emulator 7 + PAL doctests 13, TAV PAL 249 + emulator 7 + PAL doctests 13,
default PAL 25 + doctests 5, and MigTD SNP tests 10 passed. Targeted format,
PAL/emulator and MigTD Clippy, default TDX check, release-musl build and
sequential legacy Stage A/B passed with existing warnings only.
Independent Python digest vectors agree with Rust. Existing P0.7/P0.8 wire
sources and the exact 37-step sequence remain unchanged.
Evidence: `target/p0.9-validation/20261103T040914Z/`; exact commands and
qualification boundaries are recorded centrally. Legacy Stage A/B does not
activate the new policy admission path. No full CI/hardware qualification is
claimed.

P0.9 uses one MA/Policy identity and collateral model, organized like MigTD
TDX `policy_v2`: signed migration policy, identity authorization, security-
version mapping where applicable, and verified collateral consumed by policy
evaluation. Identity approval and release ranking are responsibilities within
that model, not competing identity systems.

The planned logical entity names follow the existing
[TDX collateral types](../src/policy/src/v2/servtd_collateral.rs):

| TDX entity | SNP entity | Responsibility |
|---|---|---|
| `ServtdCollateral` | `MaPolicyCollateral` | Bundle identity authorization, applicable release mapping and issuer/lifecycle inputs |
| `TdIdentity` | `MaPolicyIdentity` | Authorize the canonical MA/Policy identity and describe applicable release status/validity |
| `TdTcbMapping` | `MaPolicyTcbMapping` | Map `MA_POLICY_IDENTITY_DIGEST` to issuer-approved combined MA/Policy SVN |
| `VerifiedServtdCollateral` | `VerifiedMaPolicyCollateral` | Profile-specific verified result, consumed alongside signed policy |

These are logical responsibilities, not a requirement for duplicate signed
documents. [ma_policy.rs](../src/pal/src/snp/ma_policy.rs) defines a typed
`MaPolicyCollateral` bundle with fixed and ordered variants.
[ordered_collateral.rs](../src/pal/src/snp/ordered_collateral.rs) implements
`MaPolicyTcbMapping` inside a signed publisher snapshot. The fixed adapter
`MaPolicyIdentity` remains the allowlist authorization component;
`MaPolicyIdentityInputV1` below remains the exact input used to compute the
identity it authorizes. Naming the two responsibilities does not create two
different MA/Policy fingerprints.

As in [TDX VerifiedPolicy](../src/policy/src/v2/policy.rs), verify policy and
the required collateral signatures before evaluation, then retain verified
policy/collateral for authentication as
[MigTD policy initialization](../src/migtd/src/mig_policy.rs) does.
Tasks 7 and 9 consume those verified results rather than host-supplied
identity/approval metadata.

The model has two explicitly separated authorization profiles:

| Profile | Identity authorization | Security-version mapping | Execution scope |
|---|---|---|---|
| `FixedReleaseV1` | Existing signed `FixedReleaseAllowlistV1`, adapted into `MaPolicyIdentity`; exact selected-identity equality | Not present; no invented SVN or dormant ordering fields | Inter-node emulator and same-release handoff |
| `OrderedReleaseV1` | Custom signed `MaReleaseEndorsementV1` publisher snapshot | Required authenticated `MaPolicyTcbMapping` entries in that same snapshot | Fixture-backed cross-release contract tests now; deployment approval and qualification later |

`VerifiedMaPolicyCollateral` must distinguish the profiles explicitly: the
fixed variant carries verified exact-identity approval; the ordered variant
also requires a verified release mapping. Missing ordered-profile mapping
fails closed, not as SVN zero or an implicit fixed-profile fallback.
The exact 280-byte identity, canonical semantic-policy digest and 320-byte
fixed allowlist remain unchanged. Ordered production records are separately
versioned; bundle packaging does not silently reinterpret either profile.

Structural alignment does not make TDX and SNP report fields, wildcard rules,
trust anchors, PKI purposes or crypto providers interchangeable. Preserve TDX
`no_std` and SNP userspace/provider boundaries; no TDX runtime refactor is
required. SNP tenant-to-MA binding, Venice history/ETCB, initial-MA continuity,
durable replay and fresh purpose-specific report binding remain explicit.

This organization implements the architectural direction
`SNP-TdxPolicyAlignment-2026-11-03` inline. The later custom signed SNP v1
contract below is the intended-production format with bounded acceptance
recorded; separate deployment qualification remains required. No CoRIM conversion is required.
P0.9 completes for the emulator when P0.9A1,
P0.9B1, P0.9C1, P0.9D, and P0.9E are accepted. P0.9A2, P0.9B2, and P0.9C2
remain named production gates and do not block the fixed-release emulator.

### P0.9A1 `FixedReleaseV1` MA/Policy identity and signed allowlist

Status: APPROVED AND FROZEN on 2026-11-01

Freeze identifier: `P0.9A1-FixedReleaseV1-2026-11-01`

Define one canonical combined MA/Policy identity from authenticated Version 6
MA evidence. Both authorization profiles use this fingerprint.
Within `MaPolicyCollateral`, the fixed-profile `MaPolicyIdentity` component
is represented by the existing signed `FixedReleaseAllowlistV1`, not a second
identity certificate or an extra approval document.
The adapter exposes verified approval without changing either frozen encoding.

The exact identity input is:

```text
MaPolicyIdentityInputV1 = 280 bytes

Offset  Size  Encoding
0x000     2   FORMAT_VERSION = 1, u16le
0x002     2   PROFILE = 1 (FixedReleaseV1), u16le
0x004     4   SNP report version, u32le
0x008     4   IDENTITY_FLAGS = 0, u32le; all bits reserved in Version 1
0x00c    48   MEASUREMENT
0x03c     4   GUEST_SVN, u32le
0x040    16   FAMILY_ID
0x050    16   IMAGE_ID
0x060    48   ID_KEY_DIGEST
0x090    48   AUTHOR_KEY_DIGEST
0x0c0    32   HOST_DATA
0x0e0     8   SNP guest POLICY, u64le
0x0e8    48   LM_POLICY_DIGEST

canonical_policy =
    RFC 8785 JCS encoding of the approved Microsoft LM-policy semantic JSON
    object

The semantic policy schema is closed: unknown fields fail. It excludes
signatures, certificate chains, transport envelopes, publication timestamps,
audit annotations, and other non-policy metadata.

LM_POLICY_DIGEST =
    SHA384(
        "SNP-LM-POLICY-v1" ||
        u32le(length(canonical_policy)) ||
        canonical_policy
    )

MA_POLICY_IDENTITY_DIGEST =
    SHA384(
        "SNP-MA-POLICY-IDENTITY-v1" ||
        exact MaPolicyIdentityInputV1[280]
    )
```

The domain-separation strings are the displayed ASCII bytes without a trailing
NUL. `HOST_DATA` is part of the approved fixed-release identity. All identity
inputs are copied from authenticated MA evidence except `LM_POLICY_DIGEST`,
which is reconstructed from the exact policy selected for the operation.
`REPORT_ID`, `REPORT_ID_MA`, `REPORT_DATA`, platform TCB/ETCB, mitigation
vectors, and certificate bytes are not part of the stable release identity.

Collateral and envelope packaging remain outside the canonical semantic
LM-policy digest. Do not hash an allowlist or endorsement into the identity
it approves, or remove any frozen semantic-policy/report/session binding.
TDX measurement wildcard or optional-field matching does not replace the exact
SNP identity construction.

The fixed-profile identity-authorization encoding is `FixedReleaseAllowlistV1`:

```text
FixedReleaseAllowlistV1 = 320 bytes

Offset  Size  Encoding
0x000     2   FORMAT_VERSION = 1, u16le
0x002     2   PROFILE = 1 (FixedReleaseV1), u16le
0x004     4   RECORD_SIZE = 320, u32le
0x008     8   SEQUENCE, u64le
0x010     8   ISSUED_AT, Unix seconds, u64le
0x018     8   EXPIRES_AT, Unix seconds, u64le
0x020     4   STATUS = 1 (Approved), u32le
0x024     4   FLAGS = 0, u32le; all bits reserved in Version 1
0x028    48   approved MA_POLICY_IDENTITY_DIGEST
0x058    32   RELEASE_ID
0x078    48   SIGNER_ID
0x0a8    48   AUTHORIZATION_ROOT_ID
0x0d8     2   SIGNATURE_ALGORITHM = 1 (ECDSA P-384), u16le
0x0da     2   HASH_ALGORITHM = 1 (SHA-384), u16le
0x0dc     2   SIGNATURE_FORMAT = 1 (raw IEEE P1363), u16le
0x0de     2   RESERVED = 0
0x0e0    96   SIGNATURE = r[48] || s[48], unsigned big-endian components

signed bytes = FixedReleaseAllowlistV1[0x000..0x0df], exactly 224 bytes

SIGNATURE =
    ECDSA-P384-SHA384(FixedReleaseAllowlistV1[0x000..0x0df])
```

`RELEASE_ID` is a nonempty printable-ASCII release name, NUL-padded on the
right, with no embedded NUL. It is audit metadata; authorization is based on
the approved identity digest.

Signer and root identities are:

```text
AUTHORIZATION_ROOT_ID =
    SHA384(root certificate DER SubjectPublicKeyInfo)

SIGNER_ID =
    SHA384(
        "SNP-MA-AUTH-SIGNER-v1" ||
        AUTHORIZATION_ROOT_ID ||
        u32le(length(leaf certificate DER subject name)) ||
        leaf certificate DER subject name
    )
```

The signer certificate chain is transported outside the 320-byte record. It
must terminate at the pinned Microsoft SNP MA authorization root and carry the
Microsoft-assigned fixed-release allowlist-signing EKU. The EKU's numeric OID
is a PKI provisioning constant and does not alter this wire format. Fixture
allowlists use a separately pinned fixture root and fixture EKU and are
rejected by production providers.

Trusted time must establish `ISSUED_AT <= now < EXPIRES_AT`. The verifier
persists the greatest accepted `SEQUENCE` for each
`AUTHORIZATION_ROOT_ID`/profile pair and rejects a lower sequence. Reuse of the
current sequence is allowed only for byte-identical signed content. Record
replacement is atomic.

The exact `LM_POLICY_DIGEST` is also bound into fresh session-specific MA
`REPORT_DATA`; the verifier reconstructs the context and checks all 64 bytes
according to P0.3.

Rules:

- every identity input comes from verified MA evidence or reconstructed
  session context;
- source, destination, outgoing, and incoming MAs must match the
  policy-selected fixed identity exactly;
- no host-supplied identity or approval state is authoritative;
- changed code, policy, guest SVN, signer digests, or bound configuration
  changes the identity digest and fails until a newly signed allowlist is
  deployed;
- `FixedReleaseV1` defines no release SVN, initial-MA lookup, or ordered
  upgrade.
- expose approval through the fixed variant of `VerifiedMaPolicyCollateral`,
  without synthesizing `MaPolicyTcbMapping` or assigning SVN zero.

Acceptance:

- canonical identity and allowlist positive vectors;
- exact 280-byte identity and 320-byte allowlist lengths;
- reserved or flag bits set to nonzero fail;
- malformed, empty, overlength, non-ASCII, or noncanonically padded release
  identifiers fail;
- changed identity field or policy digest fails;
- invalid signature, unknown root, wrong signer purpose, expired manifest,
  non-Approved status, or fixture root in production fails;
- future issue time, sequence rollback, and same-sequence content replacement
  fail;
- identical inputs produce identical identity digests across implementations;
- no `FixedReleaseV1` consumer invents SVN or initial-authorization semantics.

### P0.9A2 `OrderedReleaseV1` MA/Policy endorsement

Status: ACCEPTED AND FROZEN for custom contract/fixture conformance on
2026-11-03T15:49:03Z; conditions: None.
Freeze identifier: `P0.9-OrderedCollateralV1-2026-11-03`.
Real production providers, deployment approval, live integration, issue
tracking and hardware qualification remain open. No Phase 0 gate closure.

The ordered profile extends the same `MaPolicyCollateral` model with two
verified responsibilities:

- `MaPolicyIdentity`: approve the same canonical identity defined in P0.9A1,
  with applicable signer, status and validity information;
- `MaPolicyTcbMapping`: bind that identity to an issuer-approved combined
  MA/Policy SVN for ordered comparisons.

Their relationship is:

```text
MA_POLICY_IDENTITY_DIGEST
    -> stable MA/Policy signer identity
    -> combined MA/Policy SVN
    -> release status and validity
```

The selected intended-production representation is custom signed SNP collateral
v1, not CoRIM/CoMID. This supersedes the earlier open CoRIM-or-equivalent choice.
`MaPolicyCollateral::OrderedReleaseV1` carries `MaReleaseEndorsementV1`: one
complete signed publisher snapshot combines exact-identity approval, immutable
combined-SVN mapping and release status. No duplicate fixed-release allowlist
or second identity fingerprint is required.

All integers below are unsigned little-endian. All digests are 48 bytes.
Publisher identity is a stable nonzero 48-byte namespace provisioned by trusted
deployment configuration, not a host-selected signer/root digest.
All records reject unsupported magic/version/profile, lengths, reserved bits
and trailing bytes. Version 1 fixes ECDSA P-384/SHA-384 with raw IEEE P1363
`r[48] || s[48]`; algorithms are not negotiated from untrusted metadata.

```text
MaReleaseEndorsementV1
Offset  Size  Field
0         8   magic = ASCII "SNP-MA-R"
8         2   version = 1
10        2   authorization profile = 2 (OrderedReleaseV1)
12        4   exact total byte length = 152 + 56 * count + 96
16       48   publisher_id
64       48   signing_key_id
112       8   trust_epoch
120       8   sequence
128       8   issued_at (Unix seconds)
136       8   expires_at (Unix seconds)
144       4   mapping count, 1..256
148       4   reserved zero
152    56*N   mappings, strictly ascending identity_digest, no duplicates:
                  identity_digest[48]
                  combined_svn u32
                  status u16: Approved=1, HistoricalOnly=2, Revoked=3
                  reserved zero u16
end-96   96   signature

signature message =
    ASCII "SNP-MA-COLLATERAL-v1" || exact record bytes before signature

signing_key_id =
    SHA384(ASCII "SNP-COLLATERAL-KEY-v1" || SEC1_uncompressed_P384_public_key[97])
```

No domain string includes a trailing NUL. The maximum encoded snapshot is
14,584 bytes. Count/total size are checked before allocating decoded entries.
The signature covers version/profile, namespace/key, epoch/sequence, validity,
entry count/order and every mapping/status byte. Issuer-chain packaging is not
itself authority: `CollateralKeyProviderV1` independently binds key/publisher/
purpose/trust/epoch to the configured authorization roots and lifecycle state.

The shared frozen 280-byte identity input remains byte-identical, including
its existing discriminator value 1; that discriminator identifies the frozen
fingerprint construction, not the new endorsement's authorization profile.
The endorsement is profile 2 and neither replaces nor rehashes the fingerprint.
Do not include endorsements or collateral envelopes in `LM_POLICY_DIGEST`.

The approved policy verifier must authenticate `OrderedReleaseV1` publisher
selection and the absolute combined-SVN floor along with the canonical policy
semantics; caller-provided floor/publisher metadata is not authority.
`VerifiedLmPolicyV1` explicitly distinguishes fixed and ordered release rules.
The closed Microsoft semantic-policy schema remains an external deployment
input, not invented by this collateral format.

Different releases may share an SVN when no security-relevant change occurred.
Combined MA/Policy SVN is not the fixed-allowlist update sequence, hardware
`GUEST_SVN`, platform TCB/ETCB or mitigation-vector state.
The profile defines signed release-to-SVN mapping, certificate rotation,
revocation, root transition and initial-MA authorization.
Current release approval cannot replace retained historical initial-MA
authorization.

The ordered variant of `VerifiedMaPolicyCollateral` requires both verified
identity approval and mapping, current signed report/context/platform appraisal,
and current snapshot validation; missing or conflicting mappings fail closed.
H5.2 and H5.6 qualify production publication, acquisition, lifecycle and
relying-party verification using this representation.

This profile is mandatory before:

- accepting differently ranked MA releases;
- claiming cross-release MA upgrade;
- enforcing incoming MA/Policy SVN against an initial MA/Policy SVN;
- production relying-party authorization qualification.

### P0.9B1 Fixed-release platform and MA admission

Use these exact signed fields for current-platform admission:

```text
source platform:
    source_ma.CURRENT_TCB
    source_ma.CURRENT_ETCB
    source_ma.CURRENT_MIT_VECTOR

destination platform:
    destination_ma.CURRENT_TCB
    destination_ma.CURRENT_ETCB
    destination_ma.CURRENT_MIT_VECTOR
```

Apply:

```text
source CURRENT_TCB/ETCB >= configured absolute platform floor
destination CURRENT_TCB/ETCB >= configured absolute platform floor
destination CURRENT_TCB/ETCB >= source CURRENT_TCB/ETCB

required_destination_mit_vector =
    policy.minimum_current_mit_vector
    OR source_ma.CURRENT_MIT_VECTOR

(destination_ma.CURRENT_MIT_VECTOR
    & required_destination_mit_vector)
        == required_destination_mit_vector

source, destination, outgoing, and incoming
    MA_POLICY_IDENTITY_DIGEST == policy-selected fixed identity
```

TCB and ETCB comparisons are component-wise. Reserved or unknown ETCB
components fail unless an approved profile transition defines them.

`LAUNCH_TCB`, `LAUNCH_ETCB`, and `LAUNCH_MIT_VECTOR` are used only for tenant
history under P0.4. `REPORTED_TCB` is used for signing-key collateral.
`COMMITTED_*` fields are not policy operands unless a separately frozen
rollback-commitment rule names them.

Recovery-mode `SNP_REBIND_MA` retains firmware-defined exact identity and
launch-state equality.

Acceptance:

- exact component and mitigation-vector vectors;
- downgrade of one current platform component or required mitigation bit
  fails;
- changed fixed MA/Policy identity fails;
- equal approved fixed-release moves pass;
- recovery exact-match and planned-handoff tests remain separate.

### P0.9B2 Ordered-release comparisons

Status: ACCEPTED AND FROZEN for fixture-backed contract conformance under
`P0.9-OrderedCollateralV1-2026-11-03`; production/runtime qualification remains open.

Add:

```text
source and destination MA/Policy SVN >= configured absolute floor
destination MA/Policy SVN >= source MA/Policy SVN
incoming MA/Policy SVN >= outgoing MA/Policy SVN
incoming MA/Policy SVN >= initial MA/Policy SVN
```

These rules do not apply to `FixedReleaseV1`, which uses exact identity
approval and contains no SVN.

Admission requires the same stable publisher and current snapshot digest for
source/destination (or outgoing/incoming) and historical authorization.
Both current identities must be Approved; initial identity may be Approved or
HistoricalOnly but never Revoked. All compared releases meet the absolute
floor. Different identities may share an SVN; greater SVN does not bypass
platform TCB/ETCB floors or the destination mitigation-superset rule.

The verifier reuses SNP-specific authenticated identity/report/context checks;
it never compares identity digests lexicographically as security ranks.
Roles, request, tenant, TH1, algorithm, migration version and report trust must
match the operation. Current source/outgoing `REPORT_ID` must equal the verified
tenant's `REPORT_ID_MA`. Historical authorization must name the exact verified
tenant and its actual authenticated `MigrationDataV1.init_ma_report_id`.
Local planned handoff uses its frozen zero tenant-binding context while still
requiring the exact tenant/history receipt. Recovery remains separate.

Version 1 conservatively requires identical effective platform rules,
publisher and SVN floor on both peers. Their release identities and semantic
policy digests may differ when each is independently approved and bound.
Other cross-policy compatibility needs an explicit later contract, not an
implicit destination-policy override.

Final admission rechecks current snapshot/keys, trusted-time policy/history
validity and durable historical state. Receipts do not bypass later durable
replay, firmware effects, session freshness, history or readiness gates.

### P0.9C1 Fixed-release trust and authorization binding

Implement and validate the frozen P0.9A1 encoding and:

- consume the exact canonical LM-policy bytes and digest;
- consume the exact canonical MA/Policy identity construction;
- verify the exact signed `FixedReleaseAllowlistV1`;
- pinned fixture and production authorization roots;
- signer-purpose validation;
- manifest issue and expiration times;
- deterministic signed allowlist replacement;
- source/destination collateral digest binding;
- authorization-context canonicalization;
- fixture and production trust-root separation.

Verify the fixed-profile `MaPolicyCollateral` and produce its fixed variant of
`VerifiedMaPolicyCollateral` before policy admission. Its `MaPolicyIdentity`
adapter uses the frozen allowlist as the approval component; it neither
creates another signed identity document nor changes the allowlist encoding,
identity hash or trust rules. Share bundle handling and signature,
issuer-purpose, validity and identity-binding checks where appropriate, but
retain profile-specific trust inputs and acceptance rules.

The minimum profile does not require an online revocation service. Production
use still requires a controlled signed trust-bundle and allowlist update path.

Acceptance:

- report, certificate, allowlist, policy, role, or root substitution fails;
- changed collateral ordering cannot change canonical identity;
- expired allowlist and untrusted signer fail;
- authorization vectors cover policy, collateral, role, request, tenant, and
  TH1 changes.

### P0.9C2 Production collateral lifecycle

Status: ACCEPTED AND FROZEN CONTRACT/FIXTURE CONTROL FLOW under
`P0.9-OrderedCollateralV1-2026-11-03`; production lifecycle qualification
remains gated. Intended-production format selection is not organizational
deployment approval or provisioned Microsoft publishing authority.

Lifecycle rules:

- Require `issued_at <= trusted_now < expires_at`. Policy and signing-key
  validity are independent requirements, not implied by endorsement validity.
  Expired artifacts do not authorize a new operation.
- Pin a stable publisher namespace independently of leaf/intermediate/root
  keys. `ReleaseSnapshot` and `InitialAuthorization` are separate key purposes;
  a release-signing key does not automatically authorize historical assertions.
  Fixture registry keys are explicitly test-only and purpose separated.
- `CollateralKeyProviderV1` must validate publisher/key/purpose/trust/epoch,
  signing-time validity and current revocation status against independently
  authenticated configuration. Missing or stale revocation information,
  unknown purposes and unapproved roots fail closed.
- A new leaf/intermediate/root is not authorized by merely appearing in a
  transported bundle. Trust updates need authenticated administrative approval
  and independently anchored monotonic trust state; providers reject rolled
  back epochs. No peer-controlled root transition is accepted.
- `OrderedCollateralStoreV1` authenticates bounded state by
  `(fixture-or-production trust, stable publisher, slot)` with an independent
  rollback anchor. Missing/corrupt state never becomes empty state; empty state
  requires explicit provisioning. Commit uses atomic durable revision-CAS,
  including retries; ambiguous effects return failure pending recovery.
- Snapshot sequence never resets across signer/root rotation. Reject lower
  sequence or epoch and changed signed content at the same sequence. A newer
  snapshot retains every earlier identity with the same SVN and a nondecreasing
  status: Approved -> HistoricalOnly -> Revoked. Revocation is terminal; no
  resurrection, deletion or remapping. Correction requires a new release
  identity or explicitly versioned contract, not rewriting history.
- Maximum 256 retained entries is a hard v1 bound. Exhaustion fails closed;
  archival sharding/pruning requires a later authenticated version, never
  silently dropping old/revoked mappings.
- Refresh the snapshot's key/validity/store checks at evidence use and final
  admission. Newer accepted snapshot state invalidates older receipts.
  These operation-local checks are not a distributed atomic transaction with
  concurrent policy/trust updates; live integration must serialize updates
  with operation admission, enforce replay and reverify after session loss.

Historical authorization is a separately signed record, not today's approval
of a current MA:

```text
InitialMaAuthorizationV1 = 416 bytes
Offset  Size  Field
0         8   magic = ASCII "SNP-MA-H"
8         2   version = 1
10        2   authorization profile = 2
12        4   exact byte length = 416
16       48   publisher_id
64       48   signing_key_id (InitialAuthorization purpose)
112       8   trust_epoch
120       8   sequence
128       8   issued_at
136       8   expires_at
144      32   tenant_report_id
176      32   initial_ma_report_id
208      48   exact MA_POLICY_IDENTITY_DIGEST
256      48   original LM_POLICY_DIGEST
304       4   combined MA/Policy SVN
308       4   reserved zero
312       8   observed_at (original authorization observation)
320      96   signature

signature message =
    ASCII "SNP-INITIAL-MA-AUTH-v1" || exact record[0..320]
```

The initial-authorization authority must verify original tenant/MA evidence,
exact identity/policy binding and the then-valid release approval before
signing; it does not sign host assertions. Require
`observed_at <= issued_at <= now < expires_at`. The current snapshot must
retain the same identity-to-SVN mapping and not revoke it; HistoricalOnly
permits historical appraisal but never new current-MA admission. Expiration
does not get a historical bypass.

`HistoricalTenantBindingProviderV1` must authenticate complete current tenant
evidence/persisted Venice migration history and bind its report digest to
`VerifiedTenantReportDeliveryV1` before returning actual `INIT_MA_REPORT_ID`.
Unavailable hardware/composite history is an explicit provider error, not a
caller-selected initial identity.

Retain signed initial records durably by tenant/initial-MA identifiers, with
authenticated authorized retrieval and migration/handoff continuity.
Renewal or signer rotation requires a greater record sequence and preserves
publisher, tenant ID, initial-MA ID, identity digest, original policy digest,
SVN and observed_at exactly. Only envelope key/epoch, sequence and validity may
change; lower sequence/epoch or same-sequence changed signed content fails.
Revoked historical signers do not receive automatic grandfathering: obtain an
authorized renewal from retained evidence or fail closed.

Production gates still include actual publishing authority/keys, approved
PKI/root-update and revocation services, trusted time, durable anchored state,
historical signing/retention/retrieval, MAA/relying-party acquisition and AMD
layout resolution. The custom format removes the CoRIM-profile dependency,
not these operational and qualification obligations.

Contract validation on 2026-11-03: 20 ordered unit tests added to the 25
fixed-profile tests, plus one sealed-history compile-fail test. Full TAV PAL
269 / Azure PAL 270, emulator 7 and PAL doctests 14 passed for each backend;
default PAL 25 / doctests 5 and MigTD SNP tests 10 passed. Targeted formatting,
PAL/emulator and MigTD Clippy, TDX compatibility, release-musl build and
sequential legacy Stage A/B passed with existing warnings only. Independent
signing-message vectors, every-byte signature tampering, upgrade/downgrade
for inter-node and planned handoff, tenant current-MA substitution, historical
renewal/rollback and final-admission freshness/state checks are covered.
Evidence: `target/p0.9-ordered-validation/20261103T153417Z/`; commands,
hashes and limitations are recorded in the central execution log.
These fixture/model results do not activate live ordered policy admission,
qualify real certificate-root rotation or approve production deployment.

### P0.9D Freeze gates and consumer dependencies

Status: DONE - ACCEPTED AND FROZEN CONSUMER CONTRACT CONSOLIDATION.
Accepted on 2026-11-03T16:13:49Z; conditions: None.
Freeze identifier: `P0.9D-ConsumerContractsV1-2026-11-03`.
Scope is the fixed/ordered consumer and provider handoff, not live SPDM/runtime
activation, P0.9E tracker closure or production qualification.

Prerequisites already accepted:

```text
P0.9A1/B1/C1: P0.9-FixedReleaseCollateralV1-2026-11-03
P0.9A2/B2/C2: P0.9-OrderedCollateralV1-2026-11-03
```

#### Verified inputs, outputs and profile dispatch

The API authority is [ma_policy.rs](../src/pal/src/snp/ma_policy.rs) and
[ordered_collateral.rs](../src/pal/src/snp/ordered_collateral.rs).
`MaPolicyCollateral` is a typed but unverified transport/container value.
Decoded `FixedReleaseCollateralV1`, `MaReleaseEndorsementV1`,
`InitialMaAuthorizationV1`, policy bytes, chains and host metadata are not
authorization receipts. Only trusted, deployment-selected providers may
construct authenticated claims; a peer cannot supply its own verifier or store.

| Stage | Required inputs / entry point | Verified output / consumer obligation |
|---|---|---|
| Policy, either profile | `VerifiedLmPolicyV1::verify`, trusted `LmPolicyVerifierV1` and `MaPolicyTimeV1`, bounded signed policy/issuer chain and locally selected trust | `VerifiedLmPolicyV1`; adapter authenticates platform rules and `MaPolicyReleaseRulesV1`, including ordered publisher/floor, and effective policy/signer validity |
| Common MA request | `MaPolicyVerificationRequestV1`: exact `SnpMaEvidenceV1`, canonical `SnpCollateralSetV1`, independently reconstructed `expected_context`, expected VMPL and report/authorization trust | Neither the peer context nor its declared identity/profile is the local expectation; `selected_identity` is used only for the fixed profile |
| Fixed approval | `VerifiedMaPolicyCollateral::verify_fixed`, verified policy, `FixedReleaseCollateralV1`, `MaPolicyVerificationServicesV1` | Sealed `VerifiedMaPolicyCollateral::FixedReleaseV1`; exact deployment-selected identity, signed allowlist and platform floors verified |
| Ordered snapshot | `VerifiedReleaseCollateralV1::verify`, `MaReleaseEndorsementV1`, local trust and `OrderedCollateralServicesV1` | Sealed `VerifiedReleaseCollateralV1`; bounded signatures, lifecycle, immutable mappings and durable sequence-CAS checked |
| Ordered current-MA approval | `VerifiedMaPolicyCollateral::verify_ordered`, verified policy, snapshot, common request, trusted report verifier and ordered services | Sealed `VerifiedMaPolicyCollateral::OrderedReleaseV1`; authenticated publisher/floor and Approved mapping required; snapshot refreshed |
| Initial authorization | `VerifiedInitialMaAuthorizationV1::verify`, signed initial record, `VerifiedTenantReportDeliveryV1`, `HistoricalTenantBindingProviderV1`, same snapshot and ordered services | Sealed history receipt for this exact tenant/operation and actual `INIT_MA_REPORT_ID`; current-MA approval cannot replace original authorization |
| Fixed pair | `admit_fixed_release_pair_v1`, two fixed receipts | `Result<(), MaPolicyErrorV1>`; exact release/policy, operation/role/trust and current-platform forwarding check only; caller owns final freshness and tenant-binding checks |
| Ordered pair | `admit_ordered_release_pair_v1`, two ordered receipts, sealed initial receipt, same snapshot, history provider and ordered services | `Result<(), MaPolicyErrorV1>`; publisher/snapshot/floor, tenant/source-MA and initial-SVN binding, ordering/platform forwarding, policy validity and history/key/store refresh checked |

Select the profile from trusted local configuration consistent with the
authenticated policy release rules. The corresponding verifier rejects a
wrong policy profile. Pair admission rejects mixed or wrong variants; a
missing ordered mapping never becomes SVN zero, fixed approval or an
exact-identity fallback. The fixed path does not acquire a dummy release rank
or require a duplicate ordered snapshot.

The read-only common accessors are `context()`, `identity_digest()`,
`report_id()`, `report_digest()` and `report_collateral_digest()`.
`VerifiedLmPolicyV1::digest()` provides the authenticated policy digest checked
during receipt construction. The report digest is SHA-384 of the exact
1184-byte base report; the collateral digest is SHA-384 of the canonical
`SnpCollateralSetV1` encoding. Neither is the complete tenant-evidence digest,
the stable release identity or a durable authorization/replay record.
Keep P0.5/P0.6 canonical complete-evidence and authorization-context bindings
separate; match them to the same locally correlated tenant operation.

Both approval paths reconstruct identity only after trusted report verification,
check all expected `REPORT_DATA` bytes, policy/collateral/profile/role bindings,
signing-key selection and author-key consistency, and enforce Venice current
TCB/ETCB/mitigation floors. `GUEST_SVN`, combined release SVN, publisher snapshot
sequence and platform TCB/ETCB remain distinct. `HOST_DATA` is host-supplied but
must match the approved identity. No TDX wildcard or trust rule is imported.

#### Trusted-provider ownership and fail-closed behavior

| Provider | Required responsibility | Supplied default / qualification boundary |
|---|---|---|
| `SnpEvidenceVerifier` | Authenticate exact report/collateral, VMPL, local requested-report binding and selected report trust under P0.12A/P0.12A1 | Version 6 executable/composite integration belongs to AAS1A-M/H5; no caller-selected fixture verifier in production |
| `LmPolicyVerifierV1` | Approved closed schema, signature/issuer purpose, RFC 8785 semantic bytes, authenticated profile/platform rules and effective signer/policy validity | `UnavailableMaPolicyServicesV1` returns `PolicyUnavailable`; test adapter is not the missing approved Microsoft schema |
| `MaPolicyTimeV1` | Trusted current time for policy, signer and collateral validity | Unavailable default returns `TimeUnavailable`; host clock or a test counter does not qualify deployment time |
| `MaPolicySignerVerifierV1` | Fixed-profile bounded leaf-first chain, pinned root, CA/key constraints and configured signing EKU; authenticated subject/SPKI/SEC1 claims | Unavailable default returns `SignerUnavailable`; no invented Microsoft OID/root; fixture purpose and roots remain separate |
| `DurableAllowlistStoreV1` | Fixed `(trust, root)` state with independently anchored rollback protection and atomic durable revision-CAS, including identical retries | Unavailable load/commit returns `StoreUnavailable`; missing/corrupt state is not provisioned empty state |
| `CollateralKeyProviderV1` | Ordered `(trust, publisher, purpose, key, epoch)` authority, signing-time validity, current revocation/freshness and approved anchored key/root updates | `UnavailableOrderedCollateralServicesV1` returns `LifecycleUnavailable`; transported chains do not install roots |
| `OrderedCollateralStoreV1` | Bounded authenticated `(trust, publisher, slot)` snapshot/history state, retention/retrieval authorization and atomic durable revision-CAS | Unavailable load/commit returns `StoreUnavailable`; namespace isolation, crash recovery and independent anchors need actual provider qualification |
| `HistoricalTenantBindingProviderV1` | Authenticate complete tenant evidence/current persisted Venice history against the exact report receipt before returning real `INIT_MA_REPORT_ID` | Unavailable default returns `HistoricalBindingMismatch`; no host-selected initial identity or current-release substitute |

All provider, codec, signature, trust, time, sequence, history and admission
errors propagate as failure. Runtime consumers must report the failure through
their established error/status path, never continue to key confirmation,
installation or readiness with partial/default claims. Actual production
authorization is explicitly rejected as `ProductionProfileUnavailable`;
defining a production-intent format does not enable that path.

#### Receipt lifetime and admission sequencing

1. Establish trusted operation/routing state and verify the host-pushed tenant
   report before contribution-bound MA evidence. Reconstruct the expected
   role/purpose/request/TH1/algorithm/version/tenant bindings locally; do not
   authorize using a provisional handle or copied peer context.
2. Verify each signed policy and profile-specific approval with the selected
   providers. Carry the exact policy, raw signed collateral and tenant evidence
   alongside sealed receipts so the owning consumer can reverify, not persist
   serialized Rust receipts as future authority.
3. Before fixed-profile admission, re-run policy and `verify_fixed` checks at
   trusted current time/state if either could have changed since verification.
   `admit_fixed_release_pair_v1` has no clock/store and does not refresh them.
   Bind tenant `REPORT_ID_MA` to the source/outgoing receipt explicitly under
   Task 8/P0.11; fixed pair success alone does not establish that relationship.
4. Before ordered admission, supply the same current publisher snapshot and
   exact sealed tenant/history receipt. `admit_ordered_release_pair_v1` rechecks
   both policy intervals and re-verifies history, snapshot/key authorization
   and durable state. Retained history cannot be revived after revocation;
   authorized renewal preserves the C2 immutable history fields.
5. Serialize trust/policy/provider updates with operation admission for both
   profiles. Reverify after expiry, session loss, restart or relevant updates;
   ordered refresh is operation-local, not a distributed atomic transaction.
   Neither pair function refreshes an independently changed policy source.
6. For current V2 inter-node migration, require the separate fresh purpose-`0x07`
   proofs, current firmware/history appraisal and durable bounded-replay commit
   before publishing `SnpAuthorizationResultV1` or advancing to keys/install.
   Local handoff/recovery instead retains the P0.3/P0.11 operation-specific
   evidence and firmware/recovery gates; inter-node proofs cannot replace
   them. A successful `Result<()>` is not a complete authorization result,
   an effects-once token, firmware recovery equality or proof of
   installed/readiness state.

#### Consumer-readiness and dependency matrix

This table states P0.9 handoff obligations in addition to each milestone's
other prerequisites; it does not mark those milestones implemented or ready
before the Phase 0 gate and canonical execution order.

| Consumer | P0.9 inputs / required handoff | Work that remains with that consumer |
|---|---|---|
| Task 6 | A1/C1 fixed encodings, policy/signature/trust fixture inputs; D identifies untrusted records versus verified receipts | Produce qualified full signed Version 6 evidence fixtures; existing A2/C2 unit fixtures are not a replacement |
| Task 7 | A1/B1/C1 and D fixed verification APIs; same locally reconstructed V2 purpose-6 context and verified complete tenant evidence on both sides | Wire policy/report/signer/time/store providers, exchange exact evidence/collateral, retain sealed approvals with operation/provenance; reach only `BothMaEvidenceVerified` |
| Task 8 | Task 7 receipts and exact verified tenant evidence; D report-ID/digest handoff | Verify source-MA binding and fresh V2 purpose-7 proofs; qualify current state/replay and produce the separate authorization result |
| Task 9 | Task 8 plus A1/B1/C1 and D fixed pair/profile semantics | Consume verified approvals, perform Venice history/recovery/floor checks, compute/reconstruct identical migration data; do not enable ordered policy merely because its contracts exist |
| P0.11 / R4.3 same release | A1/B1/C1 and D fixed source/destination versus outgoing/incoming contract; R4.3 also requires P0.11 | Freeze/implement handoff eligibility, tenant binding, firmware state/history preservation, recovery identity and failure behavior |
| T4.20 | A1/B1/C1/D/E fixed-profile contract gates and accepted A2/B2/C2 handoffs where applicable | Audit provider/consumer readiness, fail-closed production/fixture isolation and remaining E evidence; no locally invented policy semantics |
| R4.3 cross release | Accepted A2/B2/C2 plus D ordered APIs, real tenant-history binding, P0.11 and explicit cross-release integration approval | Wire ordered approvals/initial history and qualify incoming >= outgoing/initial plus absolute floors; this is not activated by the same-release milestone |
| H5.0 / H5.2 | H5.0 reviews accepted A2/B2/C2/D contracts and any explicitly versioned deployment changes; H5.2 consumes them | Satisfy actual authority/PKI/revocation/time/state/acquisition and AMD parser gates, integrate and qualify production providers; do not refreeze already accepted bytes |
| P0.12B / H5.6 | A2/B2/C2/D historical-record and tenant-binding contracts | Freeze actual composite evidence/acquisition and relying-party representation, qualify full original-evidence appraisal and durable retrieval; the signed history record alone does not settle composite packaging |

#### D completion and freeze gate

D requires all of the following before its separate acceptance:

- both accepted profile freezes are identified and every documented entry point,
  receipt, accessor and unavailable-provider error matches the current API;
- raw inputs cannot substitute for sealed outputs, profile selection has no
  promotion/fallback and fixed versus ordered revalidation limits are explicit;
- consumer ownership covers tenant evidence, contribution/purpose bindings,
  policy admission, history/replay, installation and recovery without equating
  any one approval with complete migration authorization;
- downstream dependency/decision statements recognize the accepted ordered
  contracts but retain real provider, E tracker and Phase 5 qualification gates;
- existing source/format freezes and the exact 37-step order are unchanged;
- validation and explicit user acceptance are appended to
  [implementation_record.log](implementation_record.log).

Validation on 2026-11-03: documented API names and call/receipt responsibilities
checked against the current implementation; D links resolve; accepted source
hashes, the exact 37-step order, the readiness index and prior central-log
prefix remain unchanged. The three existing `ma_policy` sealed-contract
compile-fail doctests passed. This is documentation-only consolidation; no
runtime behavior or new provider was introduced. Evidence:
`target/p0.9d-validation/20261103T160603Z/`.

No consumer may invent identity, comparison, trust, revocation, SVN, or
initial-authorization semantics locally.

### P0.9E Production-readiness tracking

Status: DONE - ACCEPTED AND FROZEN REPOSITORY-LEDGER TRACKING SCOPE.
Accepted on 2026-11-03T17:40:06Z; conditions: None.
Freeze identifier: `P0.9E-ReadinessLedgerV1-2026-11-03`.
The mechanism/record contract is frozen, not future status/ownership updates.
Tracking is not completion of the production requirements.

Create and maintain in the MigTD repository:

```text
doc/snp-production-readiness.md
```

The [index](snp-production-readiness.md) records PA-001 through PA-011,
including the approved-policy-schema and trusted time/durable-store gaps.
The user selected this repository ledger with stable per-PA anchors as the
approved tracking mechanism on 2026-11-03 and confirmed `@mvasantarao` as the
accountable tracking owner for every row. GitHub Issues remain disabled;
enabling public Issues is neither technically necessary nor required for E.
This explicitly supersedes earlier issue-only/named-tracking-owner blockers,
without waiving technical assignment, evidence or production qualification.

An acceptable tracking link is a GitHub Issue, Azure DevOps work item or
another explicitly approved durable tracker, including the selected
repository-ledger record. Do not invent private upstream URLs or external work
items. Each stable requirement record contains:

```text
stable requirement ID
requirement and security rationale
current status
accountable owner/team (confirmed tracking owner, external technical authority separate)
target repository or Microsoft upstream dependency
dependencies and blocking milestone
interface or version impact
approved durable tracker link
PR and commit links, or explicit pending/none disposition
implementation and test evidence, distinguishing contract/model from production
qualification result
```

The ledger links each summary row to its stable PA record and relevant accepted
contract/test evidence. External technical contacts, exact private repositories,
work items, PRs and commits are pending where not supplied. Tracking ownership
does not appoint Microsoft/AMD/BASE approvers or imply their acceptance.

Minimum tracked requirements:

```text
PA-001 custom signed SNP collateral v1 production approval/publication
PA-002 identity-to-combined-MA/Policy-SVN mapping
PA-003 InitialMaAuthorizationV1 and durable storage or lookup
PA-004 revocation and certificate-rotation lifecycle
PA-005 production authorization trust roots and provisioning
PA-006 composite AAS/MAA verification
PA-007 BASE-managed tenant sidecar persistence
PA-008 hardware authorization and rebind qualification
PA-009 AMD Version 6 ETCB/MIGRATION_DATA physical-layout clarification
PA-010 approved closed LM-policy JSON schema and canonicalization
PA-011 trusted time and independently anchored durable sequence state
```

Statuses are explicit:

```text
DESIGN_REQUIRED
EXTERNAL_DEPENDENCY
READY
IN_PROGRESS
IMPLEMENTED
QUALIFIED
BLOCKED
```

The ledger also lists prohibited production claims. Tracking coverage requires
all eleven stable records, a confirmed accountable tracking owner, complete
status/dependency/gate/version information, working tracker/evidence pointers,
and explicit dispositions for missing implementation/publication/qualification
evidence. A bare row without that accountable record does not count.

Requirement completion is stricter: `QUALIFIED` requires linked implementation,
actual tests and required authority acceptance; none of PA-001-PA-011 is
qualified now. Missing evidence is a tracked gap, never evidence of success.
The central log records dated changes and acceptance. Repository publication
and durable distribution of raw test evidence remain explicitly pending until
actual PR/commit and sanitized artifact links are supplied; no commit/push is
implied by local ledger implementation or acceptance.

E's bounded freeze gate is validation of tracker/owner coverage, record/link
integrity, honest evidence/qualification states, preserved source/formats and
canonical order, and explicit user acceptance in the central log. It does not
implement production providers, activate live policy or close the Phase 0 gate.

Validation on 2026-11-03: all eleven unique PA records and ten-field index
rows contain the confirmed owner and explicit tracking/evidence dispositions;
local file/anchor links resolve. Thirteen accepted source hashes, the frozen
D section, exact 37-step sequence and prior central-log prefix are unchanged.
GitHub Issues remain disabled. This documentation/tracking-only change needs
no firmware build or runtime regression; none is claimed. Evidence:
`target/p0.9e-validation/20261103T162359Z/`.

## P0.10 Produce migration cryptographic golden vectors

HISTORICAL V1 CRYPTO RECIPE: bilateral commitments, HKDF and PRK-derived HMACs
below are superseded, not active requirements. Preserve their original corpus
and test-only references. [T4.14-PRE](snp/task4/t4.14-pre-direct-random.md)
defines the325/703-byte V2 nonsecret preimages and new independent
`direct_random_v2.txt` corpus; no KDF or application confirmation key exists.

Status: DONE - ACCEPTED AND FROZEN for the exact inter-node cryptographic
recipe and independent golden-vector/test-only reference scope.
No runtime/provider or production qualification.
Vector freeze identifier: `P0.10-InterNodeGoldenVectorsV1-2026-11-03`.
Accepted UTC: `2026-11-03T22:45:46Z`. Conditions: None.
Prerequisites: P0.3-P0.9, P0.11 including its accepted V1.1 clarification,
P0.12A and P0.12A1.

P0.7 closure gate: recover and reconcile the authoritative Task 2 commitment
construction before accepting contribution/KDF cryptographic vectors.
P0.7 wire/state vectors and the test-only secret oracle do not satisfy this
gate. No runtime contribution/commitment activation may bypass it.

P0.8 closure gate: reconcile the canonical session-context digest and exact
HMAC-SHA384 confirmation construction, direction-specific PRK-derived keys
and labels. Independently validate both tags. P0.8 opaque-tag record vectors
do not qualify cryptography or permit runtime activation.

### Approved exact cryptographic recipe V1

Recipe identifier: `P0.10-InterNodeCryptoRecipeV1-2026-11-03`.
Status: APPROVED for test-only reference calculations and independent vectors.
Approval recorded UTC: `2026-11-03T22:25:29Z`.
User decision: "Approve candidate V1 recipe and implement reference vectors".
Conditions: None. Independent vector/reference acceptance was subsequently
recorded at `2026-11-03T22:45:46Z` under the vector freeze above.
The available records refer to an accepted Task 2 construction but no original
formula or verified acceptance record has been recovered. This recipe is a
new replacement authority for the missing definitions, not a claimed recovery.
It does not reopen the frozen P0.3/P0.6/P0.7/P0.8 encodings or P0.11 handoff
recipe. Any conflict requires an explicit versioned amendment, not silent
reinterpretation. Cryptographic recipe approval is separate from subsequent
P0.10 golden-vector acceptance and later runtime/provider qualification.

All labels below are exact ASCII with no trailing NUL; all integers are unsigned
little-endian. SHA384 outputs and HMAC-SHA384 tags are 48 bytes.
The recipe covers inter-node Source/Destination only, algorithm 0x0003;
it is not a local-handoff, recovery, ECDH or TDX key-exchange construction.

#### Contribution commitments and cycle-free evidence order

Each role generates one fresh 32-byte secret using a trusted CSPRNG after
local verified tenant identity, selected policy/identity and current session
state are available. Let `ctx0` be the exact 220-byte purpose-1
`ReportDataContextV1` with its 48-byte `purpose_binding_digest` zeroed:

```text
commitment(role) =
    SHA384("SNP-LM-CONTRIBUTION-v1" || ctx0[220] || secret_role[32])
```

`ctx0` retains the actual role, request, version, algorithm, verified tenant
REPORT_ID, current SPDM TH1 and exact MA/Policy identity digest. Its zero slot
is solely the commitment-hashing convention, not the context sent as proof.
Place the computed commitment in the original purpose-1 context slot, and
obtain/verify fresh MA evidence over the existing full REPORT_DATA binding.
The verifier recomputes the commitment from the received secret and the
independently accepted role-specific context; comparing references is not enough.

The two commitments precede the P0.6 authorization context. Full MA evidence,
both commitments, approval collateral and accepted migration history may enter
the final session context only after their verification/admission. They never
feed back into commitment generation. This avoids evidence/commitment/hash
cycles and dependence on peer inputs that have not yet arrived.

#### Complete MA-evidence and approval fingerprints

Existing complete tenant-evidence and P0.6 authorization encodings remain
unchanged. For each role, define the complete MA-evidence fingerprint:

```text
SHA384(
    "SNP-LM-MA-EVIDENCE-v1" ||
    u16le(encoding: 1 = raw AMD report, 2 = SnpEmulatorV1) ||
    u32le(1540) || exact SnpMaEvidenceV1[1540] ||
    u32le(supplement_len) || exact supplement ||
    u32le(supplement_signature_len) || exact supplement signature
)
```

Raw evidence uses zero supplement/signature lengths. Emulator evidence requires
exactly 220/96 bytes, previously authenticated against the same exact report
and fixture key. Hashing an unverified supplement creates no authenticated
claims. The frozen MA record already carries the exact policy digest,
role-specific REPORT_DATA context, report and canonical report-collateral digest.
The recipe does not allocate a new wire record or transport a raw digest as proof.

For the authorization collateral that actually admitted each role:

```text
approval_digest(role) =
    SHA384("SNP-LM-APPROVAL-v1" ||
           u16le(authorization_profile) || exact accepted approval record)

FixedReleaseV1:  profile 1, exact signed FixedReleaseAllowlistV1[320]
OrderedReleaseV1: profile 2, exact signed MaReleaseEndorsementV1 snapshot

initial_authorization_digest =
    SHA384("SNP-LM-INITIAL-v1" || exact InitialMaAuthorizationV1[416])
```

Fixed mode uses zero[48] for the initial-authorization digest; it does not
invent initial-SVN semantics. Ordered mode requires the authenticated initial
record, actual tenant/history binding and compatible publisher/snapshot
admission under P0.9. Profile dispatch is authenticated local policy, never
peer metadata or a missing-record fallback. Chain/trust/revocation/validity
verification remains mandatory; these fingerprints do not replace it.

#### Canonical session context

The exact preimage is 799 bytes in this order:

| Bytes | Field |
|---:|---|
| 17 | ASCII `SNP-LM-SESSION-v1` |
| 2 | Recipe version = 1 |
| 421 | Exact accepted P0.6 `TenantAuthorizationContextV1` encoding |
| 48 | Complete source MA-evidence digest |
| 48 | Complete destination MA-evidence digest |
| 48 | SHA384(exact canonical tenant `SnpCollateralSetV1` encoding) |
| 64 | Exact accepted canonical `MigrationDataV1` bytes, identical at both ends |
| 2 | Recipe trust classification: Fixture = 1, Production = 2 |
| 2 | Recipe evidence interpretation: SnpEmulatorV1 = 1, qualified raw AMD = 2 |
| 1 | Existing TCB profile; this V1 recipe requires Venice = 3 |
| 2 | Authorization profile: FixedReleaseV1 = 1, OrderedReleaseV1 = 2 |
| 48 | Source approval digest |
| 48 | Destination approval digest |
| 48 | Initial-authorization digest, zero only for fixed profile |

The trust/interpretation values above are recipe-local discriminants, not
renumbering of existing record/provider enums. Fixture/emulator and
production/qualified-raw are the only legal combinations in this V1 contract.
Production cannot use fixture roots/supplements or the unresolved raw layout.
Reject malformed history, differing source/destination history/identity,
mixed roles/profiles/trust, missing ordered initial evidence, invalid
commitments and any mismatch with verified local operation inputs.

The P0.6 context already binds request, negotiated version/algorithm, both
roles/MA REPORT_IDs, verified tenant identity/complete-evidence digest, TH1,
both MA/Policy identity digests and both commitments. Both peers reconstruct
the full preimage independently from accepted local inputs; they do not
echo a peer's session digest. `SnpSessionReferenceV1` retains its frozen wire
shape but now references SHA384(exact 799-byte preimage).

#### HKDF and direction-specific confirmation

```text
session_digest = SHA384(canonical_session_context[799])
salt = SHA384("SNP-LM-HKDF-SALT-v1" || session_digest[48])
IKM = source_secret[32] || destination_secret[32]
PRK = HKDF-Extract-SHA384(salt, IKM)                    # 48 bytes

MSK = HKDF-Expand-SHA384(
    PRK, "SNP-LM-MSK-v1" || session_digest[48], 32)
K_destination = HKDF-Expand-SHA384(
    PRK, "SNP-LM-CONFIRM-DST-KEY-v1" || session_digest[48], 48)
K_source = HKDF-Expand-SHA384(
    PRK, "SNP-LM-CONFIRM-SRC-KEY-v1" || session_digest[48], 48)
```

Use standard HKDF-Extract/Expand, not a custom hash or MSK-derived confirmation
key. Contributions stay in source-then-destination order regardless of which
MA computes the result.

For each direction, form the exact existing 128-byte `SnpConfirmationV1` with
local request/session reference, correct sender role/direction, Confirmed = 1,
zero[48] in the tag slot, and canonical zero reserved bytes:

```text
tag_destination =
    HMAC-SHA384(K_destination,
        "SNP-LM-CONFIRM-v1" || canonical_destination_confirmation[128])
tag_source =
    HMAC-SHA384(K_source,
        "SNP-LM-CONFIRM-v1" || canonical_source_confirmation[128])
```

Insert the computed tag without changing the P0.8 record shape. Verification
checks exact local session/request, role/direction and Confirmed status, then
uses constant-time HMAC verification over the zero-tag canonical record.
Rejected records retain the existing zero tag and terminate; they are not
accepted key confirmations. Source confirmation is not chained to the
destination tag; the existing state controller separately enforces
destination-then-source verification and aborts out-of-order/duplicate messages.
An authenticated session digest/tag is not proof of installation or permission
to skip the separate purpose-3 persisted-state check.

#### Reference scope, secret lifetime and acceptance

P0.10 implements test-only Rust reference calculations and independent
deterministic vectors using explicit public fixture secrets/keys. It does not
install a default production commitment/HMAC verifier, dispatch contributions,
derive live MSKs, choose real RNG/state providers or weaken unavailable defaults.
Task 7/Task 10 must later integrate qualified providers and the sealed
authorization/contribution state into the current encrypted SPDM session.
Production contributions/PRK/MSK/confirmation keys must not enter logs or
persisted/resumable state; zeroize owned copies on completion/abort/failure,
invalidate the session after terminal failure and use fresh contributions
after re-attestation rather than reconstructing old successful state.
Public fixture intermediate values are not production-secret logging.

Recipe approval permits reference/vector implementation only. P0.10 acceptance
requires independent byte-for-byte intermediate/final agreement and the full
positive/negative matrix below, with fixture/schema/PKI/layout/provider
limitations recorded. Runtime/SPDM/firmware/durable-state and hardware gates
remain in their owning later milestones.

Execute after the handoff/recovery and emulator-supplement contracts are
frozen. Already approved freezes satisfy the corresponding contract
prerequisites; independent vector production does not require the later AAS
runtime integration.

Produce independent vectors for:

```text
canonical MaPolicyIdentityInputV1 encoding
MA_POLICY_IDENTITY_DIGEST
signed FixedReleaseAllowlistV1
fixed-release signer-chain and root validation
fixed-release manifest issue and expiration handling
canonical SnpEmulatorSupplementV1 encoding
SnpEmulatorV1 report-to-supplement binding
fixture supplement P-384 signature
base-report and supplement ETCB equality
evidence-profile and trust-domain provenance
post-install purpose-binding preimage and REPORT_DATA
planned-handoff prepare and firmware-result purpose-binding preimages
recovery prepare and firmware-result purpose-binding preimages
purpose/role/algorithm legal-combination registry
first-migration MigrationDataV1 construction
subsequent-migration MigrationDataV1 update
byte-identical source and destination MigrationDataV1
immutable INIT_MA_REPORT_ID
source and destination contribution commitments
tenant-report digest
authorization-context digest
session-context digest
HKDF salt and PRK
32-byte MSK
direction-specific confirmation keys
source and destination confirmation tags
```

Cover changes in request, TH1, tenant identity, policy, collateral,
contributions, input order, and roles. Include negative vectors for parsing
invalid migration-data bytes as initialized history, replacing any
`INIT_MA_REPORT_ID` byte, source/destination identifier disagreement, missing
previously valid history, and initial-MA authorization evidence naming a
different `REPORT_ID`. Fixed-release authorization vectors additionally cover
changed measurement, guest SVN, family/image identity, key digests,
`HOST_DATA`, SNP guest policy, LM-policy digest, signature, root, signer
purpose, validity interval, and approval status.

`SnpEmulatorV1` vectors additionally cover:

```text
exact 220-byte supplement encoding
REPORT_SHA384 over the exact 1,184-byte report
valid fixture-VCEK supplement signature
changed report after supplement signing
changed supplement after signing
CURRENT_ETCB, LAUNCH_ETCB, or COMMITTED_ETCB mismatch
MIGRATION_DATA_VALID = 0 with nonzero migration data
fixture chain replaced by a production or unrelated chain
SnpEmulatorV1 submitted to SnpHardware
raw hardware report submitted to the fixture-only provider
UnsupportedVersion6Layout and ConflictingAbiLayout hardware failures
```

Ordered-release contract/signing vectors were accepted under P0.9A2-P0.9C2.
Full cryptographic/evidence vectors must use those contracts before
cross-release or production qualification; unit fixtures alone do not close
P0.10, Task 6 or Phase 5 executable gates.

### P0.10 independent-vector validation record

Validation UTC: `2026-11-03T22:43:50Z`.
Evidence: `target/p0.10-validation/20261103T222228Z/`.
Validation manifest SHA256:
`21ee28a9595a2d2b20cc4bf97fb3ffe7b2f7ba8adce9014cc6a9630f660aa122`.
Vector acceptance was pending at validation; the user subsequently accepted
and froze this bounded evidence at `2026-11-03T22:45:46Z`.
Recipe approval or vector acceptance does not activate runtime cryptography.

The independent [Python oracle](../sh_script/test/p010_vectors.py) regenerates
137 exact named corpus entries. Default invocation checks the committed
[public fixture corpus](../src/pal/src/snp/test_data/p010_vectors.txt) without
changing it. Deterministic fixture certificates/signatures use Python
`cryptography` with `ecdsa_deterministic`/`deterministic_signing` support
(validated with 50.0.1); no dependency installation or production key was used.
Public fixed fixture private scalars are explicitly TEST ONLY.
The [Rust reference matrix](../src/pal/src/snp/crypto_vectors.rs) is included
only inside `#[cfg(test)]` MA-policy tests, not in the live verifier path.

```bash
python3 sh_script/test/p010_vectors.py
AS=nasm AR=llvm-ar CC=clang cargo test --locked --offline \
  -p pal --features snp-emu crypto_vectors
# Deliberate corpus regeneration only; review before accepting changed vectors:
python3 sh_script/test/p010_vectors.py --write
```

| Contract/output group | Independent/reference evidence |
|---|---|
| Identity and fixed approval | Exact 280/320-byte codecs, identity/policy/root/signer digests, real P-384 allowlist signature and fixture root/intermediate/leaf signatures |
| Fixed authorization negatives | Authentic re-signed reports with each fixed identity field changed; LM-policy mismatch; every allowlist byte; root/purpose/order/chain-byte mutations; validity boundaries |
| Emulator supplement | Exact 220/96 bytes, base-report P-384 signature and complete report digest; every report/supplement/signature byte; valid re-signed ETCB/history inconsistencies and initialized-history positive |
| Provenance/layout boundary | Wrong fixture key/chain/purpose and production trust rejection; reference profile dispatch rejects crossed trust/evidence and both unresolved-layout cases |
| Purpose bindings | Exact post-install preimage/REPORT_DATA; planned/recovery prepare/result preimages; planned incoming and outgoing REPORT_DATA; all 60 purpose/role/algorithm combinations with exactly 8 legal |
| History | Exact first/subsequent 64-byte results, missing previously valid history, every installation-history byte, immutable initial identity and initial-authorization disagreement |
| Commitments/evidence | Both fresh fixture secrets, zero-slot commitment contexts, computed commitments/full REPORT_DATA; complete raw/emulator tenant and MA-evidence digests |
| Authorization | Existing sealed raw-report bridge with real fixture report signatures, exact 421-byte codec/digest; independently authenticated supplement reference encoding without minting a common-adapter receipt |
| Ordered collateral | Exact 304-byte snapshot/416-byte initial record, accepted signature-message domains, SEC1-based signing-key IDs, real signatures and signed-message mutations |
| Session/HKDF | Fixed and ordered emulator 799-byte contexts, session digest, salt, source-then-destination IKM, real PRK, MSK32 and both 48-byte expansion keys |
| HMAC/failure sequencing | Both exact 128-byte zero-tag/final records and real tags; every session byte changes MSK/tag; contribution order/labels; every confirmation byte, crossed keys, out-of-order/duplicate rejection and unavailable persisted-state/default verifiers |

Final validation:

```text
PAL TAV:       301 unit tests + 15 doctests passed
PAL Azure:     302 unit tests + 15 doctests passed
PAL default:    25 unit tests +  5 doctests passed
New P0.10:      14 tests discovered/passed in each SNP backend
MigTD SNP:      64 library tests passed
TDX:            spdm_attestation + policy_v2 cargo check passed
Format:         targeted check passed
Clippy:         PAL all-targets Azure/SNP check passed; no new reference warnings
Preservation:   exact execution-order section, prior log prefix and readiness ledger
                unchanged; frozen modules unchanged except declared trait comments
```

Early fixture checks exposed the missing length prefix in the oracle's
pre-existing LM-policy digest, insufficient certificate outer-algorithm/unused-bit
checking, TAV's RSA-only generic signature-algorithm accessor, and a misplaced
outgoing-vector test block. These were fixed in the new reference/oracle code;
the failed diagnostic logs are retained alongside successful final reruns.
No production/runtime logic was changed to make a fixture pass.

The accepted evidence closes the missing commitment/session/KDF/HMAC authority
and independent cryptographic known-answer scope. It does not
qualify a production schema, RFC 5280/revocation/time/root rollover provider,
AMD raw-layout parser or common claims adapter. The fixture chain performs
real signatures and fixture-purpose/CA/key/validity checks, not a claimed
general-purpose production PKI implementation. Policy-schema and durable-store
admission adapters remain explicit test models. Hardware/provenance dispatch
is a contract reference, not an executed hardware verifier.
Supplement transport/sealed claims, trusted state/replay/secret lifetime,
SPDM composition, persistence and hardware gates remain in Tasks 6-13/R4/H5.
No default unavailable verifier was replaced; no runtime activation, release
binary, live EMU scenario, full CI, hardware test, commit or push is claimed.

## P0.11 Freeze local handoff and recovery contracts

Active recipe supersession: [T4.14-PRE](snp/task4/t4.14-pre-direct-random.md)
replaces seed/HKDF generation below with direct independent outgoing random32.
The32-byte operand, protected transfer, operation/slot lifecycle, cleanup,
authority clarification and incoming-only recovery remain. Historical recipe
and acceptance evidence are not rewritten or treated as V2 validation.

Status: DONE - ACCEPTED AND FROZEN for logical contracts/codecs and
provider-gated conformance. No runtime activation.
Prerequisites: accepted P0.2/P0.4/P0.9 and P0.9D.

Freeze identifier: `P0.11-LocalHandoffRecoveryV1-2026-11-03`.
Accepted UTC: `2026-11-03T18:20:12Z`. Conditions: None.

Accepted clarification: `P0.11-RequestAuthorityV1.1-2026-11-03`.
Status: ACCEPTED AND FROZEN on `2026-11-03T22:06:49Z`; conditions: None.
The original V1 freeze and its historical acceptance remain intact.
This clarification supersedes V1's initiator/shutdown-authority wording, changing the
blanket requirement for a separately authenticated coordinator principal into
independently established operation authority, using the TDX architectural
distinction between requesting work and authorizing a replacement. It changes
no wire bytes, cryptographic recipe or runtime activation state. Deployments
must establish the complete operation authority and safety conditions below;
acceptance is not proof that an actual SNP provider enforces them.

The local handoff contract is separate from the inter-node migration-key
protocol.

P0.8 registry coordination: preserve record types `0x0006`/`0x0007` and
inter-node elements `0x0105`/`0x0106`. Final inter-node SPDM scheduling/opcodes
remain a separate T4.12/Tasks 10-12 gate, not a local handoff transport.

The current emulator milestone qualifies same-release handoff only:

```text
outgoing MA_POLICY_IDENTITY_DIGEST ==
    policy-selected FixedReleaseV1 identity

incoming MA_POLICY_IDENTITY_DIGEST ==
    policy-selected FixedReleaseV1 identity
```

Cross-release handoff is outside this milestone. Accepted P0.9A2/P0.9B2/P0.9C2
provide its collateral prerequisites, not activation authority; separate
cross-release integration, authoritative initial/current tenant-history binding
and qualification remain required.

### Local control codec V1

Implemented in `src/pal/src/snp/local_handoff.rs`. The following kinds have
local `u16le` discriminants 1 through 12, in this order:

```text
PrepareMaHandoffRequest
MaHandoffReady
MaRebindResult
ConfirmRebindResult
FinalizeMaHandoff
AbortMaHandoff
QueryMaHandoffStatus
RetryMaRebind

PrepareMaRecoveryRequest
MaRecoveryReady
ConfirmRecoveryResult
FinalizeMaRecovery
```

This is an isolated local-control namespace, not new global SNP record IDs,
SPDM opcodes or VDM elements. Integers are unsigned little-endian. Every
record has this exact header and suffix:

| Offset | Bytes | Field |
|---|---:|---|
| 0 | 8 | ASCII `SNP-MA-L` |
| 8 | 2 | Version = 1 |
| 10 | 2 | Local kind = 1..12 |
| 12 | 4 | Exact total record length |
| 16 | 1 | Mode: Planned = 1, Recovery = 2 |
| 17 | 1 | Existing P0.3 role: Outgoing or Incoming |
| 18 | 1 | Logical phase, below |
| 19 | 1 | Logical status, below |
| 20 | 2 | Exact P0.3 binding length |
| 22 | 2 | Reserved, zero |
| 24 | 8 | Opaque previous-MA handle |
| 32 | 8 | Opaque incoming-MA handle |
| 40 | 8 | Opaque tenant handle |
| 48 | variable | Exact existing `LocalHandoffBindingV1`, including purpose domain |
| following binding | 104 or 0 | Exact `FirmwareRebindResultV1`, only for `MaRebindResult` |

The existing binding carries operation ID[16], request ID u64, epoch u64,
deadline u64, attempt u32, previous/incoming instance REPORT_ID[32] each,
tenant-set digest[48], fixed-release identity digest[48], stage and result-set
digest[48]. Its P0.3 encoding and domain strings are unchanged.

Logical phases are Unprepared = 0, Prepared = 1, Ready = 2, Partial = 3,
Confirmed = 4, Complete = 5, Aborted = 6, ReconciliationRequired = 7.
Logical statuses are Success = 0, Pending = 1, Retryable = 2, Terminal = 3,
Indeterminate = 4, Unavailable = 5. They are NOT AMD firmware status codes.
Host phase/status fields are informational, never transition authority.

Decoding is exact and bounded to 512 bytes: reject unknown kinds/enums,
nonzero reserved bytes, wrong lengths, trailing data, invalid result shape,
wrong purpose/stage and planned/recovery confusion. Recovery accepts only
Incoming. Abort/Query/Retry and result observations are shared; the four
recovery-specific kinds cannot be used in planned mode or vice versa.
Prepare/Ready/Retry use the prepare stage; result/confirm/finalize use the
result-confirmation stage. Query and Abort preserve the current stage.

The security-relevant fields reconstruct the exact P0.3 purpose preimage.
Opaque routing handles and transport framing are not included in that
preimage. Host-control messages never contain the handoff secret.
Receiving a well-formed record does not execute an operation. Runtime
dispatch, authenticated peer scheduling, transport framing and replies remain
R4.2/R4.3/R4.5 implementation work. Query is a read of logical status, not
proof that firmware state or cleanup succeeded.

### Frozen protected metadata descriptor V1

`LocalMetadataSnapshotV1` describes, but does not itself authenticate or
transfer, the complete frozen tenant evidence and retained replay packages.
It is for the protected local peer path, not plaintext host control or audit
logs. Its exact encoding is:

| Offset | Bytes | Field |
|---|---:|---|
| 0 | 8 | ASCII `SNP-MA-M` |
| 8 | 2 | Version = 1 |
| 10 | 2 | Reserved, zero |
| 12 | 4 | Exact total length |
| 16 | 4 | Tenant count, 1..32 |
| 20 | 200 each | Sorted unique tenant entries |

Each entry is, in order: tenant REPORT_ID[32], digest[48] of the complete
canonical authenticated tenant evidence, MIGRATION_DATA_VALID u8 (0 or 1),
seven zero bytes, exact MIGRATION_DATA[64], and digest[48] of the retained
authenticated replay/journal snapshot. Valid history must decode as the
frozen MigrationDataV1; invalid history requires all 64 bytes zero. Referenced
evidence/replay packages must use their own accepted complete canonical
encoding, not raw-report-only hashes or host-selected journal summaries.

Maximum encoded size is 6420 bytes (20 + 32*200), within the existing 8 KiB
application limit including the existing 10-byte application framing.
Metadata digest is SHA384(`"SNP-MA-METADATA-v1"` || exact metadata record).
Canonical order/count and every history byte are checked. Debug formatting
redacts entry contents. Descriptors contain no MSKs, seeds, handoff secrets,
SPDM/TLS keys or live-session resume state. Actual package acquisition,
protected transfer, verification, retained journal lifetime and durable
readiness acknowledgement belong to the trusted runtime provider. Both MAs
must acknowledge this SAME snapshot digest in their authenticated operation;
the digest is not a new field in the frozen P0.3 purpose preimage.

### Handoff-secret construction

For Version 1:

```text
random_seed = CSPRNG(32 bytes)

context_hash = SHA-384(
    "SNP-MA-HANDOFF-v1" ||
    handoff_id ||
    outgoing_ma_REPORT_ID[32] ||
    incoming_ma_REPORT_ID[32] ||
    tenant_set_digest ||
    policy_digest
)

handoff_secret = HKDF-SHA384(
    salt = context_hash,
    IKM  = random_seed,
    info = "SNP-MA-HANDOFF-SECRET-v1",
    L    = 32
)
```

The two identity operands above are authenticated MA instance REPORT_IDs,
not opaque handles, certificate fingerprints or 48-byte release digests.
The separate policy digest is the exact verified P0.9 LM-policy digest;
release eligibility remains a distinct fixed-release check.

The old MA generates the secret. It is transferred only inside the local
authenticated encrypted SPDM session and installed as outgoing/incoming using
`MSG_SET_HANDOFF_SECRET` semantics.

The plaintext secret may exist only in:

```text
old MA protected memory
encrypted local peer session
new MA protected memory
firmware-maintained MA guest-context state
```

It is never logged, persisted, or exposed to BASE/Hyper-V. Both MAs explicitly
clear it with `VALID=0` after success, abort, timeout, or terminal failure.

`HandoffSecretV1` implements this HKDF construction with real ring crypto and
explicit trusted RNG/protected-secret interfaces. Generation requires a
first-attempt Prepared planned contract; recovery has no compatible secret
constructor. Retries reuse the existing protected operation secret, not a
new random seed. Seed/output buffers zeroize; the secret is non-cloneable,
has no public byte getter or host codec, and Debug is redacted. This does not
claim compiler/register or cryptographic-library internal erasure.

Installation reappraises current operation, phase, deadline, epoch, attempt,
policy and authenticated session; a delayed object is not installation
authority. Conflicting replacement of an existing operation slot is denied.
The protected sink installs outgoing, transfers only through authenticated
encrypted LocalMaHandoff SPDM, installs incoming, and acknowledges the
matching slots. On installation failure, the helper requests two-slot
cleanup; a cleanup failure is returned explicitly. Runtime guards must also
clear slots on success, abort, timeout, crash/restart reconciliation and
terminal failure. Dropping this logical model clears NO firmware slots.

### TDX comparison and P0.11 deployment requirements

This comparison covers the ten deployment items discussed after the V1
freeze. It is an assessment of the current checkout, not a claim that TDX
qualifies SNP firmware behavior. TDX's VMM receives no authorization merely
by delivering a request. MigTD evaluates attested peer policy/session state;
the old MigTD submits target-bound module approval and the replacement records
the token/attributes through TDX calls. Host orchestration is a separate plane.

Direct reference surfaces:

- [session.rs](../src/migtd/src/migration/session.rs), `parse_request`: bounded VMM
  `StartRebinding` decoding and dispatch, not coordinator identity verification.
- [rebinding.rs](../src/migtd/src/migration/rebinding.rs), `start_rebinding`: initial-policy
  binding checks where applicable, peer transport and old/new preparation.
- [mig_policy.rs](../src/migtd/src/mig_policy.rs), `authenticate_rebinding_new` and
  `authenticate_rebinding_old`: authenticated peer policy/evidence appraisal.
- [spdm_req.rs](../src/migtd/src/spdm/spdm_req.rs) and
  [spdm_rsp.rs](../src/migtd/src/spdm/spdm_rsp.rs): rebind TDREPORT/TH1
  checks, token exchange and replacement token/attribute preparation.
- [rebinding.rs](../src/migtd/src/migration/rebinding.rs), `approve_rebinding`: old MigTD's
  binding-handle/target-TD/token approval; `create_rebind_token`: trusted random
  generation. The RA-TLS alternative retains peer authentication/token flow.

These findings do not establish a TDX counterpart for every SNP requirement.
In particular, the examined flow does not implement P0.11's complete
multi-tenant reconciliation, durable replay, slot cleanup, explicit shutdown
or no-live-old-MA SNP recovery contract. Do not copy gaps or technology-specific
fields into SNP as a simplification.

| # | Deployment item | TDX implementation approach | Revised P0.11 requirement / remaining input |
|---|---|---|---|
| 1 | Who may initiate | VMM supplies routing/request data; attested MigTD policy and target-bound module approval authorize replacement, not a VMM credential. | Accepted V1.1: BASE may request work without a new coordinator credential. A trusted MA/provider independently establishes tenant/operation authority from approved policy, authenticated bindings and applicable firmware controls. If those controls are insufficient, require an approved additional authority mechanism; never silently accept the host's scope. |
| 2 | Local SPDM trust | MigTD authenticates peer evidence/policy and actual TH1; the inspected application path is not evidence for a separate coordinator PKI. | Retain the frozen LocalMaHandoff mutual-authentication/algorithm suite. Reuse approved attestation/peer-trust configuration where compatible; supply exact root, purpose, role and lifecycle rules. Do not introduce coordinator certificates just because SPDM is used, or substitute TDX TDREPORT/QVL checks for SNP verification. |
| 3 | Replacement eligibility | Signed policy, authenticated report/event-log state and forward/backward rebinding checks determine peer eligibility. | Use existing P0.9 verified policy/collateral and fresh P0.3 purpose-4/5 evidence. Supply the selected fixed identity and platform floors; retain same-release planned scope and separate firmware recovery equivalence. No second policy/identity system. |
| 4 | Trusted providers | TDX paths use existing transport, attestation/policy and module-call helpers; no new platform authority is inferred from host metadata. | Compose existing approved SNP providers where available, with explicit MA operation authority, bindings, secrets, time, randomness and durable-state boundaries. Emulator replaces effects, not authorization semantics. Missing real providers fail closed. |
| 5 | Operation policy | Rebind exchange uses bounded 60-second transport/session waits; these are not proof of firmware non-effect or crash recovery. | Keep the frozen absolute deadline, exact operation/epoch/attempt and fail-closed lifecycle. Supply deployment time budgets; do not mandate a new timeout policy service or blindly copy TDX's constant. Expiry stops advancement but permits cleanup/reconciliation. |
| 6 | Production retries | The inspected token/approval exchange does not qualify SNP firmware retry statuses or multi-tenant effects-once behavior. | Keep the empty production whitelist until authoritative AMD mapping and R4/H5 tests qualify each permitted case. Retry only unchanged failed bindings; retain successes and increment the attempt exactly. |
| 7 | Old-MA shutdown | Rebind helpers prepare/approve, close transport and report status; they do not prove safe termination of an entire multi-tenant MA. | Preserve all-tenant confirmation/reconciliation/cleanup gates. BASE supplies lifecycle intent, not proof of safety. Under accepted V1.1 the provider checks that intent against the exact operation and independent completion facts; a separate shutdown-principal credential is not mandatory unless deployment policy requires it. Actual lifecycle orchestration remains BASE-owned. |
| 8 | Audit | Existing request-correlated logging/status paths provide diagnostics, not module authorization or durable replay. | Reuse repository logging/status mechanisms for nonsecret correlation. Production chooses access, retention and failure treatment; no new audit authority service is required by P0.11. Protected evidence, metadata and secrets stay out of logs. |
| 9 | Recovery | The inspected TDX path requires a live old MigTD to approve the token; it is not a no-live-old-MA recovery precedent. | Retain incoming-only purpose-5 evidence and authoritative SNP firmware identity/launch equivalence. No old/new SPDM or secret. Supply actual binding/state/result observations and qualified recovery controls; if unavailable, deny. |
| 10 | Production activation | TDX module calls and a working peer exchange do not qualify a different architecture's firmware, persistence or deployment. | Keep R4/H5 implementation and qualification gates, the AMD production-layout blocker and explicit image/provider hygiene. Reuse architecture, not TDX ABI/security assumptions. Record separately what fixed, ordered and recovery capabilities actually pass. |

#### Request authority versus orchestration

BASE/Hyper-V requests, endpoints, handles, host statuses and lifecycle messages
are untrusted inputs with inherent denial-of-service capability. They are not
evidence that replacement, cleanup or shutdown is authorized or complete.
The MA/provider reconstructs the exact operation locally, authenticates the
tenant-to-current-MA binding and replacement eligibility, and refuses wrong
tenants, roles, instances, policy, epochs, attempts and snapshots.

For planned handoff, the outgoing MA authorizes the protected secret only after
those checks, transfers it to the accepted incoming MA over the authenticated
local session, and obtains verified installation/readiness observations.
For recovery, no outgoing MA grants that authority: independently verified
replacement policy and authoritative firmware recovery equivalence/state must
establish it. A host statement that the old MA failed grants no permission.

No separately authenticated BASE principal is inherently required by accepted
V1.1. Where an existing platform mechanism covers the complete authorization
boundary, use it rather than invent a parallel identity infrastructure.
Where it does not, qualification must identify the gap and obtain an approved
additional authority mechanism. A trusted Rust callback is not itself proof
that the production mechanism exists.

TDX's per-target old-MA approval cannot be assumed for SNP. Matching SNP MA
handoff secrets alone do not prove the exact tenant-set digest, request, epoch,
deadline, metadata, all-tenant completion or current policy. The provider must
establish those facts independently and qualify the scope of effects obtainable
through the firmware command path. Shared MA secret state must not authorize an
unaccounted tenant or be overwritten/cleared by another concurrent operation.
Serialize/reserve affected MA secret state as well as tenant ownership until
cleanup/reconciliation, and independently verify the full remaining binding
inventory before old-MA shutdown. If the platform cannot establish these facts,
it cannot claim safe scoped handoff or completion.

#### What each P0.11 contract still needs

| Contract / stage | Required inputs and implementation | Gate retained after TDX comparison |
|---|---|---|
| Host control | Existing exact local records, bounded dispatch/framing, operation correlation, opaque endpoint/handle routing and BASE lifecycle requests. | Decoding authenticates neither requester nor scope; reconstructed operation authority is required before accepting effects. |
| MA eligibility and purpose evidence | Current P0.9 policy/approval, selected fixed identity/platform rules, authenticated REPORT_IDs and fresh purpose-4 planned or purpose-5 recovery context. | Both planned roles or incoming-only recovery; all purpose/session/policy checks retained. |
| Tenant set and metadata | Authenticated tenant/current-MA inventory, exact frozen set/descriptor, complete evidence and replay packages, protected transfer and same-snapshot acknowledgement. | No host-selected scope; all history bytes and validity preserved; 32-tenant/6420-byte bounds unchanged. |
| Local peer session | Dedicated outgoing-requester/incoming-responder SPDM with approved attestation trust, actual TH1, fresh evidence and encrypted application scheduling. | No coordinator-PKI invention; no inter-node message/session mixing; absent in recovery. |
| Handoff-secret lifecycle | Existing frozen HKDF, trusted RNG, protected outgoing/incoming installation/transfer, current-operation checks and acknowledged clearing. | No token/recipe substitution from TDX; reserve affected MA state; no host secret, conflicting operation or retry regeneration. |
| Readiness and rebind | Both authenticated readiness acknowledgements, qualified current state/secret observations and host-to-firmware execution with authoritative per-tenant outcomes. | Host Ready/success flags do not open gates; canonical serial processing, effect-scope validation and no successful-tenant reissue. |
| Result confirmation | Fresh result-stage evidence over the exact complete outcome set, actual bindings and unchanged persisted history. | Results are not accepted solely because the host or installer returned success. |
| Retry/idempotency | Anchored durable operation state, qualified status mapping, authoritative failed-binding checks and fresh approvals. | Empty production retry whitelist until qualified; same operation/snapshot, attempt+1, cumulative successes and no rollback. |
| Abort/crash reconciliation | Current firmware inventory, retained authenticated journal, explicit cleanup acknowledgement and fresh authorization after session/restart loss. | No resumed secret/session from logs, no assumed non-effect, no firmware cleanup claim from model Drop. |
| Finalization/shutdown | Independent all-tenant completion, remaining-binding inventory, confirmations and cleanup, plus correlated BASE lifecycle intent under deployment policy. | Lifecycle request cannot bypass safety gates; the model neither terminates the old MA nor authenticates a new coordinator credential. |
| Recovery | Incoming purpose-5 approval, authoritative failed/current binding and qualified firmware identity/launch/state equivalence. | No live old MA, old/new SPDM or secret; no TDX recovery inference or report-layout fallback. |
| Audit and deployment | Existing nonsecret logging/status, operational access/retention configuration, real provider tests, production image and hardware evidence. | Logs/model tests are not authority or qualification; R4/H5 remain the only relevant activation/qualification gates. |

P0.11 therefore needs approved operation/policy inputs and trusted providers,
not a mandatory new BASE identity service. Exact authorization coverage and
recovery/state/effect observation remain platform qualification questions.
This clarification does not start R4, H5 or P0.10, select real credentials/providers,
or qualify SNP enforcement from the TDX comparison.

### Planned-handoff policy

V1 freezes these conservative rules:

| Surface | Required contract |
|---|---|
| Eligibility | Both planned approvals use P0.9 fixed-release receipts under the same exact current policy and identity, with independently appraised SNP platform TCB/ETCB, guest policy/debug and version floors. No ordered receipt fallback. |
| Initiator / operation authority | Accepted V1.1: BASE requests work but supplies no authority. A composition-selected trusted provider independently authorizes the exact tenant/MA/operation using authenticated policy/bindings and applicable firmware controls. No separate BASE credential is mandatory if those mechanisms cover the boundary; uncovered authority or missing providers deny. |
| Local SPDM | Dedicated `LocalMaHandoff` session: outgoing requester, incoming responder, SPDM 1.2 mutual authentication, ECDSA P-384, SHA-384, ECDHE P-384, AES-256-GCM. Both ends verify exact P0.3 purpose-4 evidence and actual session TH1. |
| Trust/purpose | Roots and chain/purpose/role policy are explicit composition-selected trusted providers, isolated from fixture keys, inter-node and other sessions. No implicit OS/host root or invented production certificate acceptance. Unavailable providers deny. |
| Tenant scope | Nonempty, sorted, unique, sealed authenticated tenant IDs; exact count/digest and frozen descriptor throughout the operation. Inventory changes require abort/reconciliation and a new authorized operation. |
| Metadata/readiness | Verify complete referenced evidence/replay state and the same descriptor digest, actual matching slots, both fresh approvals and both readiness acknowledgements before any rebind. A host Ready flag cannot open this gate. |
| Firmware scheduling | One tenant rebind at a time in canonical REPORT_ID order; no concurrent operations for one tenant and no reissuing already-successful tenants. Durable ownership reservation/CAS belongs to the provider. Accepted V1.1 additionally makes affected MA secret-state reservation and firmware effect-scope qualification explicit; host-selected inventory is not authority. |
| Retry classes | V1's PRODUCTION retry whitelist is empty pending authoritative AMD status mapping and R4/H5 qualification. Never infer retryability from a nonzero raw status or a host logical `Retryable` tag. The fixture whitelist is test-only. |
| Partial ownership | Successful tenants belong to incoming; failures remain outgoing only after authoritative unchanged-binding appraisal. Preserve split ownership and every history byte. Never automatically roll back successful rebinds. |
| Retry | Require explicit provider authorization, currently recognized retryable status, authoritative unchanged failed binding/history, same epoch/operation/snapshot and attempt exactly previous+1 without wrap. Fresh purpose-4 prepare evidence is required again. |
| Idempotency | Exact immediate duplicate commands re-enter trusted current-state/idempotency appraisal; no cached success bypass. Provider anchors operation/request/epoch/attempt and effects durably. Conflicting or stale replays deny; process memory is not rollback protection. |
| Abort/failure | Stop new work; reconcile observed per-tenant ownership, acknowledge slot cleanup and retain necessary protected journal state. An expired operation may request cleanup/abort but cannot finalize successfully. Unknown outcomes become ReconciliationRequired, not assumed failure or success. |
| Shutdown | Require all tenant successes and incoming confirmations, terminal reconciliation and acknowledged two-slot cleanup. Accepted V1.1 interprets the BASE gate as correlated lifecycle intent under deployment policy, independently checked against completion and remaining bindings, not a mandatory coordinator credential. Complete means eligible for lifecycle shutdown; this model never shuts down an MA. |
| Crash/restart | No automatic resume from host logs, no persisted secret/seed, no cached readiness. Reappraise firmware bindings/history and the anchored journal, clear surviving temporary slots, reconcile split ownership, and obtain fresh authorization. Ambiguous state remains closed. |
| Active migration | Default abort/re-attest/restart for any in-flight inter-node migration. No live-session/key transfer or resume without a separately approved exact authenticated resume contract. |
| Audit | Record operation/request/epoch/attempt, transition/outcome, counts and nonsecret correlation digests under deployment audit policy. Never emit secrets, raw protected metadata, evidence bodies or journal contents. Logging is not an authoritative state store. |

`PlannedHandoffContractV1` and `RecoveryContractV1` are distinct public types.
Their private common logical model enforces:

```text
Unprepared --Prepare--> Prepared --Ready--> Ready
Ready --Results(all success)--> Confirmed --Finalize--> Complete
Ready --Results(partial/all failed)--> Partial --Retry--> Prepared
nonterminal --Abort with cleanup/reconciliation--> Aborted
provider failure or authoritative mismatch --> ReconciliationRequired
```

Results contain exactly one canonical outcome per frozen tenant, including
unchanged prior successes on later attempts; no missing, reordered or
substituted entries. Result evidence binds the exact complete result-set
digest and stage. Logical success/failure shapes are checked against actual
provider-authenticated current bindings, not host-proposed firmware results.
Unknown outcomes cannot enter an accepted result set.

Core checks include exact binding/policy/role/REPORT_ID, fixed-only receipts,
operation stage and current-context proof, unchanged TH1, cumulative result
consistency, and all 64 authoritative history bytes plus the validity flag.
Prepare/Retry/Results require fresh stage-specific approvals; Ready and
Finalize still re-enter the provider. The `now` parameter is trusted
composition time, never a host timestamp; the provider independently owns
trusted current time and current policy/PKI/revocation appraisal at every
transition. A previously verified P0.9 receipt is not a freshness proof.

`LocalHandoffAuthorityV1` is the explicit trusted boundary for all external
effects/current facts above. Runtime composition, not the peer, selects it;
its default is `UnavailableLocalHandoffServicesV1`, which fails closed for
transition, RNG and secret services. Logical tests supply explicit fixtures.
They do not establish durable replay, actual readiness, slot cleanup,
firmware equivalence, SPDM root policy or shutdown authorization in deployment.
Under accepted V1.1, this provider's authority means independently authorized
operation/state and completion, not automatic trust in a BASE principal.

Planned handoff is complete only when:

```text
replacement MA accepted
AND tenant set frozen
AND metadata verified
AND matching secrets installed
AND both MAs ready
AND all required firmware rebinds succeeded
AND new MA confirmed each successful tenant
AND partial failures reached a policy-approved terminal state
AND temporary secrets were cleared
AND BASE lifecycle intent satisfies the independently verified shutdown gate
```

The last condition uses accepted V1.1 terminology; original V1 required
explicit BASE shutdown authorization. Neither interpretation lets a host
request stand in for completion, cleanup or remaining-binding appraisal.

### Recovery distinction

Recovery has:

```text
no live old MA
no old-to-new SPDM
no handoff secret
host orchestration
firmware identity and launch-state equivalence checks
fresh P0.3 purpose-0x05 incoming-MA prepare evidence
fresh P0.3 purpose-0x05 firmware-result confirmation evidence
```

Recovery is a distinct state machine and test suite. It follows the frozen
P0.3C recovery contract and cannot fall back to planned-handoff evidence or
requirements.
It uses the same conservative serial/result/retry/reconciliation skeleton,
but never demands an outgoing approval, old/new session or matching secret
slots. Fresh purpose-5 incoming receipts use zero TH1 and algorithm None.
The failed instance comes only from authoritative current binding; replacement
approval alone does not establish the AMD-required identity/launch-state
equivalence. The trusted firmware-state provider must separately prove that
equivalence, report effects and unchanged history. Without that provider,
recovery is unavailable, not a bypass around planned-handoff checks.

### Migration history during planned handoff and recovery

Version 1 preserves the tenant's existing `MIGRATION_DATA` unchanged during
both planned handoff and recovery:

```text
SNP_REBIND_MA changes the tenant-to-MA binding.
MSG_SET_HANDOFF_SECRET changes only the handoff-secret state.
Neither operation updates MIGRATION_DATA.
```

Rules:

- do not invoke `MSG_SET_MIGRATION_INFO` merely to mutate history during
  rebind;
- do not claim that handoff or recovery updates `INIT_MA_REPORT_ID`, historical
  minima, or mitigation history;
- under `FixedReleaseV1`, planned handoff requires outgoing and incoming MAs
  to match the same policy-selected identity exactly;
- under `FixedReleaseV1`, recovery requires only the verified replacement MA
  to match that identity; the failed MA identity comes from authoritative
  binding state and is not represented by fresh outgoing-MA evidence;
- under future `OrderedReleaseV1`, evaluate outgoing, incoming, and initial MA
  no-rollback using P0.9B2;
- any future requirement to mutate history during rebind requires an AMD ABI
  mechanism and a new migration-data/profile version.

### P0.11 acceptance and downstream gates

Validation evidence: `target/p0.11-validation/20261103T174528Z/`.
Eighteen new handoff/recovery tests and one recovery/secret compile-fail
doctest pass. The focused selector runs 19 tests including one existing
local-role test. Full regression results:

| Gate | Result |
|---|---|
| PAL with TAV backend | 287 tests, 15 doctests; emulator 7 tests |
| PAL with Azure backend | 288 tests, 15 doctests; emulator 7 tests |
| Default PAL | 25 tests, 5 doctests |
| MigTD SNP selector | 10 tests, 55 filtered |
| Targeted formatting, PAL/emulator and MigTD Clippy | PASS; existing unrelated warnings retained, no new local-module diagnostics |
| Default TDX compatibility check | PASS |
| SnpEmuAzure release-musl build | PASS |
| Serial legacy Stage A and Stage B | PASS; existing migration runtime only, not a local-handoff integration test |

Conformance covers all twelve kinds, strict decode negatives, exact maximum
6420-byte metadata/32-tenant limit, independently computed control/metadata/
HKDF fixture vectors, planned/recovery separation, stage/context/TH1 mutations,
all 64 history bytes and validity/binding changes, cumulative partial results,
retry attempts/status denial, reappraised duplicates, deadline/abort and
provider/cleanup/shutdown failures. Fixture keys, RNG seed and observations
are explicitly test-only; no real AMD firmware effect is asserted.

Accepted scope covers the inline V1 contract, Rust logical types/exact codecs,
independent control/metadata/HKDF vectors and provider-gated conformance tests.
It does NOT activate host dispatch, MA-profile SPDM scheduling, an SNP
binding/secret-slot emulator, production trust/time/durable state providers,
physical rebind/recovery or crash qualification. R4.1-R4.5 and H5 retain these
implementation/qualification gates, including the unresolved production
Version-6 physical-layout conflict. P0.10 consumes this frozen construction
only after explicit P0.11 acceptance; no next milestone starts automatically.

## P0.12A Freeze the shared AAS report-verifier boundary

P0.4 consumer gate: the common authenticated TCB representation and AAS adapter
must explicitly accommodate Venice FMC/TEE/SNP per Firmware ABI 1.59 Table 3.
The older four-field sketch below is not a valid Venice mapping. Reconcile
and freeze that family-aware amendment before AAS1A-M closes; do not encode
FMC as a boot loader or synthesize a microcode component.

Status: APPROVED AND FROZEN for the common API and `SnpEmulatorV1` on
2026-11-02

Freeze identifier: `P0.12A-SnpEmulatorV1-2026-11-02`

Finalization addendum identifier:
`P0.12A1-CommonVerifierBoundary-2026-11-02`

The addendum is additive to the original emulator evidence freeze. It freezes
the MigTD-owned leaf types, AAS adapter ownership, and the basic TDX/common-TEE
architectural boundary without changing the existing TDX implementation.

Production physical-layout status: BLOCKED on AMD clarification of the
Firmware ABI 1.59 ETCB versus ARG ABI v1.20 `MIGRATION_DATA` overlap.

Freeze the typed boundary consumed by MigTD peer-MA and tenant-report
authorization. This contract is required by the emulator and production MA,
and does not depend on the production composite relying-party envelope.

Define the common types:

```rust
trait SnpReportVerifier {
    fn verify(
        &self,
        request: SnpReportVerificationRequest,
    ) -> Result<AuthenticatedSnpClaims, SnpReportVerificationError>;
}

enum SnpEvidenceProfile {
    SnpEmulatorV1,
    FirmwareAbi159V6,
    ArgAbi120MigrationOverlayV1,
}

enum SnpTrustDomain {
    Fixture,
    ProductionAmd,
}

enum SnpReportVerificationRequest {
    GuestRequestedMa {
        evidence: SnpEvidenceInput,
        collateral: SnpCollateralInput,
        expected_vmpl: u32,
        expected_report_data: [u8; 64],
    },
    HostRequestedTenant {
        evidence: SnpEvidenceInput,
        collateral: SnpCollateralInput,
    },
}

enum SnpEvidenceInput {
    EmulatorV1(SnpEmulatorEvidenceV1),
    RawAmdReport {
        report: [u8; 1184],
    },
}

struct SnpEmulatorEvidenceV1 {
    report: [u8; 1184],
    supplement: [u8; 220],
    supplement_signature: [u8; 96],
}
```

MigTD owns every type in the public `SnpReportVerifier` signature, the
authenticated claims, provenance, and stable errors. AAS may keep different
internal request, collateral, parser, certificate, and claim types. The
MigTD AAS adapter performs an explicit, fail-closed mapping from AAS-native
authenticated output into these MigTD-owned types. MigTD does not pass its Rust
type definitions to AAS at runtime, and unfinished or later-changing AAS APIs
do not redefine the migration protocol.

Freeze the referenced leaf types:

T4.9 approved semantic addendum (2026-11-03): the older four-field
`AuthenticatedTcb` sketch below is superseded by an explicit tagged
representation, not used as a Venice encoding. `MilanGenoa` has boot loader,
TEE, SNP and microcode; `Turin` additionally has FMC; `Venice` has exactly
FMC, TEE and SNP, matching the existing P0.4 codec. No component is synthesized.
The common request also gains `GuestRequestedTenant` with independently
supplied expected VMPL and all 64 expected REPORT_DATA bytes, for fixture/
emulator verification only. The existing two request meanings and active
host-zero V1 path are unchanged. Implementation:
[snp_report.rs](../src/pal/src/snp_report.rs). Public requests borrow immutable
evidence/collateral; this Rust ownership choice changes no wire format.
The user explicitly approved both additions with no conditions before coding.
Neither addition qualifies the AAS adapter or production parser.

```rust
struct SnpCollateralInput {
    expected_trust_domain: SnpTrustDomain,
    leaf_certificate_der: Vec<u8>,
    intermediate_certificate_der: Vec<u8>,
    root_certificate_der: Vec<u8>,
    revocation: SnpRevocationInput,
    verification_time_unix_seconds: u64,
}

enum SnpRevocationInput {
    FixtureNotApplicable,
    AmdCrlsDer(Vec<Vec<u8>>),
}

struct AuthenticatedTcb {
    boot_loader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

struct AuthenticatedEtcb {
    raw: [u8; 32],
}

enum SnpSigningKeyKind {
    Vcek,
    Vlek,
}

struct SnpCollateralStatus {
    trust_domain: SnpTrustDomain,
    leaf_certificate_sha384: [u8; 48],
    certificate_chain_sha384: [u8; 48],
    verification_time_unix_seconds: u64,
    revocation: SnpRevocationStatus,
}

enum SnpRevocationStatus {
    FixtureNotApplicable,
    CheckedNotRevoked,
}
```

All DER vectors are bounded by implementation constants and rejected before
parser entry when oversized or empty. `AmdCrlsDer` must contain every CRL
required to validate the selected leaf and chain and must not be empty.
`FixtureNotApplicable` is legal only for `SnpTrustDomain::Fixture`; production
AMD collateral must provide and successfully validate revocation input. The
verification time comes from the composition's trusted time provider, not from
the evidence or a network response inside the verifier.

`certificate_chain_sha384` is:

```text
SHA384(
    "SNP-CERT-CHAIN-v1" ||
    u32le(len(leaf DER)) || leaf DER ||
    u32le(len(intermediate DER)) || intermediate DER ||
    u32le(len(root DER)) || root DER
)
```

The domain string is ASCII without a trailing NUL. `AuthenticatedTcb` is
returned only after reserved-byte and encoding validation.
`AuthenticatedEtcb` preserves the exact authenticated 32-byte value;
component-level reinterpretation is not invented while the published Version
6 layouts conflict. `SnpCollateralStatus` is success-only evidence metadata
and never represents an unverified, unchecked, expired, or revoked chain.

`SnpEmulatorV1` uses a Firmware ABI 1.59-formatted, fixture-VCEK-signed
1,184-byte base report. Byte `0x48` bit 5 remains zero as required by that
layout. A separate test-only supplement supplies the logical ARG migration
fields that cannot coexist with the ETCB fields in the conflicting published
layout.

```text
SnpEmulatorSupplementV1 = 220 bytes

Offset  Size  Encoding
0x000     2   FORMAT_VERSION = 1, u16le
0x002     2   PROFILE = 1 (SnpEmulatorV1), u16le
0x004    48   REPORT_SHA384
0x034    32   CURRENT_ETCB
0x054    32   LAUNCH_ETCB
0x074    32   COMMITTED_ETCB
0x094     1   MIGRATION_DATA_VALID = 0 or 1
0x095     7   RESERVED = zero
0x09c    64   MIGRATION_DATA

SUPPLEMENT_SIGNATURE =
    ECDSA-P384-SHA384(
        "SNP-EMU-SUPPLEMENT-v1" ||
        exact SnpEmulatorSupplementV1[220]
    )
```

The domain string is ASCII without a trailing NUL. The raw IEEE P1363
signature is `r[48] || s[48]` and is verified with the same fixture VCEK public
key that authenticates the base report. The fixture certificate chain is
validated only against the fixture ARK.

`REPORT_SHA384` must equal SHA-384 over the exact 1,184 report bytes.
Supplement ETCB values must byte-equal the authenticated ETCB values extracted
from the Firmware ABI 1.59 base report. If `MIGRATION_DATA_VALID == 0`, all 64
`MIGRATION_DATA` bytes must be zero. Any mismatch fails before claims are
returned.

`AuthenticatedSnpClaims` is common to both compositions:

```rust
struct SnpClaimProvenance {
    evidence_profile: SnpEvidenceProfile,
    trust_domain: SnpTrustDomain,
    report_sha384: [u8; 48],
    supplement_sha384: Option<[u8; 48]>,
}

struct AuthenticatedSnpClaims {
    provenance: SnpClaimProvenance,
    report_version: u32,
    guest_svn: u32,
    policy: u64,
    family_id: [u8; 16],
    image_id: [u8; 16],
    vmpl: u32,
    report_data: [u8; 64],
    measurement: [u8; 48],
    host_data: [u8; 32],
    id_key_digest: [u8; 48],
    author_key_digest: [u8; 48],
    author_key_en: bool,
    report_id: [u8; 32],
    report_id_ma: [u8; 32],
    reported_tcb: AuthenticatedTcb,
    current_tcb: AuthenticatedTcb,
    committed_tcb: AuthenticatedTcb,
    launch_tcb: AuthenticatedTcb,
    current_etcb: AuthenticatedEtcb,
    committed_etcb: AuthenticatedEtcb,
    launch_etcb: AuthenticatedEtcb,
    current_mitigation_vector: u64,
    launch_mitigation_vector: u64,
    migration_data_valid: bool,
    migration_data: [u8; 64],
    signing_key_kind: SnpSigningKeyKind,
    collateral_status: SnpCollateralStatus,
}
```

For `SnpEmulatorV1`, report fields and ETCB are authenticated by both the base
report signature and supplement consistency check; migration data is
authenticated by the supplement signature bound to the exact report digest.
No host-supplied unauthenticated field enters `AuthenticatedSnpClaims`.

Stable errors include:

```rust
enum SnpReportVerificationError {
    InvalidReportLength,
    UnsupportedReportVersion,
    MalformedReport,
    InvalidReservedBits,
    UnsupportedSigningKey,
    SignatureVerificationFailed,
    MissingCollateral,
    MalformedCollateral,
    CollateralTooLarge,
    CollateralTrustDomainMismatch,
    MissingRevocationCollateral,
    UntrustedCertificateChain,
    ExpiredCollateral,
    RevokedCollateral,
    InvalidVerificationTime,
    UnexpectedVmpl,
    ReportDataMismatch,
    InvalidTcbEncoding,
    InvalidEtcbEncoding,
    InvalidMitigationVector,
    InvalidSupplementLength,
    InvalidSupplementReservedBits,
    SupplementSignatureFailed,
    SupplementReportDigestMismatch,
    SupplementEtcbMismatch,
    InvalidSupplementMigrationData,
    FixtureEvidenceInProduction,
    UnsupportedVersion6Layout,
    ConflictingAbiLayout,
}
```

The verifier performs parsing, cryptographic authentication, request-specific
structural checks, and authenticated-claim extraction. It does not authorize a
migration session. MigTD separately checks role, request, TH1, expected
`REPORT_DATA`, tenant correlation, the authorization profile, replay state,
operation state, migration history, and forward policy.

Provider behavior:

```text
SnpEmuAzure:
    accepts only SnpEmulatorV1 plus fixture collateral
    verifies base report, supplement, report binding, and ETCB equality

SnpHardware:
    rejects SnpEmulatorV1 and all fixture roots
    accepts only RawAmdReport plus production collateral
    returns UnsupportedVersion6Layout or ConflictingAbiLayout for the
    overlapping Version 6 fields until AMD publishes an authoritative layout
```

There is no automatic layout detection, caller-selected reinterpretation,
zero/default claim substitution, or runtime fallback between providers.

### P0.12A1 TDX and common-TEE boundary

TDX remains on the existing Intel QVL path. AAS scope in this plan is SNP-only;
Item 4 does not migrate TDX to AAS, replace QVL, or require edits to the
working TDX call graph.

Freeze the names and direction of the future production boundary now:

```rust
trait TdxQuoteVerifier {
    fn verify(
        &self,
        request: TdxQuoteVerificationRequest,
    ) -> Result<AuthenticatedTdxClaims, TdxQuoteVerificationError>;
}

enum AuthenticatedTeeEvidence {
    Tdx(AuthenticatedTdxClaims),
    Snp(AuthenticatedSnpClaims),
}
```

During the emulator milestone these are architecture-level definitions only.
No TDX provider implementation, caller conversion, policy conversion, or
runtime selection change is required. Exact `TdxQuoteVerificationRequest`,
`AuthenticatedTdxClaims`, and `TdxQuoteVerificationError` leaf fields are
frozen only after the working TDX/QVL implementation is reconciled with
Microsoft upstream; defining duplicate fields from the out-of-sync checkout is
prohibited.

Production later supplies an Intel-QVL-backed `TdxQuoteVerifier` adapter.
`AuthenticatedTeeEvidence` may be used only at genuinely TEE-neutral
orchestration boundaries. SNP policy continues to consume
`AuthenticatedSnpClaims` directly, and TDX policy continues to consume
`AuthenticatedTdxClaims` directly. The wrapper must not reduce either
technology to a lowest-common-denominator policy claim set.

Acceptance:

- shared policy consumes one `AuthenticatedSnpClaims` type and contains no
  emulator-specific authorization branch;
- the public SNP request, collateral, claim, provenance, leaf, status, and
  error types are MigTD-owned and independent of AAS-native Rust types;
- the AAS adapter has an explicit fail-closed mapping and never returns
  partially populated, defaulted, or unauthenticated claims;
- profile and trust-domain provenance are mandatory and authenticated;
- callers cannot consume unauthenticated report fields;
- changed report bytes, report digest, supplement bytes, signature, ETCB
  duplicate, valid bit, migration data, fixture chain, or trust domain fail;
- fixture evidence is rejected by `SnpHardware`;
- raw hardware evidence never falls back to the emulator supplement;
- policy tests run against typed claims independently of the physical parser;
- base-report parser tests cover Firmware ABI 1.59 and ARG overlay
  interpretations separately without claiming both are simultaneously valid;
- verification errors do not silently fall back to fixture or alternate
  verifier behavior;
- Intel QVL remains the TDX verifier and no emulator milestone task rewires or
  refactors the working TDX path;
- `AuthenticatedTeeEvidence` is optional orchestration glue and is not used to
  merge SNP and TDX authorization policy;
- production TDX adapter adoption is gated on reconciliation with Microsoft
  upstream and is not an emulator blocker;
- no TAV dependency or TAV implementation is selected by either final SNP
  composition.

## P0.12B Freeze production relying-party evidence and composite AAS contract

Status: DEFERRED to H5.6 after P0.9A2-P0.9C2

Freeze the logical `CompositeSnpEvidenceV1` contract used by the external
relying-party verifier. This is separate from the peer-MA SPDM records used to
authorize a migration session.

Required logical members:

```text
format and profile version
tenant Version 6 report and report-verification collateral
current-MA Version 6 report and report-verification collateral
initial-MA evidence or an approved signed initial-MA authorization reference
MigrationDataV1 and its profile identity
current-MA and initial-MA policy endorsements
evidence-production and bounded-replay classification
canonical evidence and endorsement digests
```

Per-report collateral identifies:

```text
signing-key kind
leaf certificate
issuer chain
trust-anchor selection
revocation and expiration inputs
applicable MA/Policy endorsement
```

Required correlation:

```text
tenant.REPORT_ID_MA == current_ma.REPORT_ID
tenant.MIGRATION_DATA.INIT_MA_REPORT_ID == initial_ma_identity
MigrationDataV1 profile and reserved fields are valid
current and initial MA releases map to approved MA/Policy identities and SVNs
all supplied collateral and endorsements apply to the exact verified reports
```

Freeze one authoritative initial-MA evidence mechanism:

```text
carry the initial-MA report and endorsements with the tenant evidence
OR resolve immutable evidence from a trusted repository by REPORT_ID
OR use a durable signed initial-MA authorization record with equivalent claims
```

The contract must define:

- required and optional members;
- canonical internal representation;
- a versioned wire encoding if evidence crosses a process or service boundary;
- maximum sizes and nesting limits;
- missing, stale, revoked, mismatched, unsupported, and malformed failures;
- evidence cache and retention rules;
- privacy treatment for report and platform identifiers;
- authenticated claims returned to the relying party.

Define `CompositeSnpVerificationResultV1` with:

```text
accepted or rejected
verified tenant identity and current-MA binding
verified initial-MA identity or authorization
evaluated MigrationDataV1 history
current and historical policy levels
collateral and endorsement status
bounded-replay classification
typed failure domain and reason
```

Ownership:

```text
Azure/azure-guest-attestation-sdk:
    Version 6 report cryptography and authenticated claim extraction
    CompositeSnpEvidenceV1 verification and Microsoft migration-policy appraisal

MigTD:
    migration evidence generation, MigrationDataV1, and authenticated identifiers

BASE team and attestation-client owners:
    tenant evidence acquisition, evidence collection, and envelope assembly

Microsoft MA release and security endorsement owners:
    endorsement publication, release-to-SVN mapping, revocation, and rotation

Application relying party:
    final allow or deny decision from authenticated verifier output
```

Acceptance:

- the owner and target repository of every layer are explicit;
- the initial-MA evidence mechanism is selected;
- canonical positive and negative evidence vectors exist;
- equivalent internal and remote representations produce identical claims;
- unknown versions, ambiguous references, and missing required evidence fail
  closed;
- the contract does not require tenant-controlled `REPORT_DATA`.

## Phase 0 gate

Status: RECONCILED for bounded Phase 1 provider/interface implementation on
2026-11-03, under the user-approved T4.9 execution contract.

The required P0.1-P0.12A1 bounded acceptances, including P0.9D/E and the
P0.9A2-P0.9C2 contract/fixture scope, are recorded above and centrally.
The active T4.9 worktree baseline is
`target/t4.9-validation/20261103T233017Z/baseline.json`.
P0.9E retains accountable PA-001-PA-011 tracking; P0.10 supplies the accepted
exact recipe and independent vectors; P0.11 supplies the accepted local and
authority contracts. Previous IN PROGRESS records remain historical.
This reconciliation closes no production limitation and promotes no interface,
fixture or reference test into active runtime/AAS/hardware qualification.
P0.12B, H5.0-H5.7 and the existing runtime activation gates remain unchanged.

Phase 0 completes when:

- P0.1-P0.8, P0.9A1, P0.9B1, P0.9C1, P0.9D, P0.9E, P0.10, P0.11,
  P0.12A, and P0.12A1 are frozen;
- current uncommitted work is baselined;
- exact layouts and registries are recorded;
- fixed-release identity, allowlist, trust, platform-policy, history, and
  cryptographic golden vectors pass;
- P0.9A2-P0.9C2 bounded contract/fixture freezes are accepted; H5.0 retains
  deployment-contract review and parser readiness, H5.2 production integration,
  and H5.6 P0.12B/composite qualification. Those production gates do not block
  emulator provider or runtime implementation; P0.9D defines the handoffs;
- `doc/snp-production-readiness.md` has confirmed accountable tracking owners,
  target repositories/upstreams, approved durable tracker links, dependencies,
  gates, evidence dispositions and prohibited claims for PA-001 through PA-011;
  the selected repository ledger satisfies the tracker mechanism, not the
  separate production qualification or publication requirements;
- production-only limitations are explicitly assigned to Phase 5.

---

# Phase 1 - Complete Task 4 Provider Architecture

Task 4 defines interfaces and provider boundaries. It does not yet activate the
full runtime protocol.

## TDX-aligned implementation model for T4.9-T4.20

Model identifier: `Task4-TdxAlignedModelV1-2026-11-03`.
Recorded UTC: `2026-11-03T23:08:21Z`.
User instruction: "Model all the work along the lines of TDX."
Confirmed scope: T4.9-T4.20.

This is the implementation modeling guide for all twelve steps below, not
execution or acceptance of those steps. TDX supplies architectural precedent;
the existing accepted SNP contracts supply SNP semantics. Exact new provider
APIs, lifecycle/framing choices and composition interfaces still require their
own review and the T4.20 freeze. No P0 freeze, wire record, cryptographic recipe,
production-readiness disposition or canonical execution-order entry is changed.
Before starting implementation, reconcile and record the Phase 0 completion
gate and capture the new active-worktree baseline.

### Governing TDX pattern and its SNP adaptation

The examined TDX flow separates a host request, protected peer communication,
attestation/policy checks, platform effects and a correlated host result:

```text
host request / typed operation
    -> MA-owned operation orchestration
    -> selected peer transport and secure session
    -> authenticated evidence, policy and session binding
    -> role-specific platform key/binding operation
    -> transport/session completion and correlated status
```

Concrete precedents are bounded request decoding in
[parse_request](../src/migtd/src/migration/session.rs#L349), orchestration in
[exchange_msk](../src/migtd/src/migration/session.rs#L1103) and
[start_rebinding](../src/migtd/src/migration/rebinding.rs#L74), feature-selected
[transport setup/shutdown](../src/migtd/src/migration/transport.rs#L9), and
[request-correlated status](../src/migtd/src/migration/session.rs#L731).
These are functions and code-path boundaries, not an existing universal TDX
provider-trait framework. SNP should make the equivalent seams explicit with
the smallest useful typed provider APIs; do not introduce a generic plugin
registry, runtime platform probing or a second orchestrator for each backend.

Keep three planes separate:

```text
Host/control plane:
    work intent, managed handle, correlation, evidence delivery, cancel/status
Peer/security plane:
    SPDM, authenticated MA evidence/policy, protected V2 key delivery/acceptance
    and correlated firmware outcomes; separate protected local handoff
Platform/effect plane:
    trusted current binding/state, key/history installation, rebind/persistence
```

Host and transport metadata remain untrusted. A name, handle, supplied digest,
request ID or socket is not authorization. Following the accepted P0.11 V1.1
TDX comparison, do not impose a new authenticated BASE/coordinator principal
merely because BASE requests work. Independently appraise accepted policy,
verified identities/current bindings, operation scope and qualified platform
controls. Uncovered authority needs an explicitly approved additional mechanism
or denial; the TDX comparison does not remove an SNP provider check.

TDX policy initialization verifies policy before exposing
[VERIFIED_POLICY](../src/migtd/src/mig_policy.rs#L95). Rebind peer policy/report
appraisal precedes role-specific TH1 checks and failure tears down the SPDM
session in the [requester](../src/migtd/src/spdm/spdm_req.rs#L1303) and
[responder](../src/migtd/src/spdm/spdm_rsp.rs#L1198). Model SNP similarly:
raw delivery -> cryptographic receipt -> policy/operation admission ->
authorized effect. Do not promote cached or decoded evidence straight to an
installation capability.

### ABI constraints and Technical Notes reconciliation

Reconciliation identifier: `Task4-TdxAbiReconciliationV1-2026-11-03`.
Baseline UTC: `2026-11-03T23:21:16Z`.
Scope: constraints on all twelve T4.9-T4.20 models, not execution, a new API
freeze, or production qualification.

Sources checked:

- The accepted [P0.2 current ABI addendum](snp/task4/q162-arg-v120-command-addendum.md#current-p02-addendum-2026-11-02)
  for Firmware ABI 1.59 and ARG ABI v1.20, and the accepted P0.3-P0.12A1
  contracts in this canonical plan. The original ABI PDFs are not reopened,
  copied or published by this reconciliation.
- The user-specified local
  [Technical Notes](<../../../Docs/AMD SEV SNP Venice Live Migration – Technical Notes.docx>):
  introductory TDX/SNP comparison, networking and lifecycle discussion;
  Q132-Q168 implementation/evidence/key/policy workstreams; and Q169-Q183
  Venice, rebind, common-verifier, layout and authorization refinements.
  Exact DOCX SHA256:
  `54b4b73ced91e32bd8ae5d0ef3860b5659a21cb702467c6982feb5acfed06f8f`.
  Question numbers identify discussion sections, not ABI revisions or freezes.
- The actual TDX source precedents linked in the individual models below.

**Precedence:** model by security responsibility, not instruction, field name
or superficial lifecycle similarity. The ABIs constrain architectural effects;
accepted SNP contracts define application semantics where the ABIs leave them
implementation-defined. TDX and historical Technical Notes proposals cannot
override either. The published Version 6 layout conflict remains fail closed:
source priority does not authorize choosing guessed offsets. Changes to an
accepted contract require a separately approved versioned addendum, not this
modeling guide.

#### Mandatory ABI design invariants

Every relevant provider request, verified result, state transition and consumer
must preserve these invariants. The accepted P0.2 addendum owns the exact ABI
fields, mode values, preconditions and statuses; do not duplicate a competing
command specification in Task 4.

| ID | Principle retained from the accepted ABI/contracts | Task 4 responsibility and required evidence |
|---|---|---|
| ABI-01 | Separate BASE/hypervisor initiation and guest-context routing, MA policy/peer authentication, and ARG/firmware enforcement. The MA is not the ARG page-migration engine. | T4.9/T4.12/T4.15-T4.18 keep host, peer and effect planes distinct; managed handles never become verified identities or shared physical addresses. |
| ABI-02 | BASE obtains host-requested tenant reports; each MA requests its own guest report. Preserve the distinct VMPL rules and independently constructed MA REPORT_DATA versus all-zero host REPORT_DATA. | T4.9/T4.13/T4.17 reject MA-as-tenant substitution, nonzero host REPORT_DATA, unsupported binding classification and report-self-echo verification. Do not prescribe a universal MA VMPL from an illustrative TDX/SNP diagram. |
| ABI-03 | Acquisition, report/chain authentication, MA/tenant policy approval and firmware authorization are different gates. A valid AMD signature alone does not approve an MA image or policy. | T4.9/T4.12/T4.17/T4.18 expose sealed verified claims and later admission separately; test correctly signed but unapproved identity, wrong tenant-to-MA binding and missing providers. |
| ABI-04 | MA authentication, secure-channel establishment, software verification and migration-data meaning are implementation-defined; `MSG_VERIFY_REPORT` is removed. `MSG_EXPORT_REQ` is not a report generator. | T4.9-T4.14 retain accepted SPDM, purpose binding, replay, policy and KDF semantics; no firmware-verification dependency or exported-GCTX/REPORT_DATA equivalence. |
| ABI-05 | Installation is the selected bound-MA path, with authenticated tenant/current binding, legal role-specific guest state and no active migration session. Firmware's receiving-side REPORT_ID omission is not permission to omit MA-side destination identity checks. | T4.11/T4.12/T4.17 model the accepted sending/receiving preconditions, target selection and explicit rejection; do not substitute the guest-self path or a TDX TDCS write. |
| ABI-06 | Both MAs install the approved identical key and opaque history with the accepted algorithm and role. Persistence and readiness are not proven by a host ACK or an installer return alone. | T4.11-T4.13/T4.17 retain reciprocal confirmation, separate destination persisted-state evidence and partial/indeterminate outcomes. Purpose-3 evidence follows persistence; it cannot authorize its own installation. |
| ABI-07 | BASE begins architectural migration only after role-specific installation/readiness. Debug fixed-key/null-cipher options are not production alternatives. | T4.12/T4.15/T4.17 separate MA readiness from begin-migration, page transfer and tenant resume; preserve legal firmware state/role and explicit failures. H5.1/H5.3/H5.7 qualify real effects. |
| ABI-08 | Guest firmware messages, host firmware commands and peer messages are separate transports. Shared/untrusted buffers do not authorize effects or expose plaintext keys. | T4.11-T4.13/T4.15 keep VMPCK/sequence, GHCB/VMGEXIT and physical-address handling inside qualified adapters; SPDM protects peer secrets. No invented ioctl, NAE code, TDX VMCALL or production TCP fallback. |
| ABI-09 | Preserve exact ABI serialization/reserved fields and raw operation-specific firmware statuses. Transport failure, firmware rejection, evidence failure and policy denial are distinct. | T4.11/T4.12/T4.17 test malformed/reserved inputs, unknown statuses and error-domain mapping; a generic success/retry cannot erase firmware failure. Only explicitly legal correlated retries proceed. |
| ABI-10 | Planned handoff uses protected matching secret slots; recovery is a separate firmware mode with exact identity/launch-state checks, not a missing outgoing-process shortcut. | T4.10-T4.14/T4.17 retain P0.11 single-slot ownership, encrypted transfer, clearing, authoritative binding inventory and incoming-only recovery. Never substitute TDX approval tokens or fabricate old-MA proof. |
| ABI-11 | Signed current platform state, launch history, signing-key TCB and firmware rollback commitments have different meanings. Firmware stores opaque history; the MA calculates the approved history and policy. | T4.9/T4.11/T4.17 preserve P0.4/P0.9 operands, Venice components, mitigation-bit semantics and immutable initial identity; no host-desired launch state or firmware-calculated minima. |
| ABI-12 | A semantic verifier interface does not resolve conflicting physical report layouts or qualify firmware, durability or recovery. | T4.15-T4.20 retain authenticated profile/trust provenance, emulator supplement isolation, explicit production-layout/provider errors and named downstream qualification gates. No default claims or alternative backend on failure. |

#### TDX-to-SNP difference coverage

This crosswalk includes the Technical Notes' original thirteen work items,
their additional workstreams, and later corrections. It supplements, rather
than replaces, the individual models. An owning later task is an explicit
handoff obligation, not a reason to omit its interface or failure contract.

| ID | Difference or concern in Technical Notes | Required SNP disposition / accepted authority | Owning Task 4 seam and later implementation/qualification |
|---|---|---|---|
| DIF-01 | TDX module/Service-TD versus SNP MA/ARG/firmware responsibility; one runtime-selected source/destination binary (introduction, Q132/Q135/Q152-Q155). | Keep shared MA orchestration and explicit runtime roles; never infer a role from an address. Remove SNP-reachable TDCALL/TDCS/ServTD assumptions without changing working TDX/AzCVMEmu semantics. | T4.12/T4.15-T4.19; Task 5 removes remaining inherited behavior; P2.2 owns atomic artifacts and hashes. |
| DIF-02 | TDX VMCALL versus SNP host, guest-message and peer channels (networking, Q134/Q153/Q155/Q166). | Separate selected BASE host-push, qualified guest firmware messaging and protected peer transport. Linux report ioctls target the calling MA, not another tenant. | T4.9/T4.11-T4.13/T4.15-T4.17; H5.1/H5.3/H5.5 qualify production routing, memory, sequence and transport. |
| DIF-03 | MA plus tenant evidence, inline/cache references and out-of-band delivery (Q137/Q144-Q148/Q155/Q166/Q170). | Preserve P0.5 base-report reference bytes and P0.6 complete-evidence binding; authenticate supplement/collateral association separately. Both peers independently verify the complete source evidence before current V2 purpose 6. | T4.9/T4.12/T4.17; Tasks 6-8 activate fixtures/exchange; H5.1/H5.4 qualify cache/replay lifecycle. |
| DIF-04 | Host-zero tenant REPORT_DATA versus fresh MA/session-bound evidence (Q140/Q142/Q155/Q166/Q170). | P0.3 purposes, legal roles, all 64 bytes and padding remain exact. P0.6 binds verified complete tenant evidence to TH1/request/roles/policy. No tenant-cooperation or first-use nonce claim is inferred. | T4.9/T4.12/T4.13/T4.17; Tasks 7/8; H5.4 qualifies the accepted bounded-replay policy. |
| DIF-05 | REPORT_ID, REPORT_ID_MA, initial/current MA identity versus TD UUID/ServTD hashes (Q136/Q137/Q145/Q175/Q176/Q182/Q183). | Use verified tenant-to-source-MA binding and retain immutable INIT_MA_REPORT_ID. Initial authorization is distinct from current approval; a digest is not a retrievable original report or authorization record. | T4.9/T4.11/T4.12/T4.17; Tasks 8/9/12; H5.2/H5.6 qualify initial-evidence retrieval and relying-party appraisal. |
| DIF-06 | SNP report/certificate trust versus Intel quote/QE/PCK/PCS layers (introduction, Q138/Q139/Q141/Q145-Q147/Q155). | Authenticate supported AMD signing-key/certificate claims and report bytes; do not import QEIdentity, Intel collateral fields, local-chip-verification assumptions or trust based only on certificate presence. | T4.9/T4.13/T4.15-T4.18 and common AAS boundary; H5.2 qualifies production roots, claims and revocation. |
| DIF-07 | Production certificate-table acquisition versus private fixture blobs and peer collateral (Q134/Q138/Q146/Q155). | `snp_msg_cert_entry` is an acquisition format, not the peer wire format. Normalize into the frozen collateral contract; independently validate trust, signer selection, duplicate/size limits, HWID and REPORTED_TCB as applicable. | T4.9/T4.13/T4.15/T4.17; collateral/runtime tasks and H5.2 qualify KDS/THIM/cache, offline, expiry, revocation and root transitions. |
| DIF-08 | AAS replacement, base-report verification and composite LM verification (Q132/Q155/Q174/Q177/Q180). | P0.12A/A1 selects one MigTD-owned SNP claims/error/provenance boundary. AAS verifies the base; MigTD owns binding, supplement, policy and workflow. Final SNP compositions have no TAV fallback; TDX stays on QVL. | T4.9/T4.15-T4.19; AAS1A/AAS1A-M qualify the adapter; P0.12B/H5.6 own production composite verification. |
| DIF-09 | RTMR/event-log/TDINFO versus SNP measured launch and policy identity (introduction, Q144/Q145/Q154/Q176/Q182). | Do not relabel HOST_DATA or a vTPM log as RTMR, or retain empty EventLogMy/SerVtdExt/TdReportInit as SNP proof. Use the accepted complete MA/Policy identity and typed evidence. | T4.9/T4.13/T4.17/T4.18; Tasks 5/7/9 replace inherited payloads and appraise signed identity. |
| DIF-10 | Measurement-to-release ranking, tcbDate suggestions, FixedReleaseV1 and OrderedReleaseV1 (Q149-Q151/Q160/Q161/Q173/Q175/Q176/Q183). | P0.9 uses one MA/Policy collateral model. Fixed approval is exact identity, not an SVN; ordered ranking requires the accepted signed mapping and initial authorization. No SVN inferred from hashes, GUEST_SVN, collateral sequence or date. Standard CoRIM encoding is not mandatory. | T4.9/T4.12/T4.15/T4.17/T4.18; Tasks 7/9 consume verified collateral; H5.2/H5.6 qualify production publication/lifecycle. |
| DIF-11 | Current forward TCB, absolute floors, historical lifetime floors and mitigation semantics (Q136/Q149/Q150/Q155/Q159-Q161/Q169/Q170/Q173). | P0.9 consumes the specified current MA platform operands; P0.4 consumes verified tenant launch/history operands. Keep component dominance, absolute/lifetime checks and bit containment separate. REPORTED/COMMITTED/host-desired launch values are not substitutes. | T4.9/T4.11/T4.17/T4.18; Tasks 8/9/11/12 wire policy and persisted history. |
| DIF-12 | Processor-aware TCB and complete Venice ETCB versus four/five-component sketches (Q149/Q150/Q160/Q164/Q165/Q169/Q170). | Require the accepted Venice Version 6 program/profile, exact fourteen ETCB components and zero reserved components. Preserve P0.12A's Venice FMC/TEE/SNP amendment; no invented boot-loader/microcode mapping or automatic cross-family normalization. | T4.9/T4.15/T4.17; AAS1A-M, Task 6 and H5.0 qualify family-aware claims/parser; other-family support needs an approved extension. |
| DIF-13 | Opaque architecture history64 versus proposed eight-byte ETCB projection (Q136/Q159/Q165/Q169/Q170/Q181). | P0.4 VeniceV1 owns exact little-endian history64: full mitigation vector, fourteen defined ETCB bytes and initial MA ID. Invalid history is not zero minima; first-use initialization and subsequent minima/AND preserve immutable initial identity. | T4.9/T4.11/T4.17; Tasks 9/11/12 persist and reattest byte-identical source/destination history. |
| DIF-14 | Version 6 ETCB/history overlap and synthetic report hierarchy (Q163-Q165/Q177-Q180/Q182). | P0.12A uses a signed base plus exact signed supplement with matching digest/ETCB and authenticated provenance. Do not edit a captured AMD report or overlay both claims. Production raw combined interpretation stays blocked on PA-009/H5.0. | T4.9/T4.15-T4.19; Task 6/AAS1A-M qualify signed positive/negative fixtures; H5.0 qualifies corrected raw parsing. |
| DIF-15 | TDX directional module keys versus SNP software-owned MSK (key-visibility discussion, Q135/Q140/Q142/Q143/Q155/Q167/Q168/Q170). | The accepted T4.14-PRE V2 amendment supersedes the bilateral P0.7/P0.10 recipe: source generates final random32 MSK, delivers it through promoted encrypted SPDM, and requires protected acceptance plus correlated role-specific firmware outcomes. No contribution, commitment, HKDF, application HMAC or module-key read is selected. | T4.10/T4.13/T4.14/T4.17; Task 10 activates the accepted V2 recipe and ordering. |
| DIF-16 | Entropy, secret exchange, separation, erasure and conditional forward secrecy (Q140/Q142/Q155/Q167/Q168). | Use approved local CSPRNG and owned/redacted secret buffers. MSK32 and independent outgoing handoff32 cross only their promoted encrypted peer channels. Preserve exact role/order/retry/cleanup rules; no plaintext host delivery, derived-key prerequisite or SPDM-only erasure/compromised-MA safety claim. | T4.10/T4.13/T4.14/T4.17; Tasks 10/11 and Phase 4 qualify cleanup on abort, cancel, timeout and partial effects. |
| DIF-17 | Firmware-derived keys versus migration-key establishment (Q132/Q134/Q135/Q155/Q169). | `MSG_KEY_REQ` is not an MSK read/install or report verifier. T4.10 must resolve a real approved platform-secret need or leave it unavailable; historical modeled MSG_KEY_REQ events do not make it a runtime prerequisite. | T4.10/T4.14/T4.17; any production key adapter retains its own explicit approval/qualification gate. |
| DIF-18 | Protected acceptance versus firmware completion and persisted-state evidence (Q155/Q159/Q167/Q168). | Current V2 requires purpose6/7 admission, protected delivery/acceptance, destination completion before source installation, and correlated source completion/ack. Acceptance is not application key-possession or attested persistence. Fresh purpose3/Task12 remains separately deferred; partial/unknown effects require reconciliation. | T4.11-T4.13/T4.17; Tasks 10/11 activate ordering; Task12 reactivation needs separate approval; H5.3/H5.4 qualify persistence/reconciliation. |
| DIF-19 | TDX rebind approval versus planned SNP handoff and recovery (Q156-Q158/Q170-Q173/Q175/Q182). | P0.11 governs separate inter-node/local peer sessions, exact tenant sets/current binding, single secret-slot serialization, no-secret incoming-only recovery and immutable history. Old/new process availability does not replace firmware equality checks or shutdown inventory. | T4.10-T4.14/T4.17; Phase 4 runtime handoff/recovery; H5.5 qualifies real firmware and BASE reconciliation. |
| DIF-20 | Version negotiation, VDM/schema replacement and payload growth (Q144-Q148/Q154/Q155/Q182). | Keep schema, migration, algorithm, history and evidence profiles distinct. Use frozen typed codecs, exact role/request correlation and bounds; cache/chunking choices need review, not silent new wire semantics. Replace requester/responder together at runtime activation. | T4.12/T4.13/T4.17/T4.18; Task 3 addenda and Tasks 7/8/13 own full framing/exchange and negative tests. |
| DIF-21 | Replay, restart, cache correlation, cancellation and status (Q132/Q155/Q158/Q168/Q170). | P0.5/P0.6/P0.11 retain one operation owner, immutable terminal outcomes, qualified durable replay/current firmware checks and no empty-journal or secret-resume fallback. A zero-bound report has no proved first-use freshness. | T4.9/T4.12/T4.13/T4.17; active runtime tasks, Phase 4 and H5.4 qualify durability/rollback/restart. |
| DIF-22 | Unavailable hardware, feature isolation and provider capability (Q134/Q147/Q152-Q155/Q158/Q177/Q180). | Explicit reviewed provider sets select evidence, trust, transport, state/effects and RNG. std/Underhill does not select fixtures. Shared SNP logic is independent of emulator capability; missing hardware/AAS support fails explicitly. | T4.15-T4.19; retain required positive/negative compile and binary/dependency-isolation tests. |
| DIF-23 | Qualification, release evidence and actual VM migration (Q132-Q134/Q155/Q162/Q181). | Distinguish reference vectors, interface conformance, deployment-shaped emulator, hardware effects, production security and completed page migration/resume. Preserve old/new regressions, secret-free diagnostics and reproducible artifacts; readiness is not completed tenant migration. | T4.17-T4.20; P2.1/P2.2, later runtime tests and H5.7 retain their exact order and acceptance gates. |

#### Historical proposals and current disposition

The DOCX contains successive proposals and historical code/status snapshots.
They are accounted for explicitly, not adopted literally:

- Earlier lifecycle tables describing PSP-generated opaque transport-key
  import, inaccessible plaintext keys or swap-out/in as the selected MA
  key-establishment flow are not the accepted ARG/Q162 flow. Retain the later
  corrected key-visibility explanation and accepted T4.14-PRE direct-random V2
  construction. Historical P0.7/P0.10 contribution/HKDF/HMAC bytes remain
  historical, not an active fallback.
- Q132's static captured-report milestone and unevaluated TH1/freshness claims
  remain historical validation scope. They do not satisfy the signed dynamic
  evidence, purpose binding or post-install requirements of the new workflow.
- Q155's temporary TAV/parity bridge is historical transition advice, not an
  exception to the final AAS-only SNP composition. Existing historical test
  results are not rewritten.
- Q165's ArgSvnV1/eight-byte projection and earlier one-byte mitigation
  sketches are superseded by P0.4 VeniceV1. Q164's older-family examples are
  not automatic Venice admission.
- Q166/Q170's once-open acquisition and first-use-freshness questions are
  resolved for V1 by accepted P0.5/P0.6 host-push and bounded replay, not by
  inventing tenant nonce support. H5.4 must qualify that policy; stronger
  freshness requires a separately approved contract.
- Q167/Q168 compare alternative crypto schemes and recommend defensive
  properties; they do not reopen the accepted P0.10 recipe, prove atomic
  effects, or add MA-side page-encryption/nonce generation. Actual ARG page
  protection and its qualified key/nonce lifecycle remain platform work.
- Q181-Q183 pre-freeze status, ordering and CoRIM possibilities are historical
  snapshots where later canonical acceptances differ. FixedReleaseV1 can
  serve a qualified same-release production deployment; OrderedReleaseV1's
  accepted custom signed mapping covers ordered evolution without mandatory
  CoRIM/CoMID conversion. Neither qualifies the missing deployment providers.

#### Required closure evidence for T4.9-T4.20

For each ABI and difference row, the owning step must record its concrete
producer/consumer surface, accepted contract, positive/negative test or
explicit unavailable boundary, and named downstream owner when deferred.
T4.17 tests the interface invariants; T4.18 audits their wiring; T4.19 runs
applicable regressions/isolation; T4.20 rejects an unmapped row, an implicit
fallback, a changed frozen encoding or a claimed downstream pass without
executed evidence. Do not require a later runtime pass to close a properly
bounded earlier interface test.

This reconciliation establishes required model coverage, not executable
conformance. Exact new API/cache/framing/lifecycle choices still require the
existing review/acceptance gates. Phase 0 closure, T4.9 START, API freeze,
production readiness, commit and push are not authorized by this entry.

### T4.9 model - host-pushed tenant evidence at the request boundary

TDX precedent: the host supplies work/routing inputs through bounded,
operation-specific request decoding; the MA performs the subsequent security
checks. TDX's examined migration flow does not provide the exact signed
BASE-pushed SNP tenant-report/supplement receipt required here.

Model `TenantEvidenceSource` as consumption/validation of evidence already
pushed by BASE, not an MA-triggered report-acquisition service. Reuse the
[P0.5 request, identity and correlation types](../src/pal/src/tenant_identity.rs#L13).
BASE retains report acquisition and managed-handle/GCTX mapping; the MA owns
verification and an immutable operation-bound result. The hardware tenant
source is not the local `/dev/sev-guest` MA-report acquisition provider.

Reuse the common P0.12A/P0.12A1 verifier boundary and existing P0.6 digest/replay
mechanisms. A complete verified receipt must bind authenticated tenant REPORT_ID,
report/optional supplement, provenance, collateral association and operation.
It proves evidence verification, not policy approval, durable authorization,
current firmware binding or successful migration. Missing common verification
returns an explicit unavailable-provider error; no TAV/captured-report fallback.

Preserve the old SHA384(base-report) reference meaning. Specify a reviewed
versioned package/reference association for supplement/signature/collateral,
cache ownership/limits and exact retry equivalence; do not silently redefine
the base-report reference or complete-evidence digest. Both BASE requests must
deliver the same complete source evidence before purpose 1.

The active V1 migration path remains host-requested zero REPORT_DATA. Define
fixture/emulator `GuestProvidedReportData` classification and expected-binding
semantics explicitly; no report-self-echo check, new tenant-cooperation
requirement or blind use of an MA-specific verifier request. Unsupported
production classifications fail closed.

Preserve the stage boundary: evidence receipt/correlation precedes purpose-1
MA proofs; the [authorization context](../src/pal/src/snp/tenant_authorization.rs#L110)
then supplies the verified replay binding for
[reservation](../src/pal/src/tenant_replay.rs#L333). Purpose-2 proofs and
[current-firmware validation](../src/pal/src/tenant_replay.rs#L356) precede
authorization. T4.9 defines this handoff, not a fabricated pre-proof
authorization digest; T4.12/later runtime tasks own final scheduling.

### T4.10 model - a narrow platform key/secret seam

TDX precedent: [read_msk](../src/migtd/src/migration/session.rs#L1292)
reads module-owned MIG_ENC_KEY through the binding handle and target TD UUID.
SNP should similarly isolate platform-specific key/secret operations behind a
typed provider, with explicit role/operation scope and unavailable outcomes.
Do not import TDCS fields/handles, assume MSG_KEY_REQ, or invent a platform
key call merely to reproduce TDX's shape. The accepted P0.10 two-contribution
KDF remains application-level SNP state, not an emulated TDX MIG_ENC_KEY read.

### T4.11 model - effects behind an installer boundary

TDX precedent: [write_msk](../src/migtd/src/migration/session.rs#L1307)
writes the peer migration key through target-bound module operations.
Model SNP installation as one typed request to the selected installer using
the existing verified tenant, role, session, MSK32 and VeniceV1 history64.
The provider owns firmware mapping and precise failure/effect reporting.

Do not copy MIG_DEC_KEY fields, treat a local return or host acknowledgement
as persisted-state proof, or infer atomicity from TDX's field-write loop.
Preserve partial/indeterminate outcome handling. Under the current-scope
deferral, fresh purpose-3 verification is not a prerequisite for installation
success or readiness. The historical P0.8 success-admission API must be
explicitly reconciled before runtime activation; never fabricate verification.
Real ARG effects and durability are qualified later; an unavailable production
installer returns failure.

### T4.12 model - one correlated control owner, separate binding effects

TDX precedent: [typed host dispatch](../src/migtd/src/migration/session.rs#L349),
[status reporting](../src/migtd/src/migration/session.rs#L731), and distinct
migration/rebinding entry paths. Use one retained operation context for
prepare/cancel/abort/query/status, not separate uncorrelated identities for
delivery, peer exchange and installation. Request acceptance is not approval
of platform effects. Status describes MA-authored results, not host-asserted
completion.

Use the existing host-transport seam as layering precedent, but keep its
current TDX-shaped payloads out of new shared SNP interfaces. Finalize bounded
SNP framing, complete evidence association, V2 purpose6/7 scheduling,
protected key acceptance and separate correlated firmware outcomes.
Reserve historical wire allocations and use distinct V2 records; do not
conflate local controls or reactivate deferred persisted-state attestation.
Restart must recover authenticated metadata/outcomes or fail/abort; no empty
journal, lost-secret reconstruction or replacement live SPDM session.

For binding effects, TDX writes a rebind accept token/attributes and performs
[target-bound approval](../src/migtd/src/migration/rebinding.rs#L439).
SNP uses P0.11's binding manager, protected secret sink, authoritative current
state and exact planned/recovery contracts instead. Do not substitute TDX
tokens for the SNP operation-bound random32 secret or relax incoming-only recovery, effect-scope,
remaining-binding inventory, cleanup and shutdown/reconciliation gates.
Host-control messages carry no SNP secrets; BASE shutdown remains lifecycle
intent, not authoritative completion.

### T4.13 model - feature-selected transport, purpose-specific secure session

TDX precedent: [transport alias/setup/close](../src/migtd/src/migration/transport.rs#L9),
source/destination secure-channel exchange and separate migration/rebind paths.
Define a narrow factory/session interface with explicit request correlation,
roles, verified policy/session context, allowed messages, timeout and abort.

TDX's reuse of transport helpers is not proof that it already implements SNP's
typed `InterNodeMigrationPeerSession`/`LocalMaHandoffPeerSession` isolation.
Preserve those two SNP types and reject crossed messages. Transport selection
does not establish trust; peer evidence binds to the actual current SPDM TH1.
TDX migration quote and rebind TDREPORT helpers are distinct
[evidence paths](../src/migtd/src/spdm/mod.rs#L302); SNP retains its own
frozen purpose/role/algorithm contexts and cannot reuse TDX offsets/labels.
Only later runtime tasks activate the complete SNP VDM exchange.

### T4.14 model - standard primitives, operation-owned secret lifetime

TDX precedent: [SystemRandom token generation](../src/migtd/src/migration/rebinding.rs#L475)
and [ZeroizeOnDrop migration keys](../src/migtd/src/migration/data.rs#L206).
Use standard approved crypto/RNG services and narrow owned secret wrappers,
not host-provided seeds or another configurable cryptographic recipe.

SNP uses direct source-generated MSK32 and independent outgoing-generated
handoff32 under T4.14-PRE, not contributions, PRK or application confirmation
keys. Keep independent draws and explicit authenticated context binding,
first-attempt handoff generation, move-only/sink ownership, redacted diagnostics
and explicit completion/error/cancel/timeout cleanup. The TDX examples do not
prove removal of every internal crypto copy, panic-safe firmware-slot cleanup
or crash recovery; SNP must state and qualify those boundaries separately.
Deterministic randomness remains an explicitly isolated test provider.

### T4.15 model - explicit platform compositions, shared orchestration

TDX precedent: the [Cargo feature graph](../src/migtd/Cargo.toml#L75) and
distinct [bare-metal/AzCVMEmu entry points](../src/migtd/src/bin/migtd/main.rs#L5)
select platform/runtime capabilities. Model the four accepted compositions as
selections of providers around shared orchestration, not four independent
protocol implementations.

TDX hardware/no_std and AzCVMEmu/std behavior stay unchanged.
SnpEmuAzure and SnpHardware share approved SNP contracts/AAS boundary, but have
different evidence roots, state/effect, transport and RNG providers. The
current SnpEmu inheritance of TDX emulator shims is a refactoring target, not
the production model. Missing hardware providers must fail explicitly; shared
policy code consumes verified claims without emulator-dependent semantics.

### T4.16 model - compile-time selection at composition roots

TDX precedent: feature-gated entry points and transport aliases, not runtime
backend discovery. Apply that principle to the existing capability split:
shared SNP code independent of snp-emu; explicit std; Underhill runtime
independent of fixture selection; independently gated Linux/effect providers.

Do not copy the current problematic SnpUnderhill -> SnpEmu inheritance or
TDX-shim leakage. Select AAS only for SNP; remove TAV from the final SNP graph,
code, tests and packaging. Unavailable AAS Version 6 verification remains an
explicit boundary until AAS1A-M, not a reason to retain a fallback.
Reject mixed emulator/production/TDX providers and fixture/mock/bypass
capabilities at compile time where possible. Exact feature/module names and
provider-set signatures are reviewed here; std alone never selects fixtures.

### T4.17 model - interface tests corresponding to real trust/effect seams

TDX precedent: distinct policy/session checks and teardown on rejected peer
evidence. Build tests around the equivalent SNP request, receipt, policy,
replay, peer-session and effect boundaries, not only successful codec round trips.
Reuse accepted P0.3-P0.11/P0.12 vectors and test controlled authenticated inputs,
wrong roles/TH1/profile/trust, malformed packages, retry conflicts, provider
absence, indeterminate effects and secret non-exposure.

Run the already specified positive/negative compile matrix and production
isolation checks. A test double can qualify the interface/failure contract,
not attestation or migration. TDX's existing policy/rebind checks do not prove
SNP layout or replay guarantees. Record AAS1A-M executable obligations and
explicit unavailable-adapter behavior; defer neither errors nor test ownership.

### T4.18 model - refactor to seams without a protocol rewrite

TDX precedent: request orchestration calls separate transport, policy,
role-specific exchange and platform-effect functions. Move SNP callers to
the reviewed equivalents at composition roots; shared logic sees typed
providers, not scattered cfg branches, TDX fields or direct platform calls.
Reuse existing helpers where they satisfy the accepted boundary; do not add
a parallel receipt, policy digest, state controller or provider registry.

Keep TDX/AzCVMEmu implementation unchanged except separately reviewed necessary
shared-boundary changes. Route SNP verification to AAS's unavailable-or-qualified
boundary, never TAV fallback. Task 5 owns removal of remaining active inherited
TDX behavior; T4.18 must not activate or rewrite the full Task 3 protocol.
Do not require later verified runtime results to accept earlier interface tests.

### T4.19 model - preserve the reference paths and prove isolation

TDX precedent: [firmware build variants](../.github/workflows/main.yml#L21) and
[AzCVMEmu migration/rebind scenarios](../.github/workflows/integration-emu.yml#L24)
exercise separate platform/protocol paths. Use those existing paths as
regression references, alongside the specified SNP provider/compile tests.
Code that affects shared boundary behavior must run relevant actual emulator
regressions; compilation alone does not prove behavior preservation.

Explicitly build the production composition without default features,
inventory dependency/features and scan binaries/manifests for prohibited
fixture roots, TAV, mock effects/state, TCP emulation and test randomness.
Inter-node and local-handoff composition tests are not completed migration or
rebind qualification. Image-content inventories remain provisional here;
P2.2 owns final bundle schemas/tooling. Deferred AAS tests are named obligations,
not passed results.

### T4.20 model - freeze the seams, not inferred hardware guarantees

Freeze the interfaces/compositions that let later SNP tasks follow the same
high-level request -> secure peer appraisal -> authorized platform effect ->
correlated result pattern. Audit every producer/consumer handoff, typed
authority boundary, missing-provider outcome and emulator/production exclusion.
The existing T4.20 deliverables, audit, review/acceptance and commit gates apply;
this modeling request does not authorize that future commit.

TDX is precedent for separation of responsibilities, not replacement SNP
authority. Retain Phase 5 qualification for production trust/revocation/time,
raw Version 6 layout, durable rollback/replay, actual firmware effects,
recovery equivalence, inventory/shutdown and crash handling. No TDCALL, TD UUID,
ServTD attribute/token, Intel QVL assumption or TDX MSK format enters a shared
SNP contract because it exists in the reference implementation.

### Design and approval rule for the modeled work

Do not ask the user to redefine rules already accepted in P0.1-P0.12A1.
Reduce new decisions to the precise SNP adaptation at each TDX-like seam:
complete package/reference ownership; binding-classification verification;
receipt/authorization separation; provider responsibilities/error mapping;
peer/control scheduling; secret/effect lifetime; composition selection.
Record recommendations with source precedent and acceptance tests. Any
behavioral/trust/wire change or unresolved firmware assumption requires
explicit approval or a retained fail-closed gate, not a TDX-equivalence claim.

Log each subsequent step centrally with its baseline, approved contract,
implementation/validation evidence, remaining gates and explicit acceptance.
This modeling entry is not a START, completion or freeze of T4.9-T4.20.

## T4.9 Tenant evidence source

Status: DONE - ACCEPTED BOUNDED INTERFACE/CONTROL-FLOW CONFORMANCE;
mandatory downstream qualification gates remain.

Execution contract: `T4.9-TenantEvidenceSourceV1-2026-11-03`.
The user approved implementation and the package/binding contract with no
conditions, and separately approved the coupled family-aware common TCB
amendment with no conditions. This is not a T4.20 interface freeze.

Accepted completion: `T4.9-TenantEvidenceSourceConformance-2026-11-04`.
User accepted at `2026-11-04T03:13:21Z`: "Accept bounded T4.9 implementation;
retain downstream gates". Conditions: None. Acceptance covers the implemented
interfaces and validated control flow, not runtime activation, real AAS
verification, production qualification or the later T4.20 freeze.

Mandatory P0.5 closure: consume the shared provisional/verified identity and
host-push delivery contract; validate references against already BASE-pushed
bytes and preserve request correlation. No MA-pull acquisition. Complete
evidence/supplement binding and durable replay must satisfy P0.6, not just the
base-report correlation helper.

Mandatory P0.6 closure: expose complete authenticated evidence receipts and
select explicit durable replay and current-firmware validation providers.
Missing production state must return `ProductionReplayStateUnavailable`;
an empty journal or test model is not a fallback. Preserve the frozen complete
evidence/authorization digests and provider trust boundaries.

Define:

```text
TenantEvidenceSource
TenantEvidenceRequest
TenantEvidence
TenantEvidenceBinding
TenantEvidenceError
```

Version 1 consumes host-pushed evidence from `PrepareMigrationRequest`.

Required classifications:

```text
GuestProvidedReportData
HostRequestedZeroReportData
```

Required errors:

```text
ProviderUnavailable
UnsupportedBinding
InvalidState
InvalidReport
IdentityMismatch
ReplayDetected
ProductionReplayStateUnavailable
```

Fixture and emulator providers support both classifications. The hardware
provider supports only deployed production behavior and otherwise fails
closed.

### Approved T4.9 implementation contract

Implementation:
[tenant_source.rs](../src/pal/src/snp/tenant_source.rs),
[common verifier contract](../src/pal/src/snp_report.rs), and
[interface tests](../src/pal/src/snp/tenant_source/tests.rs).

- `TenantEvidencePackage` owns already BASE-pushed base report, optional
  authenticated emulator supplement/signature and canonical collateral set.
  Construction enforces existing certificate/total-size, profile and Venice
  constraints; construction and hashing alone confer no trust.
- `TenantEvidenceRequest` consumes the existing `PrepareMigrationRequestV1`,
  package, locally constructed binding expectation and optional previously
  verified identity. Inline bytes or the unchanged SHA384(base-report)
  reference must match. No resolver, MA-pull, new cache wire record or opcode.
- One `HostPushedTenantEvidenceSource` owns one operation, selected trusted
  verifier, immutable local collateral/root/time configuration, receipt,
  existing durable replay journal and current-firmware provider. No defaults
  are supplied for these providers. The same source supports fixture/emulator
  request classifications through the common verifier, not a second workflow.
- `TenantEvidence` has no public constructor. Its retained immutable receipt
  contains common authenticated claims/provenance, exact complete package,
  canonical complete-evidence and collateral digests, operation and binding.
  Matching inline/reference retries reuse it. Changed bytes, supplemental
  signature, collateral, binding expectation or operation cannot replace it.
  The local slot is bounded to one package/receipt; cross-request cache,
  restart, trusted-time progression and root lifecycle are later owners.
- Host-zero verification uses the dedicated host tenant request and all-zero
  REPORT_DATA/host VMPL rules. Guest-provided verification uses the dedicated
  guest tenant request with independently expected legal VMPL and all64 bytes.
  It cannot export the host-zero delivery capability into active V1
  authorization. No MA-specific request or report-self-echo verification.
- Successful common-verifier output is checked against exact input provenance,
  binding, identity, Venice profile, supplement/history and collateral status
  before a receipt is minted. Verification is separate from policy approval,
  tenant-to-source-MA admission, replay authorization and installation.
- The existing P0.5 delivery and P0.6 digest/binding/journal formats remain
  unchanged. The retained P0.6 fixture trust tag is a compatibility
  representation, not permission to select its historical verifier/root.
  Actual fixture root verification belongs to the selected common adapter.
- Delivery performs no journal reservation or firmware operation. Later
  handoffs require the existing sealed purpose-1 replay binding and purpose-2
  authorization proofs, match the retained delivery, and reuse the existing
  journal/current-firmware checks. Missing durable state returns
  `ProductionReplayStateUnavailable`; terminal outcomes and rollback remain
  explicit errors. These handoffs do not perform migration-policy evaluation.
- `UnavailableSnpReportVerifier` always returns unavailable, never legacy TAV,
  a fixture default or claims. Raw production combined evidence fails at the
  existing Version 6 layout conflict; production rejects fixture evidence and
  guest-provided binding. No production parsing/effects or real AAS success
  are claimed.

Qualification boundary: interface doubles exercise both classifications and
failure/stage contracts, not signatures or live AAS. P0.10 crypto vectors
remain independent evidence. Task 6/AAS1A-M qualify signed fixture/common
adapter execution; T4.12/Tasks 7-12 activate host/peer scheduling and policy;
T4.16 corrects the existing SNP/emulator capability gate; H5.0/H5.1/H5.4
qualify physical layout, BASE/cache lifecycle and durable production state.
The new source is not selected by any existing runtime call site.

Validation completed 2026-11-04 for the 2026-11-03 execution baseline:
17 new unit tests and one new compile-fail receipt
test pass. Complete PAL suites pass: default 26 unit/5 doctests, existing
TAV-backed SNP 318 unit/16 doctests and existing Azure-backed SNP
319 unit/16 doctests. MigTD SNP library passes all 64 tests serially.
SNP binary-composition and TDX SPDM/policy_v2 checks, targeted formatting,
PAL all-targets Clippy and the unchanged independent P0.10 oracle (137 entries)
pass. No new-code Clippy warning remains; existing warnings are retained.

Diagnostic limitation: the first parallel MigTD run failed the unchanged
`migration::logging::test::test_log_info` request-ID assertion. Both subsequent
serialized full-suite runs pass. The original failure log is retained; no
logging/test-isolation fix or parallel-suite qualification is claimed here.
The new interface uses trusted contract doubles, not an implemented AAS
verifier. No live EMU, full CI, release-image or hardware qualification is
claimed. Exact commands/results and preservation evidence are recorded in
[implementation_record.log](implementation_record.log), with raw logs under
`target/t4.9-validation/20261103T233017Z/`.

## T4.10 Platform key provider

Status: DONE; BOUNDED IMPLEMENTATION ACCEPTED

Define exact typed operations for any platform key or platform secret required
by the SNP workflow. Do not assume `MSG_KEY_REQ` availability. Unavailable
hardware operations fail explicitly.

### Approved V1 disposition

Contract: `T4.10-PlatformKeyNotRequiredV1-2026-11-04`.
The user approved the recommended contract and implementation with no
conditions on 2026-11-04.

The approved active platform-derived-key operation set is empty. P0.10 derives
MSK and confirmation keys from two fresh secret contributions using its frozen
HKDF recipe. P0.11 derives the local handoff secret from a fresh random seed
and its separate frozen HKDF recipe. Neither includes a firmware-derived key.
Do not invent a root-key selector, guest-field selection, platform-secret
purpose, key-export request or firmware encoding merely to resemble TDX.

`MSG_KEY_REQ` remains defined in Firmware ABI v1.59 section 7.2; this decision
does not deprecate that service or claim a deployment implements it.
`PlatformKeyProvider::prepare_key(&SnpOperationContext)` remains only a disabled
compatibility boundary, not an approved purpose-scoped key request. Its
`UnavailablePlatformKeyProvider` implementation always returns
`PalError::NotAvailable`, without deriving/exporting a key, firmware invocation,
fixture fallback or success trace. It is not required in the V1 provider set
or session flow. A future derived-key need requires separate approval of exact
typed purpose, scope, lifetime, output/error and availability semantics before
an adapter or runtime call is introduced.

Remove `MockPlatformKeyProvider` and the mandatory success-only preparation call
from the legacy SNP session, preserving its early invalid-role rejection before
session effects. `SingleProcessMigration` and `InterNodeTwoProcessMigration`
must reject platform-key operation
traces instead of requiring modeled `MSG_KEY_REQ` success. Verification,
installer, role/request binding and secret-log checks remain required.
Update the provider-set, class and sequence diagrams consistently.

This bounded change does not alter the accepted P0.10/P0.11 recipes, installer,
wire/corpus, TDX/AzCVMEmu behavior or other legacy runtime flow. It does not
activate the approved contribution protocol or certify the legacy runtime as
implementing it. T4.11 owns typed installation; T4.14 owns randomness;
T4.15-T4.18 and Tasks 5-12 retain composition/caller/runtime integration;
T4.20 owns the overall interface freeze. Existing production/hardware gates
remain in force.

### Implementation and validation

Accepted completion: `T4.10-PlatformKeyNotRequiredConformance-2026-11-04`.
The user explicitly accepted the bounded implementation with all downstream
gates retained and no conditions at 2026-11-04T03:34:09Z.

The unavailable implementation is exercised for both source/destination roles
and exact retries. The legacy SNP session no longer constructs a platform-key
provider or reports modeled `MSG_KEY_REQ` success, but retains early role
validation before session effects. A new async regression checks invalid-role
rejection at the actual `exchange_msk` entry. The existing mock installer and
its input/trace behavior are unchanged. Required provider-set/class/sequence
diagrams no longer prescribe a platform-key slot or preparation call.

Validation completed 2026-11-04:

- PAL default: 27 unit tests and 5 doctests pass.
- PAL SNP with existing TAV backend: 319 unit tests and 16 doctests pass.
- PAL SNP with existing Azure backend: 320 unit tests and 16 doctests pass.
- Separate `snp_emu`: 7 unit tests pass; MigTD SNP/Azure: 66 pass serially.
- Both new unit regressions, targeted formatting, shell syntax, PAL all-targets
  and MigTD library/test Clippy, TDX SPDM/policy_v2 composition and the SNP musl
  release build pass. Existing warnings are not promoted to clean-warning claims.
- Legacy Stage A autostart and Stage B WFR/controller regressions pass
  sequentially on the same final ELF. Stage A rejects an injected legacy
  success trace, and Stage B rejects an injected failure trace. Both negatives
  reach the explicit unapproved-operation check after otherwise successful
  workflows. Binaries remain unchanged during execution and ports are released.
- The independent P0.10 oracle retains 137 exact entries and passing crypto
  negatives. All Phase 0 sections, the entire TDX model, the 37-step order and
  453 other baseline files remain byte-exact. The central log is append-only.

Diagnostic limitation: an initial combined `-p pal -p snp_emu` test command
enabled the emulator dev dependency's default/native TAV crypto backend and
failed to compile the unchanged P0.10 pure-Rust certificate test adapter.
The separate suites above use the previously validated PAL selections and
pass. The original failure is retained; no combined-feature pass, dependency
repair or additional backend qualification is claimed.

These are bounded interface and legacy-runtime regression results, not
activation of the accepted contribution/handoff protocols or production key
services. Full CI, the T4.19 regression matrix, T4.20 freeze and all real
hardware/production qualification gates remain open. Commands, results,
limitations and preservation evidence are recorded in
[implementation_record.log](implementation_record.log); raw evidence is under
`target/t4.10-validation/20261104T032332Z/`.

## T4.11 Migration key and history installer

Status: DONE - ACCEPTED for bounded typed interface/conformance;
downstream runtime, stateful emulator and hardware gates retained.

Contract: `T4.11-TypedInstallerBoundaryV1-2026-11-04`.
User disposition: "Approve recommended bounded contract and implement T4.11".
Conditions: None. Recorded with the START baseline at
`2026-11-04T16:20:27Z` in the central append-only execution record.
Prerequisites: accepted P0.4/P0.8 contracts and bounded T4.9/T4.10.

Accepted completion: `T4.11-TypedInstallerConformance-2026-11-04`.
Accepted UTC: `2026-11-04T16:35:15Z`. User disposition:
"Accept bounded T4.11 implementation; retain downstream gates".
Conditions: None. This does not activate a runtime installer, qualify a kernel
API/hardware effect or authorize automatic execution of T4.12.

Current scope: fresh post-install purpose-3 attestation and peer verification
are deferred, not prerequisites for this interface or current success/readiness.
Retain exact-history admission, prior authorization/confirmation, role-specific
firmware completion and truthful partial/indeterminate outcomes. A local
completion receipt does not claim independently attested persistence.
The MA-facing request uses a logical managed-tenant handle; OHCL/kernel owns
target-context resolution, GCTX_PADDR, physical buffers and firmware encoding.
The exact OHCL API is not assumed or invented here.

Define the MA-facing interface for ARG ABI v1.20
`MSG_SET_MIGRATION_INFO`.

Request:

```text
managed tenant handle
verified tenant REPORT_ID
32-byte MSK
exact 64-byte VeniceV1 MigrationDataV1
source or destination role
algorithm 0x0003
request and session identity
```

Result/error:

```text
source versus destination REPORT_ID rules
bound-MA failure
guest-state failure
active-session failure
algorithm failure
firmware status
partial-install or abort requirement
```

### Approved bounded Rust contract

The new interface is
`pal::snp::migration_install::SnpMigrationKeyInstaller`:

```rust
fn install_migration_info(
    &self,
    request: &MigrationInstallRequestV1<'_>,
) -> Result<MigrationInstallCompletionV1, MigrationInstallErrorV1>;
```

`MigrationInstallRequestV1::new` borrows the existing `SnpOperationContext`,
`VerifiedTenantIdentity`, `VerifiedTenantAuthorizationV1`,
`SnpSessionReferenceV2` under T4.14-PRE, MSK `[u8; 32]` and history `[u8; 64]`, and validates
algorithm `Aes256GcmMigrationV1` (`0x0003`). All seven operation fields must
match the authorization binding, its tenant REPORT_ID must match the verified
identity, and the session request ID must match the operation. Decode the
history with the existing exact `MigrationDataV1` codec; preserve every byte
rather than recalculating it in the installer.

These are shape/correlation checks, not new authorization. The caller must
already admit that exact history and policy, enforce durable/current-firmware
replay authorization, reconstruct the amended V2 session reference and require
protected acceptance/destination completion as role-appropriate. The shared
authorization type proves only its documented role-proof scope (active V2
purpose7). The original T4.11 acceptance remains historical; the reference
type and active proof construction are amended by T4.14-PRE. Providers independently enforce current target,
bound-MA, guest-state, role, active-session and algorithm conditions.

The logical request retains the verified identity for both roles.
`firmware_report_id()` yields that identity for source and zero[32] for the
destination's ignored operand. It exposes no physical address, buffer layout,
ioctl number or invented OHCL API. Kernel/lower-layer target authorization,
protected marshalling and secret-copy cleanup remain PA-008/H5 work.

The request is non-cloneable and borrows secret material; Debug redacts key,
identity, authorization, history and session material. The caller owns
zeroization of the secret and any transport copies. A borrowed request cannot
outlive its secret owner.

Local completion/error correlation retains the full operation, verified tenant
REPORT_ID and existing session reference. Completion construction accepts only
observed raw firmware status zero; it is not a wire result, independently
attested persistence receipt or proof that a mock invoked firmware.
Callers must compare response correlation before advancement.

Errors distinguish unavailable, firmware rejection, transport failure, observed
partial installation and indeterminate effects. Optional raw status preserves
absent versus zero versus nonzero. Effects are NotApplied, Partial or Unknown;
partial/unknown require reconciliation and no error authorizes success.
There is no automatic retry. Raw nonzero firmware status is conservatively
Unknown pending a qualified status/effect mapping: shared INVALID_GUEST and
INVALID_GUEST_STATE codes do not justify inventing precise bound-MA versus
REPORT_ID, or guest-state versus active-session diagnoses.

`UnavailableMigrationKeyInstallerV1` returns an explicit correlated unavailable
error for both roles/retries, without platform effects or fixture fallback.
Recording/failure-injection implementations exist only in unit tests; real
stateful emulator semantics remain Task 11 and hardware integration remains H5.
Exports use the existing PAL SNP feature gate; final product provider/feature
composition remains T4.15-T4.18.

The existing `pal::traits::MigrationKeyInstaller::set_migration_info(context,
&[u8])`, `MockMigrationKeyInstaller` and legacy runtime remain separate and
unchanged in behavior. They cannot supply the full new request and are not
adapted with invented identity, history or authorization. No current runtime
is switched to the new interface in this milestone. Historical P0.8 controller
reconciliation remains T4.12/before activation; purpose-3 exchange stays deferred.

### Bounded validation and retained gates

Sixteen new unit tests cover both roles, borrowed material, all operation
correlation fields, identity/session/algorithm rejection, canonical history,
exact history forwarding, redacted Debug, raw status and all local failure/
effect shapes. Two new compile-fail doctests check non-cloneability and
secret-borrow lifetime. Recording and failure-injection providers are test-only,
not signed evidence, stateful firmware emulation or persisted-state proof.

Final validation: default PAL 27 unit/5 doctests; TAV PAL 335/18; Azure PAL
336/18; separate snp_emu 7; serial MigTD SNP 66. Targeted rustfmt, PAL and
MigTD Clippy, TDX SPDM/policy_v2 composition and release-musl build pass.
Final legacy Stage A/B pass sequentially; independent P0.10 oracle retains
137 exact entries and passing cryptographic negatives. Existing unrelated
warnings remain. Initial new large-error Clippy diagnostics were resolved by
boxing only the error's owned nonsecret correlation, without losing fields;
the final installer files have no lint diagnostics.

Evidence: `target/t4.11-validation/20261104T162027Z/`.
No runtime is activated or adapted; no actual OHCL API/firmware invocation,
stateful emulator semantics, production retry mapping, fresh purpose-3
exchange, full CI or hardware qualification is claimed. T4.12/P0.8
reconciliation, T4.15-T4.20 composition/regression/freeze, Task 11 and H5/PA-008
remain open. Implementation acceptance is separate from contract approval.

## T4.12 Host control and MA binding interfaces

Active amendment: [T4.14-PRE](snp/task4/t4.14-pre-direct-random.md) replaces
the V1 HMAC sequence below with `InstallExchangeSequenceV2` and private
protected-acceptance receipts. Host entry additionally checks the exact
authorization digest/local role; correlated local and peer firmware effects,
durable replay and reconciliation remain. The original acceptance below is
historical interface evidence, not acceptance of these replacements.

Status: DONE - ACCEPTED for bounded interface/controller conformance;
downstream runtime, storage, stateful emulator and hardware gates retained.

Completion: `T4.12-HostControlBindingConformance-2026-11-04`.
Accepted UTC: `2026-11-04T17:41:29Z`.
User explicitly confirmed "Accept bounded T4.12 implementation; retain downstream
gates" with boolean true. No additional conditions supplied.

Contract: `T4.12-CorrelatedHostControlAndBindingV1`.
User explicitly approved the bounded A-E contract on 2026-11-04; the initial
form response "None" was not counted as approval; follow-up boolean was true.
Prerequisites P0.5/P0.11 are accepted. Real adapters, active workflow,
deployment storage and hardware qualification remain downstream gates.

### T4.12 approved bounded implementation contract

The additive implementation is in
[`host_control`](../src/pal/src/snp/host_control.rs),
[`control_exchange`](../src/pal/src/snp/control_exchange.rs) and
[`binding_manager`](../src/pal/src/snp/binding_manager.rs).
Legacy TDX-shaped TCP/runtime behavior remains unchanged and is not an adapter
to these contracts.

**A - host framing.** `SNP-HC01`, version u16=1, little-endian. The 72-byte
header carries magic8, version2, kind2, direction1, reserved3, total-length4,
reserved4 and the complete 48-byte operation context. Kinds 1-5 are prepare,
cancel, abort, query/status and local handoff. Direction 0 is request and 1 is
response. Operation context encodes request/migration/handle/peer/policy u64s,
protocol major/minor u16s, legacy logical role (source=1/destination=0),
presence bits (peer=1/policy=2/version=4), reserved2. Absent option bytes are
zero; present zero is distinct from absent. Total frame cap is 65,536 bytes,
not the separate 8,192-byte SPDM application cap.

Prepare carries a whole-package digest48, delivery kind1, then either a
length-prefixed inline package or the frozen base-report reference48, followed
by complete source and destination MA packages. Packages carry profile1
(raw=0/emulator=1), reserved3, collateral-length4, base-report1184, optional
emulator supplement220/signature96, and the existing collateral-set bytes.
Each package has an outer u32 length. Reference lookup is only against an
already BASE-pushed local package, checking both SHA384(base report) and the
separate SHA384(exact host package). Neither digest is a trust anchor.
Profiles transport untrusted bytes, never host-selected roots/verifiers or
authority. Receipt identity is promoted only by the existing verifier.

Cancel/abort/query requests have empty bodies. Status responses encode
phase1, terminal outcome1 (absent=0/success=1/abort=2/failure=3), reserved2 and
result digest48 (absent=zero). Phase values 0-8 are awaiting evidence,
evidence received, source evidence matched, purpose1 verified, authorized,
installation started, installed locally, terminal, reconciliation required.
Terminal phase and outcome presence must agree. Local frames contain the
unchanged P0.11 control record and matching request ID; its distinct binding,
roles and 128-bit operation namespace are not derived from migration IDs.
No key/secret has a host-control codec.

**B - retained lifecycle.** `SnpHostOperationV1` owns one evidence source,
complete operation, package/profile association, verified replay binding,
session reference and terminal observation. It requires local verified
evidence plus matching complete source-evidence association before purpose1
reservation; purpose2/current-firmware authorization is a separate transition.
The peer association must come over the authenticated peer path; digest
equality alone is not proof of remote verification or policy.

Construction queries the existing authenticated P0.6 journal. Authenticated
terminal outcomes can be queried without new proofs/effects. Any restored
nonterminal operation requires reconciliation, not a new SPDM session.
Before a P0.6 binding exists, the separately injected
`HostControlContextAuthorityV1` must durably reserve the complete operation
with anchored pre-proof tombstones. An existing reservation requires
reconciliation even if the P0.6 journal is empty. Missing/unavailable state
fails closed; no empty-state fallback is supplied. Production context storage
is unavailable, not an in-memory implementation.

Exact delivery retries retain the owner and do not repeat replay/platform
effects. Before verified reservation, cancellation durably records an abort
through the pre-proof context authority without fabricating a replay binding.
After verified reservation, cancellation uses the existing P0.6 journal.
Pre-proof context outcomes cannot claim migration success. Once installation
starts, cancel/abort or uncertain effects require reconciliation. Terminal
results are durably acknowledged before return; ambiguous writes require
reconciliation. Restart never reconstructs keys or resumes a lost session.

**C - current-scope P0.8 reconciliation.** Frozen 128-byte confirmations,
136-byte persisted-installation results and the historical
`SnpConfirmationSequenceV1` remain unchanged. The latter remains inactive:
no fake purpose3 verifier and no reinterpretation of its success digest.
A distinct `FirmwareCompletionRecordV1` (record 0x0008, element 0x0107,
88 bytes, magic `SNP-LM-F`) reports MA-observed firmware completion, not
attested persistence. It contains header16, session reference56, role1,
outcome1, effect1, status-presence1, raw-status4, reserved8. MA roles remain
source=0/destination=1. Outcomes are completed=1/not-applied=2/unavailable=3/
indeterminate=4; effects are not-applied=0/applied=1/partial=2/unknown=3.
Completed requires applied/Some(0); unavailable requires not-applied/None;
not-applied cannot carry Some(0); indeterminate requires partial or unknown.
Absent raw status bytes are zero. Local conversion checks the entire T4.11
correlation. Raw firmware rejection remains unknown/indeterminate until a
qualified effects mapping exists.

`InstallSessionControlV1` (record 0x0009, element 0x0108, 80 bytes, magic
`SNP-LM-Q`) contains header16, session56, kind1, reserved7; kind1=poll and
kind2=acknowledge source completion. Both new headers contain version u16=1,
record type u16 and exact length u32. Existing allocations are not renumbered.

| Exchange | Request opcode / element / bytes | Response opcode / element / bytes |
|---|---|---|
| Poll destination confirmation | 0x28 / 0x0108 / 80 | 0x29 / 0x0105 / 128 |
| Submit source confirmation; destination installs after verification | 0x2A / 0x0105 / 128 | 0x2B / 0x0107 / 88 |
| Source installs after destination completion, submits its outcome | 0x2C / 0x0107 / 88 | 0x2D / 0x0108 / 80 |

These are paired authenticated/encrypted inter-node exchanges, not unsolicited
responses, local handoff controls or host notifications. One pending request
is allowed. Wrong direction/session, duplicate/reordered/unsolicited responses,
failed confirmation or negative installation aborts the transcript; effects
remain subject to reconciliation. Both confirmations are independently
verified using the selected verifier. A private confirmation receipt permits
destination installation after the source tag; source installation additionally
requires the destination completion response. A private completed-exchange
receipt plus matching local completion is required before durable success.
Neither receipt independently proves policy/KDF correctness or live-session
authority. Actual cryptographic/session/provider composition remains later work.
0x2E-0x2F remain unallocated. Fresh purpose3 stays deferred.

**D - binding boundary.** `MaBindingManagerV1` exposes protected set/clear,
planned/recovery rebind and authoritative binding query. Rebind requests
borrow the existing Ready P0.11 contract and validate exact binding and tenant
membership; providers must additionally enforce correct method/mode, current
authority, firmware recovery equivalence, slot reservation/effect scope and
cleanup. Set-secret is borrowed/redacted/non-cloneable and planned-only.
Recovery does not create an outgoing proof/session/secret requirement.
Logical handles are not GCTX addresses. Local completion is correlated and
status zero only; errors retain raw status and not-applied/partial/unknown
effects. No automatic retry or stateful platform implementation is supplied.
Unavailable providers return explicit errors, never success-only stand-ins.

**E - qualification boundary.** Tests exercise strict codecs, authenticated
state-provider handoffs, transcript scheduling and legacy preservation using
labeled test-only doubles. They do not qualify real durable storage, complete
MA-profile appraisal, active SPDM/HMAC, kernel/GHCB/BASE APIs, authoritative
emulator effects or hardware. Production actions remain
[PA-007-OHCL-01 through -07](snp-production-readiness.md#pa-007-t412-ohclbase-host-control-integration-actions)
and [PA-008](snp-production-readiness.md#pa-008). No T4.13 execution is authorized.

Validation, 2026-11-04: 24 new unit tests across PAL/MigTD and two new compile-fail
tests; PAL default 27/5, TAV 358/20, Azure 359/20, snp_emu 7 and serial full
MigTD SNP library 67. Three independent Python byte-layout vectors match the
new host query/completion/poll codecs. Targeted format/Clippy, default TDX
SPDM/policy_v2 compilation, musl release build and sequential legacy Stage A/B
passed. Other canonical sections and exact execution order are byte-exact;
449 other baseline files and HEAD are unchanged. Final commands/hashes and
qualification exclusions are retained in the central execution record.
This is not a full CI gauntlet or actual new-protocol runtime/hardware result.

Mandatory P0.5 closure: wire the shared logical request and identity promotion
into the final request/response and transport framing. Preserve complete
operation correlation and idempotent delivery without repeating workflow
effects; retain the correlation slot across retries and enforce P0.6 durable
state, including terminal outcomes and restart.

Mandatory P0.6 closure: both BASE requests must supply the same complete source
tenant evidence before current V2 purpose 6. Do not bootstrap from the later
authorization exchange. Wire distinct purpose-6/purpose-7 workflow states, complete MA
profile transport, terminal queries and authenticated restart context; never
reconstruct an empty replay journal or silently replace a lost SPDM session.

Current P0.8 integration closure: finalize inter-node SPDM request/response
scheduling for V2 protected delivery/acceptance and correlated firmware
outcomes, coordinating the Task 3 opcode registry with P0.11 without conflating
local handoff and inter-node transports. Fresh purpose-3 evidence and its
verification acknowledgement are deferred. Explicitly reconcile the historical
P0.8 success-admission API before activation, without changing frozen records,
fabricating persistence verification or reusing an authorization-result record
as an installation result. No unsolicited response substitutes for correlated
result delivery.

Migration operations:

```text
PrepareMigrationRequest/Response
host request identity
managed tenant handle
host-pushed tenant report or authenticated reference
source or destination role
cancel, abort, query, and status
```

Local handoff/recovery operations use the P0.11 contracts.

Define a provider boundary such as:

```text
MaBindingManager
    set_handoff_secret
    clear_handoff_secret
    rebind_handoff
    rebind_recovery
    query_binding
```

The emulator implementation owns authoritative binding state. The hardware
implementation maps managed handles to GCTX addresses and firmware commands.

## T4.13 Peer-channel boundary

Active amendment: [T4.14-PRE](snp/task4/t4.14-pre-direct-random.md) retains
the purpose-separated owner/backend lifecycle but selects purposes6/7 and
opcodes0x30-0x35; old0x26-0x2D are rejected. Only successful promoted peer
I/O can mint `ProtectedInstallRecordV2`. The original acceptance below is
historical bounded evidence; replacement tests are recorded separately.

Status: DONE - ACCEPTED for bounded interface/channel conformance;
downstream runtime, transport, policy/crypto and hardware gates retained.

Completion: `T4.13-PeerChannelConformance-2026-11-04`.
Accepted UTC: `2026-11-04T18:25:34Z`.
User explicitly confirmed "Accept bounded T4.13 implementation; retain downstream
gates" with boolean true. No additional conditions supplied.

Contract: `T4.13-PurposeSeparatedPeerBoundaryV1`.
Approval recorded UTC: `2026-11-04T18:01:40Z`.
User explicitly approved bounded contract A-E with boolean true; no additional
conditions supplied. P0.7/P0.8/P0.11 bounded contracts are accepted. T4.12's
accepted operation correlation and current-scope completion schedule remain
integration constraints, not proof of production crypto or transport support.

Define:

```text
PeerTransportFactory
PeerSession
SPDM establishment
application VDM send and receive
message correlation
close and abort
```

Support two explicitly typed uses:

```text
InterNodeMigrationPeerSession
LocalMaHandoffPeerSession
```

The session type fixes expected roles, policy, allowed messages, and transport
purpose. Messages from one session type are rejected in the other.

### Approved T4.13 bounded implementation

The [PAL peer boundary](../src/pal/src/snp/peer_channel.rs) supplies:

1. `PeerTransportFactory`/`PeerSession` trusted adapter contracts and
   `UnavailablePeerTransportFactoryV1`; there is no production connection,
   plaintext fallback, invented OHCL API or implicit emulator selection.
2. A `PendingPeerSessionV1` bootstrap owner. Only MA evidence/collateral is
   allowed before promotion. Its expected contexts use the backend's actual
   current SPDM TH1, never the caller's template TH1. Production adapters must
   already provide SPDM confidentiality/integrity for bootstrap delivery.
3. Separate non-cloneable inter-node and planned-local session types.
   Promotion borrows existing `VerifiedLmPolicyV1` and both
   `VerifiedMaPolicyCollateral` objects, compares complete role-specific
   contexts/current TH1 and policy digests, and invokes trusted current policy
   admission. Local MA REPORT_IDs must match the exact old/new binding.
   Fixed/ordered-release pair checks and current binding/epoch/attempt/stage
   appraisal are backend obligations; a test double is not their qualification.
4. Immutable full operation correlation, current engine binding checks around
   I/O, one outstanding inter-node request, exact paired response opcode and
   source-requester/destination-responder direction. A shared PAL registry
   lookup is reused by MigTD's existing static VDM validator; no opcode,
   element, version, frozen record or application-size limit is changed.
5. Exact bounded frame/record decoding and role/context checks. Purpose1
   contexts match exactly; purpose2 additionally requires the existing tenant
   authorization controller to verify its independently reconstructed binding.
   Confirmation/completion records require a once-bound trusted P0.10 session
   reference, distinct from SPDM session ID/TH1. Actual commitment/HMAC checks
   and T4.12 protocol ordering remain their existing controllers' duties.
6. Logical local MA-evidence/collateral, exact metadata-snapshot digest and
   outgoing-to-incoming secret transfer, with owned zeroizing secret buffers
   and redacted diagnostics. These are not new local wire opcodes or plaintext
   host records. Secret transfer is prepare-stage planned-only. No recovery
   session with a failed outgoing MA is constructed; incoming-only recovery
   retains P0.11's independent authority/evidence path.
7. An absolute deadline from trusted time, clock-rollback detection and
   pre/post-operation checks. The backend must enforce deadlines inside its
   blocking/async I/O; wrapper checks cannot interrupt a stuck syscall.
   Failures abort the owner without automatic retry/replacement. Primary and
   cleanup errors remain separate; uncertain cleanup requires reconciliation.
   Close is idempotent only after successful closure with no pending request.
   Drop requests backend abort and logs cleanup failure, but proves no firmware
   slot cleanup, durable terminal state or hardware effects.

This scope defines channel conformance, not a second contribution/confirmation,
tenant-policy or replay controller. Verified proof types cannot be manufactured
from received frame bytes by this boundary. Test adapters model encrypted
delivery/current admission; they do not execute real SPDM or production policy.
Actual SNP handlers, full cryptographic/provider composition, production
transport routing, local peer wire framing and hardware remain later gates.
Current TDX/emulator runtime remains selected as before. Fresh purpose3 stays
deferred. No T4.14, commit or push is authorized.

Production obligations are tracked under
[PA-007 T4.13](snp-production-readiness.md#pa-007-t413-peer-channel-qualification-actions).
TDX precedent and application-design choices are explained in the
[technical note](snp/approval-decision-technical-note.md#10-t413-purpose-separated-peer-channel-boundary).

### T4.13 validation evidence

Final validation passed on 2026-11-04: 25 new unit tests and 3 new compile-fail
tests; PAL default 27 unit/5 doctests, TAV 383/23, Azure 384/23; snp_emu 7;
full serial MigTD SNP library 67. Coverage includes all fourteen active
inter-node opcodes in both directions, bootstrap/app isolation, actual-backend
versus template TH1, wrong/stale/full-operation correlation, local metadata,
secret direction, recovery exclusion, deferred-purpose3 rejection, deadline/
clock failure, close/abort/drop, provider errors and cleanup uncertainty.
Relevant PAL/MigTD Clippy and targeted formatting passed with no diagnostics
in the new peer boundary/tests or changed SNP VDM validator; unrelated existing
warnings remain. TDX SPDM/policy_v2 compilation and the established musl release
build passed. Sequential legacy Stage A/B passed on the same rebuilt ELF,
all roles/controllers exited zero, and no regression listener remained.
TCP TIME_WAIT was distinguished from a live listener using socket inspection
and SO_REUSEADDR rebind checks.

Evidence: `target/t4.13-validation/20261104T180140Z/`.
These are channel/fixture conformance and legacy regressions, not activated
SNP peer exchange, real SPDM/cryptographic admission, actual local wire support,
production adapters, full CI parity or hardware qualification.

## T4.14 Randomness and secret services

Status: DONE - ACCEPTED; documented bounded scope and exclusions.
Implementation authorized at 2026-11-05T02:23:45.866Z.
Completion accepted at 2026-11-05T03:02:37.597Z.
User acceptance: "I accept T4.14 within its documented bounded scope,"
No additional conditions were specified. Existing exclusions remain in force.
T4.14-PRE completed, accepted and frozen at
2026-11-05T02:22:07.036Z; conditions: None. Consume P0.7 and P0.11 as
superseded by that amendment. No T4.14 implementation or completion is
claimed by the accepted pre-step.

Define:

```text
RandomSource
MigrationKeyV2 (final MSK32)
HandoffSecret
zeroizing wrappers
deterministic test source
ownership and move/copy rules
cleanup on success, failure, cancel, timeout, and panic boundaries
```

Generate independent final random32 MSK/handoff values. There is no seed,
commitment, HKDF, PRK or application HMAC confirmation. Preserve the nonsecret
V2 context, once-only generation/retry authority, move-only/redacted owners,
secure transfer and complete success/failure/uncertain-effect cleanup.

Completion: `T4.14-RandomSecretServices-2026-11-05`.
The shared [random service](../src/pal/src/random.rs) supplies `RandomSource`,
explicit unavailable behavior and a ring `SystemRandomSource` under PAL's
`system-random` capability. That capability alone does not enable SNP/TAV,
OpenSSL or Azure attestation. `snp-emu` selects it without changing the
existing ring source or lockfile. Scripted deterministic values are compiled
only into unit tests, not selectable by deployed consumers.

Existing MSK/handoff generators accept the shared service through their typed
domain adapters. They retain source-only/Prepared-first-attempt checks and
independent direct32-byte draws. Private non-Clone/non-Copy `Secret32` storage
uses volatile zeroization through `zeroize` on Drop. Public consuming `clear`
methods retire owners without leaving a usable zero-key object; authorized
retries retain the same owner rather than generate a replacement.
Wire payloads retain their existing zeroizing ownership and exact V2 bytes.

Handoff installation consumes the local owner on success, error and unwind.
Errors attempt two-slot cleanup exactly once; cleanup failures remain explicit.
Unwind attempts the same cleanup with logged reconciliation failures.
Successful installation retains provider slots for the actual handoff;
finalization/abort cleanup remains the authority/runtime's responsibility.
Cleanup providers must not panic. Panic-abort, crash, kill, firmware-slot
persistence and compiler/register/transport-internal copies are not erased or
qualified by Rust Drop; downstream reconciliation/qualification remains required.
An RNG/constructor is not durable once-only/restart authority or local
outgoing-role appraisal; those remain admitted runtime/provider obligations.

Final validation: PAL default33/6, standalone RNG34/6, SNP413/24 and
Azure-SNP414/24 unit/doctests PASS; registered libraries, SNP/MigTD tests,
unchanged independent V2/P0.10 corpora and strict checks PASS. Full local CI
command parity passes with Rust1.88:32 firmware builds,six tools,14 EMU
scenarios. Azure SNP tests and rebuilt musl legacy Stage A/B use their required
Rust1.90 toolchain and pass. No hardware/new-runtime qualification is claimed.
Evidence: `target/t4.14-secret-services/20261105T022345Z/` and the append-only
central log. T4.14 bounded completion acceptance is recorded separately;
T4.15 is READY for a separately authorized start and remains NOT STARTED.

## T4.15 Explicit provider sets

Status: DONE - ACCEPTED; documented bounded scope and exclusions.
Authorized at 2026-11-05T13:08:46.245Z after accepted T4.9-T4.14 completions.
Completion identifier: `T4.15-ExplicitProviderSets-2026-11-05`.
Completion accepted at 2026-11-05T13:51:09.902Z.
User acceptance: "I accept T4.15 within its documented bounded scope and exclusions."
No additional conditions were specified; existing exclusions remain in force.

Freeze these top-level compositions:

```text
SnpEmuAzure
SnpHardware
AzCVMEmu
TDX hardware
```

The names have distinct meanings:

```text
SnpEmuAzure
    Cargo feature and emulator composition

SnpHardware
    Cargo feature and production Linux/Underhill composition

SnpHardwareProvider
    concrete production provider selected by SnpHardware
```

The build/runtime matrix is:

| Composition | Runtime | Rust mode | SNP verifier | Evidence and state |
|---|---|---|---|---|
| TDX hardware | Bare-metal MigTD | `no_std` | Intel TDX path | Production |
| AzCVMEmu | Host emulator | `std` | TDX emulator path | Emulator |
| SnpEmuAzure | Linux/Underhill emulator | `std` | AAS base report + signed `SnpEmulatorV1` supplement | Fixtures and emulated state |
| SnpHardware | Linux/Underhill production | `std` | Common verifier contract; physical Version 6 overlap blocked | Real providers |

Shared SNP capability modules:

```text
snp-core
    typed SNP reports, wire records, policy inputs, provider traits

snp-aas-verify
    common SnpReportVerifier contract and AAS base-report adapter

snp-underhill-runtime
    PID1/Linux runtime behavior shared only where explicitly selected
system-random
    existing PAL ring-backed OS CSPRNG for both Linux SNP compositions
```

Emulator-only capability modules:

```text
snp-fixture
    SnpEmulatorSupplementV1 codec, signer, and verifier
snp-state-emulator
snp-tcp-transport
snp-mock-installation
snp-mock-rebind
```

Scripted deterministic randomness remains an isolated `cfg(test)` provider
under accepted T4.14, not a deployable emulator capability or runtime option.

Production-only capability modules:

```text
snp-linux-hardware
snp-production-collateral
snp-production-transport
snp-production-randomness
snp-production-installation
snp-production-rebind
snp-production-persistence
```

`SnpEmuAzure` includes fixture evidence, fixture roots, migration-state
emulation, firmware binding-state emulation, the real OS-backed random service,
and approved emulator transports.

`snp-production-randomness` selects that same existing PAL `SystemRandomSource`
for Linux production; the capability name does not introduce another RNG.
Selection is not production qualification. The proposed kernel entropy-
provenance checklist is not a newly accepted prerequisite or implementation
mandate; downstream production evidence scope requires explicit review.

`SnpHardware` never contains fixtures, synthetic roots, TCP emulation, TDX
calls, mock installation, mock rebind, deterministic test randomness, or a
runtime fallback to any emulator provider.

Bounded implementation:

- [Composition contracts](../src/pal/src/composition.rs) describe all four
  platform/mode/provider-family selections without changing TDX entry points,
  transports or Cargo feature inheritance.
- Sealed SNP composition types own private provider selections. The emulator
  root accepts trusted typed service inputs; production accepts no emulator
  injection. Consumers borrow existing evidence, collateral, peer/clock,
  host/context, replay/firmware-state, installation, binding and protected
  handoff seams without replacing the owned providers.
- Both Linux SNP sets select the concrete `SystemRandomSource`; scripted
  randomness remains unit-test-only. The disabled platform-key provider and
  common unavailable `SnpReportVerifier` remain explicit. Production effects,
  evidence/collateral and trusted clock are unavailable; construction or RNG
  availability is not admission or production readiness.
- `composition::snp::SnpHardwareProvider` names the closed aggregate, not the
  older report-only adapter in `snp::hardware`. Shared SNP remains under its
  historical `snp-emu` gate until T4.16. This step does not claim a new
  `SnpHardware` Cargo feature, production image isolation, an implemented AAS
  adapter, physical Version 6 parsing or effectful runtime activation.

Validation: PAL default34/6, system-random35/6, SNP418/27 and Azure-SNP419/27
unit/doctests PASS; SNP emulator7, serial MigTD SNP library67, registered
libraries, unchanged V2/P0.10 references and scoped strict checks PASS.
Full local Rust1.88 CI command parity passes:32 firmware builds,six tools,
14 EMU scenarios,28/28 process exits zero. Rebuilt musl legacy Stage A/B PASS.

During validation, the newly reported baseline `pin-utils` advisory blocked
CI. The user separately authorized narrow dependency remediation. Compatible
futures-util0.3.32/hyper1.9.0 and supporting futures updates remove `pin-utils`;
the new lockfile was revalidated without waivers or toolchain changes.
Supplemental Rust1.88 strict SNP checks exposed unchanged TAV/peer-log lints;
they remain recorded failures, not repaired or claimed passed. Established
strict workspace/PAL checks pass with Rust1.90; CI retains Rust1.88.

Evidence: `target/t4.15-provider-sets/20261105T130846Z/`.
Existing fixtures were restored byte-for-byte, prior evidence and the 37-step
order retained. No production row, broader phase or GitHub-hosted CI execution
is qualified. Bounded completion acceptance is recorded separately;
T4.16 is READY for a separately authorized start and remains NOT STARTED.

## T4.16 Feature selection

Status: DONE - ACCEPTED within its documented bounded scope and exclusions.
Completion identifier: `T4.16-FeatureSelection-2026-11-05`.
Authorized by "Implement T4.16" at `2026-11-05T15:12:07.400Z`.
Validation recorded at `2026-11-05T16:05:02.185Z`.
User acceptance: "I accept T4.16 within its documented bounded scope and exclusions."
Acceptance timestamp: `2026-11-05T16:11:10.268Z`.
No additional conditions specified; existing exclusions remain in force.
This current disposition supersedes earlier readiness/not-started statements.

### T4.16.1 Make shared SNP code independent of `snp-emu`

Replace the current impossible gate:

```text
pal::snp exists only when snp-emu is enabled
hardware provider exists only when snp-emu is disabled
```

with capability-based gates such as:

```rust
#[cfg(feature = "snp")]
pub mod snp;

#[cfg(feature = "snp-fixture")]
pub mod fixture;

#[cfg(feature = "snp-linux-hardware")]
pub mod hardware;
```

Shared report, policy, wire, collateral, and verifier traits compile for both
`SnpEmuAzure` and `SnpHardware`.

### T4.16.2 Make `std` explicit

Use an explicit `std` capability instead of treating `SnpEmu` as synonymous
with all SNP code:

```rust
#![cfg_attr(not(any(test, feature = "std")), no_std)]
```

`SnpEmuAzure`, `SnpHardware`, and `AzCVMEmu` enable `std`. TDX hardware does
not. Enabling `std` does not enable fixtures or emulator providers.

### T4.16.3 Split Underhill runtime from emulator capability

The current inheritance:

```text
SnpUnderhill -> SnpEmu
```

must be removed. Introduce a runtime capability, for example:

```text
SnpUnderhillRuntime
```

that supplies PID1 and Linux/Underhill behavior without selecting fixture
evidence, synthetic roots, emulator state, TCP transport, or mock firmware
operations.

Compose:

```text
SnpEmuAzure =
    std
    + SnpUnderhillRuntime
    + snp-core
    + snp-aas-verify
    + snp-fixture
    + snp-state-emulator
    + snp-tcp-transport
    + system-random
    + snp-mock-installation
    + snp-mock-rebind

SnpHardware =
    std
    + SnpUnderhillRuntime
    + snp-core
    + snp-aas-verify
    + snp-linux-hardware
    + snp-production-collateral
    + snp-production-transport
    + snp-production-randomness
    + snp-production-installation
    + snp-production-rebind
    + snp-production-persistence
```

The production randomness capability selects PAL `system-random`. Scripted
randomness is unit-test-only and is not part of either deployed composition.

### T4.16.4 Select AAS exclusively for SNP

Both SNP compositions use the same `SnpReportVerifier` semantic contract.
`SnpEmuAzure` composes the AAS Firmware ABI 1.59 base-report verifier with the
fixture-only supplement verifier. `SnpHardware` uses the production AAS path
and fails explicitly at the conflicting Version 6 physical-layout boundary
until AMD clarification. Remove TAV from the final SNP feature graph, code
selection, trace markers, dependency graph, tests, and packaging manifests.

The AAS adapter is local verification code. It must not perform network calls
or rely on a remote attestation service during peer-MA authorization.

### T4.16.5 Separate Linux hardware from fixture providers

Rename or re-home the current `/dev/sev-guest`, `OpenOptions`, and Linux
`ioctl` implementation as the production Linux evidence provider selected by
`snp-linux-hardware`. It is a `std` provider and must not be gated by the
absence of `snp-emu`.

Fixture report and collateral providers compile only under `snp-fixture`.
Firmware-state, installation, and rebind emulators compile only under their
explicit emulator features.

### T4.16.6 Reject mixed or incomplete compositions

Add compile-time guards equivalent to:

```rust
#[cfg(all(feature = "SnpHardware", feature = "SnpEmuAzure"))]
compile_error!("SNP production and emulator compositions are mutually exclusive");

#[cfg(all(feature = "SnpHardware", feature = "snp-fixture"))]
compile_error!("Production SNP builds cannot include fixture evidence");

#[cfg(all(feature = "SnpHardware", feature = "snp-state-emulator"))]
compile_error!("Production SNP builds cannot include emulated firmware state");

#[cfg(all(feature = "SnpHardware", feature = "snp-tcp-transport"))]
compile_error!("Production SNP builds cannot include emulator TCP transport");

#[cfg(all(feature = "snp-aas-verify", not(feature = "std")))]
compile_error!("The selected AAS verifier requires std");
```

Apply equivalent guards to synthetic roots, mock installation, mock rebind,
test randomness, test attestation bypasses, and incompatible TDX providers.

### T4.16.7 Select providers once

Select concrete provider families only at composition roots. Shared SNP logic
receives typed provider sets and cannot probe features or fall back at
runtime. A missing production provider is a compile-time error where possible,
otherwise an explicit startup or operation failure.

### T4.16 implementation and bounded validation

Shared PAL SNP contracts now use `snp-core`, independently of fixture selection.
MigTD uses explicit `std`; its legacy TDX capabilities are optional and excluded
from the production SNP graph. `main` retains legacy attestation selection;
the image-hash tool explicitly selects its TDX capability without enabling
attestation. Existing TDX/AzCVMEmu execution remains on that legacy path.
`SnpUnderhillRuntime` supplies shared Linux configuration/PID1 support without
emulator inheritance. The compatibility alias `SnpUnderhill` is runtime-only;
`SnpEmuAzure` explicitly adds the emulator.

Hardware and fixture modules now have independent capability gates. Closed
production and fixture-root constructors are selected once at MigTD roots.
Both compositions select existing `SystemRandomSource`; scripted randomness
remains unit-test-only. Production rejects fixture/state/TCP/mock/bypass/TDX
mixing. TAV and its crypto patch are absent from the workspace dependency and
registered-test graphs; historical patch files/evidence remain unchanged.
Frozen certificate-vector tests use the repository X.509 parser and ring.

The local AAS capability is the only selected SNP verification backend.
Its legacy captured-fixture verifier rejects live Version 6 requests; the
common Version 6 claims/layout adapter remains explicitly unavailable until
the existing AAS1A-M gate. The reachable legacy `/dev/sev-guest` implementation
is compiled independently, not newly qualified or activated for Version 6.
The production binary exits 2 with an explicit unavailable-services diagnostic,
without acquiring evidence, generating secrets or falling back to fixtures.

Validation PASS: 40 persistent positive/negative/dependency checks; PAL
default34/6, random35/6, core415/26, fixture415/26, emulator422/26 and
production415/27 unit/doctests; SNP emulator7 and serial MigTD SNP library67;
registered libraries, unchanged independent corpora, scoped strict checks,
release-bypass rejection and rebuilt musl legacy Stage A/B. Full local CI
command parity passes with Rust1.88: format/check/CI-Clippy, deny stages,
32 firmware builds, six tools and all 14 EMU scenarios, with 28 zero process
exits. Consumer-feature, binary-test reachability and AzCVMEmu import regressions
were repaired and revalidated; the EMU stage was resumed after its repair.
Scoped SNP/strict checks use Rust1.90. No advisory waiver or lint suppression.

Evidence: `target/t4.16-feature-selection/20261105T151207Z/`.
Eight generated policy/chain files were archived and restored byte-for-byte.
The 37-step order, historical prefixes, corpora and submodule revisions remain
unchanged. No effectful V2 caller activation, operational production
AAS/layout/transport/state/effect providers, hardware or RNG qualification,
readiness-row qualification or GitHub-hosted CI is claimed. T4.17 and T4.18
remain downstream; this implementation is not completion acceptance.

## T4.17 Interface and provider tests

Status: DONE - ACCEPTED within the documented bounded scope and exclusions.

Implementation authorized at `2026-11-05T16:22:33.174Z`; bounded validation
recorded at `2026-11-05T17:21:34.964Z`.
Completion identifier: `T4.17-InterfaceConformance-2026-11-05`.
Explicit bounded acceptance recorded at `2026-11-05T17:27:38.397Z`.
No additional conditions were specified; existing exclusions remain in force.

This is the architectural and interface-conformance gate, not acceptance of an
implemented AAS Version 6 verifier. Codec, supplement-signature, provider
selection, typed-claim policy, and fail-closed boundary tests run here.
Explicit test doubles may exercise interfaces but may not produce accepted
attestation or migration-qualification results. End-to-end AAS base-report
authentication and composed-claims conformance are completed under AAS1A-M
after Task 6 and AAS1A, then the relevant T4.17-T4.19 tests are rerun.

The bounded implementation reuses the accepted corpus and existing suites,
adds exhaustive claim/supplement consistency and zero-effect rejection tests,
and expands the two selected sets' unavailable-service/verifier checks.
The persistent feature checker now runs 55 checks, including real external
consumer positive controls and private/sealed/fixture API rejection checks.
It exposed and repaired a missing explicit `zeroize/alloc` declaration in
standalone PAL builds; package resolution and the lockfile are unchanged.
The common-claims policy addition is a provider-independent projection into
the unchanged 280-byte identity, not authentication or policy admission.
Legacy fixture appraisal and effectful runtime callers are not replaced here.

PAL unit/doctest matrices, serial MigTD SNP tests, the standalone SNP emulator,
registered libraries, independent references, strict checks and local CI
command parity pass: 32 firmware builds, six tools and 14 EMU scenarios.
Rebuilt musl Stage A/B pass with the frozen historical host controller.
The eight generated policy/chain fixtures were restored byte-for-byte.
Evidence and the executed requirement register are preserved under
`target/t4.17-interface-conformance/20261105T162233Z/`.
See [technical-note section 26](snp/approval-decision-technical-note.md#26-t417-interface-and-provider-conformance)
for test mappings and downstream obligations. Failed development attempts
remain recorded. No production/AAS/layout/RNG/hardware or hosted-CI
qualification is claimed. Bounded acceptance is recorded in
[technical-note section 27](snp/approval-decision-technical-note.md#27-t417-bounded-completion-acceptance)
and the central log; see the current T4.18 disposition below.

Post-acceptance maintenance at `2026-11-05T18:01:29.016Z` separately validated
SDK/azure-tpm 0.2.0 at `8774be30f452060c56372d34ccbe34c3d3f3c577`,
preserving the native backend and all other lockfile package records.
The [maintenance record](snp/approval-decision-technical-note.md#28-sdk-8774be3-update-and-regression)
records the full rerun, serial library-test invocation and existing exclusions.
Accepted T4.17 artifacts are immutable; this does not start T4.18.

Cover:

```text
provider conformance and selection
hardware fail-closed behavior
no fixture fallback
shared SnpReportVerifier contract in SnpEmuAzure and SnpHardware
SnpEmulatorV1 codecs, supplement signature, and provenance contracts
report/supplement digest and ETCB equality using controlled authenticated inputs
typed policy consumes common claims without emulator branches
hardware UnsupportedVersion6Layout and ConflictingAbiLayout failures
production build rejects fixture roots and fixture reports
production build rejects state emulation and TCP emulator transport
production build rejects mock installation, mock rebind, and test randomness
production build contains no TAV implementation or dependency
SnpUnderhillRuntime does not imply SnpEmuAzure
SnpHardwareProvider is reachable only from the production composition
typed errors
host/peer/firmware-plane separation
tenant binding classification
VeniceV1 installer validation
handoff-secret non-exposure
binding manager state ordering
secret cleanup
```

Required compile matrix:

```text
TDX hardware/no_std                         PASS
AzCVMEmu/std                                PASS
SnpEmuAzure/std                             PASS
SnpHardware/std                             PASS; unavailable Phase 5 providers
                                             fail closed at startup/operation
SnpHardware + SnpEmuAzure                   COMPILE FAIL
SnpHardware + snp-fixture                   COMPILE FAIL
SnpHardware + snp-state-emulator            COMPILE FAIL
SnpHardware + snp-tcp-transport             COMPILE FAIL
SnpHardware + test attestation bypass       COMPILE FAIL
```

Before AAS1A-M, `SnpEmuAzure` must compile, but an unavailable AAS Version 6
adapter returns an explicit unavailable-provider failure and no authenticated
claims. This temporary non-operational boundary is recorded in the
consumer-readiness matrix; it is not an alternate verifier or a fixture
fallback. Full verifier execution is not a prerequisite of T4.20.

## T4.18 Refactor current callers

Status: ACCEPTED - bounded validation recorded at
`2026-11-05T18:58:22.061Z`; the user accepted completion within its documented
bounded scope and exclusions at `2026-11-05T19:04:48.267Z`.

Authorized at `2026-11-05T18:20:16.530Z`. Completion identifier:
`T4.18-CallerIntegration-2026-11-05`.

The emulator entry point now owns one selected provider root, explicitly shared
with WFR and both SPDM roles. MA evidence and collateral use separate frozen
seams; only the named legacy bridge assembles the unchanged captured blob.
Legacy SDK verification and key-only mock installation are selected at that
root, not constructed in shared SPDM/session code and not adapted into common
V6 claims or typed V2 installation. Missing evidence/collateral fails without
fixture fallback. Malformed/truncated/trailing legacy blobs are rejected and
GetTDReport acknowledgement failures remain terminal with their transport error.

The closed hardware set explicitly selects the existing Linux MA acquisition
adapter, without qualifying its hardware ABI or report freshness. Its collateral,
common V6 verifier, transports, authorities, persistence and effects remain
unavailable. Production bootstrap consumes the selected host-control seam and
exits 2 on its explicit unavailable error, before any report ioctl or operation.
The common SNP contracts retain provider-independent typed services, owned
randomness and sealed selection; no TAV or fixture verification fallback exists.

All 27 final local gates pass: 57 feature/dependency/external-consumer checks,
PAL/SNP/registered-library suites, independent references, workspace/scoped
strict checks, 32 firmware builds, six tools, 14 EMU scenarios and rebuilt musl
Stage A/B. The first binary-only feature failure was repaired by separating the
SNP entry module from the unused TDX dispatcher. Its evidence is retained.
An extra non-CI `cargo fmt --all -- --check` reports unchanged vendored formatting;
the exact repository/CI formatter passes. Existing SNP legacy lint warnings and
the serial registered-test limitation are not claimed fixed.

Evidence: `target/t4.18-caller-integration/20261105T182016Z/`.
See [technical-note section 29](snp/approval-decision-technical-note.md#29-t418-caller-integration)
for the caller register, tests and exclusions. Earlier acceptance/evidence,
the SDK pin/lockfile, both frozen corpora and the 37-step order are preserved.
The eight regenerated Azure fixtures were restored byte-for-byte.
Bounded acceptance is recorded in
[technical-note section 30](snp/approval-decision-technical-note.md#30-t418-bounded-completion-acceptance)
and the central log. Existing exclusions and limitations remain unchanged.
No full Task 3 exchange, AAS/layout/production qualification or broader
acceptance is implied; the separately authorized T4.19 disposition is below.
No commit or push.

Route fixture evidence, real Linux evidence, AAS verification, collateral,
migration installation, replay persistence, randomness, transport, and
rebind behavior through the frozen provider sets.

For AAS, route callers to the frozen verifier boundary now; implement and
accept the Version 6 adapter in AAS1A-M. Until then, report its unavailability
explicitly. Do not retain TAV as a temporary runtime fallback.

Refactor at least:

```text
src/pal/src/lib.rs
src/pal/src/snp/mod.rs
src/pal/src/snp/qvl/*
src/pal/src/snp/fixture/*
src/pal/src/snp/hardware/*
src/migtd/Cargo.toml
src/pal/Cargo.toml
src/migtd/src/lib.rs
src/migtd/src/bin/migtd/main.rs
src/migtd/src/bin/migtd/snpemu.rs or its renamed runtime modules
composition roots and bundle builders
```

Remove backend checks from shared protocol logic. Preserve TDX and AzCVMEmu
behavior.

Do not activate the full Task 3 runtime exchange in this step.

## T4.19 Task 4 regression

Status: ACCEPTED - bounded validation at `2026-11-05T20:12:53.102Z`;
the user accepted completion within its documented bounded scope and exclusions
at `2026-11-05T23:49:26.373Z`.

Authorized at `2026-11-05T19:45:40.638Z`. Completion identifier:
`T4.19-Task4Regression-2026-11-05`.

All 26 final local command gates pass: PAL and available verifier/interface
suites, serial registered libraries, 57 feature/dependency/external-consumer
checks, independent references, workspace/scoped strict checks, 32 firmware
builds, six tools, 14 EMU scenarios (28 zero process exits), and rebuilt musl
Stage A/B. Legacy SNP Clippy passes with inherited warnings, not a warning-free
claim. Preparation remained valid; no dependency/submodule change was needed.

New composition regression covers both inter-node roles and both local-handoff
directions for both provider-set compositions, requiring explicit unavailable
peer-provider errors. It does not execute or qualify a local two-process
handoff. Seven inventory-tool controls exercise fixture/synthetic-root/symbol
and dependency rejection. Both explicit no-default release builds produce
separate provisional ELF inventories with target, environment, dependencies,
source and image hashes. Production contains none of the named captured assets,
synthetic roots or forbidden symbols; its selected host boundary refuses startup
with exit 2. Source-selected Linux acquisition is not exercised or qualified.

Evidence: `target/t4.19-task4-regression/20261105T194540Z/validation-manifest.json`.
Separate inventories: `image-inventories/SnpEmuAzure/manifest.json` and
`image-inventories/SnpHardware/manifest.json` within that evidence directory.
These are not P2.2 bundles or a versioned deployment schema.
See [technical-note section 31](snp/approval-decision-technical-note.md#31-t419-task-4-regression)
for the coverage, retained failed attempts and deferred executable verifier
obligations. Common AAS V6/layout and actual composed-claims tests remain
deferred to AAS1A-M, not reported passed.

Eight generated fixtures were restored byte-for-byte; all 13 Azure configuration
files, prior accepted evidence, lockfile, both frozen corpora, HEAD/submodules,
37-step order and historical log/note prefixes are preserved.
No full Task 3 activation, production/readiness-row or hardware/RNG/deployment/
hosted-CI qualification is implied. Bounded acceptance is recorded in
[technical-note section 32](snp/approval-decision-technical-note.md#32-t419-bounded-completion-acceptance)
and the central log. Existing exclusions and deferred obligations remain
unchanged. T4.20 is READY for separate authorization, NOT STARTED.
No broader acceptance, commit or push.

Validate:

```text
PAL and available verifier/interface tests
SnpEmuAzure compile, composition, and explicit unavailable-provider behavior
SnpHardware compile and composition
InterNodeTwoProcessMigration provider composition
LocalMaHandoffTwoProcess provider composition
TDX and AzCVMEmu preservation
feature selection
provider absence and fail-closed paths
Cargo feature and dependency inventory
production binary fixture/root/symbol scan
separate emulator and production bundle manifests
```

Bundle manifests here are provisional image-content inventories, not
qualified P2.2 bundles. P2.2 owns the versioned schema and bundle tooling.
Record deferred executable verifier tests for AAS1A-M rather than reporting
them as passed.

Build the production composition explicitly:

```text
cargo build --release --no-default-features --features SnpHardware
```

The exact target and environment are recorded by the production bundle
builder. The build must not depend on default features to exclude test or
emulator code.

## T4.20 Task 4 freeze

Status: DONE - ACCEPTED AND FROZEN within the documented bounded scope and
exclusions at `2026-11-06T00:32:02.025Z`; conditions: None.
Authorized at `2026-11-05T23:50:40.311Z`.
Freeze identifier: `T4.20-Task4Freeze-2026-11-05`.
The [audit/freeze record](snp/task4/task4-freeze.md),
[consumer-readiness matrix](snp/task4/consumer-readiness-matrix.md),
[feature matrix](snp/task4/feature-selection-diagram.md) and
[source/evidence inventory](snp/task4/freeze-inventory.json) record the exact
bounded disposition and separate emulator/production ELF manifests.
All four Task4 diagrams now distinguish actual selected ownership and
unavailable services from downstream runtime requirements. Active stale V1
handoff wording is reconciled to the accepted direct-random V2 amendment;
historical codecs, evidence, log/note prefixes and the37-step order are preserved.

The user selected a documentation-only freeze commit; the audited implementation
remains uncommitted and is identified by470 non-document input hashes plus
submodule revisions, not by a fabricated implementation commit. The commit alone
cannot reproduce the audited source tree. Fresh T4.20 checks verify documentation,
input/evidence correspondence and commit scope; T4.19 runtime/CI results are
reused evidence, not rerun tests. See technical-note section33 and the central log.
T4.19 acceptance/exclusions remain unchanged. Explicit T4.20 acceptance is
recorded in technical-note section34 and the central log. The documentation-only
freeze commit remains `ab91f5f9194152cd4e5440ec050c447de5de8f0d`; no new commit
or push is made for this acceptance. Historical validation/inventory/commit
receipts retain their original acceptance-pending snapshot status.
No production qualification, Task12 reactivation or P2.1/P2.2 start is implied.

Audit:

- the contracts required by AAS1A, Tasks 5-14, and Phase 4 consumers are frozen
  and their planned integrations are recorded in the consumer-readiness matrix;
- P0.9A1, P0.9B1, P0.9C1, P0.9D, and P0.9E are frozen and no emulator
  consumer invents policy semantics;
- accepted P0.9A2-P0.9C2/D ordered contracts are separate from fixed fields;
  their production-provider/runtime qualification remains explicitly gated,
  not supplied by the fixed emulator or contract-only fixture tests;
- no direct platform call is required by shared SNP logic;
- no TDX field remains in a shared SNP interface;
- no host-control interface carries secrets;
- the selected matrix is TDX hardware/no_std, AzCVMEmu/std,
  SnpEmuAzure/std, and SnpHardware/std;
- both SNP compositions select the AAS verifier boundary, with executable
  Version 6 integration explicitly gated on AAS1A-M, and neither uses TAV;
- the common `SnpEmuAzure` verifier contract permits only the frozen signed
  supplement profile and fixture provenance; the selected adapter is unavailable
  until AAS1A-M, and the isolated captured-v5 legacy bridge is not that adapter;
- the common `SnpHardware` verifier contract forbids fixture supplement/roots
  and requires the named Version 6 layout failure at AAS1A-M; current selection
  returns `ProviderUnavailable` without claims and startup refuses at host
  control before report acquisition, not an exercised layout qualification;
- `SnpUnderhillRuntime` does not imply fixtures or emulator behavior;
- the production dependency tree and binary contain no fixtures, synthetic
  roots, state emulator, TCP emulator, mock firmware operations, or test
  randomness;
- missing production providers fail closed without fixture fallback;
- production blockers are explicit;
- qualification claims are correctly scoped.

Deliver:

```text
Task 4 audit
commit
freeze record
updated architecture diagrams
consumer-readiness matrix
Cargo feature matrix
production dependency inventory
emulator and production image-content manifests
```

## Phase 1 gate

Status: SATISFIED within the documented interface-level scope following explicit
bounded T4.20 acceptance at `2026-11-06T00:32:02.025Z`. All exclusions remain.

Task 4 Steps 9-20 are complete, frozen, and consumable by all later runtime
tasks at the interface level. This gate does not claim executable AAS Version 6
conformance or migration qualification. AAS1A-M must close the recorded
verifier implementation and executable-test obligations before Task 7.

---

# Phase 2 - Terminology and Composition Cleanup

## P2.1 Replace Stage A/B terminology

Status: DONE - ACCEPTED AND FROZEN within the documented bounded scope and
exclusions at `2026-11-06T00:47:34.984Z`; conditions: None.
Authorized at `2026-11-06T00:34:35.144Z` following bounded T4.20 acceptance.
Naming-only commit:
`1dbb3e6bf8e9f3666d9a5ead2dbb6e66b6d15481`.
User-selected scope excludes prerequisite implementation and acceptance changes;
those remain intact and uncommitted. The commit alone does not reproduce the
accepted working implementation.

Use:

```text
Stage A -> SingleProcessMigration
Stage B -> InterNodeTwoProcessMigration
local old/new MA test -> LocalMaHandoffTwoProcess
```

Rename current code, scripts, CLI text, tests, and active documentation.
Preserve historical logs, commits, hashes, and frozen execution records.

Commit this behavior-neutral change separately.

Implemented: canonical runner paths, environment names, evidence-directory
defaults and diagnostics for the first two scenarios, with old paths/env names
retained only as explicit compatibility aliases. Active usage is documented in
[the scenario guide](snp-migration-scenarios.md). `LocalMaHandoffTwoProcess`
remains the reserved Phase4 name; no local runtime was created.
Rust/CLI symbols and CI contained no stage-letter scenario names to rename;
existing process arguments/protocol/manifest fields are unchanged. Historical
summaries, frozen addenda/manifests, note/log prefixes and exact37-step order
are preserved.

Validation: Bash syntax/ShellCheck on all four entry points; eight naming/alias
tests on both the working tree and the independently reconstructed rename-only
index; exact naming-transform equivalence; four sequential canonical/alias
regressions on the same frozen accepted ELF/controller,12 process exits zero.
No scenario listeners remain. Rust and full-CI builds were not rerun for this
harness/documentation-only change. Earlier CI evidence remains inherited, not
relabeled as fresh execution. See technical-note section35 and the central log.
Explicit bounded P2.1 acceptance is recorded in technical-note section36 and
the central log. Original validation/commit receipts retain their historical
acceptance-pending snapshot status. No common V6/V2 activation,local-handoff/
production qualification,P2.2 start,new commit or push is implied.

## P2.2 Make MigTD an atomic artifact producer

Status: DONE - ACCEPTED AND FROZEN within its documented scope and exclusions at
`2026-11-06T15:39:00.609Z`; conditions: None. Authorized at
`2026-11-06T00:49:32.416Z`, following bounded P2.1 acceptance. The user subsequently
authorized a separate accepted-prerequisite commit
`5d6a4ad302d2c5b17a8a80d11286657559ad126d` to enable fresh-HEAD validation.
The separately reviewable external bundle-consumer conversion is committed as
`700e22aae1bcf09aff7d591cffc5ea6a39b4169c`. After actual old/new VM runs, the user
approved the documented stale-assertion deviation and moving nested source
intact to the session archive. Tooling commit
`8cd88edcf4eafa7ed8eb9ede7fec7777d61c51ce` and frozen-input correction
`bb1a2fccb2e42062378d4ef454718b6a1b5eadd5` now reproduce both bundles from a
fresh checkout with remotely initialized declared submodules. All24 targeted
unit and19 real-bundle tests pass there; the fresh emulator bundle also
completes the legacy compatibility workflow on both actual VMs. The final
consumer commit is `efb0d48614d5a386a263058a9a8b1e3788a01ac3`.
See technical-note section37 and
`target/p2.2-artifact-production/20261106T004932Z/validation.json`.
Explicit bounded P2.2 acceptance and Phase2 closure are recorded in
[technical-note section38](snp/approval-decision-technical-note.md#38-p22-bounded-acceptance-and-phase2-closure)
and the central execution log. Harness relocation commit:
`4a10dafd9125457616d09589f618cef1d3ff9e68`; MigTD relocation commit:
`af17a246a2ec6117e0872b63e7d750e7dbe71165`. Task5 has not started and requires
separate authorization; no push is authorized.
The bounded T4.20 prerequisite remains accepted.

Implementation and usage: [SNP bundle contract](snp-bundles.md). Current bundles
are build-validated/migration-unqualified; common V6/V2 activation and Task14
qualification remain excluded.

MigTD must build, describe, and validate its own emulator and production
artifacts without requiring a `snp-ma-vm-harness` source checkout, nested MigTD tree,
or source-relative path outside the repository.

### Ownership boundary

MigTD owns:

```text
SnpEmuAzure and SnpHardware Cargo compositions
emulator and production MA builds
bundle construction
component, provider, feature-matrix, and image-content tests
bundle-manifest schema and validation
MA, initramfs, dependency, SBOM, and checksum records
host_wfr_test or its approved replacement
expected verifier and provider markers
```

The VM-launch harness owns:

```text
QEMU/OVMF invocation
VM topology and lifecycle
host networking and process orchestration
bundle consumption
log and result collection
platform-specific emulator configuration
```

The harness does not own or build MigTD source, select the verifier, infer
fixture versus production mode, or contain a nested `deps/MigTD` checkout.

### Versioned bundle contract

Define and validate:

```text
schemas/snp-ma-bundle-manifest-v1.json
```

Required manifest members:

```text
schema version
composition: SnpEmuAzure or SnpHardware
qualification classification
MigTD repository and commit
AAS repository and commit
Cargo features
Cargo.lock hash
Rust toolchain, target, linker, and build profile
static versus dynamic linking mode
MA ELF and initramfs paths and hashes
kernel, root filesystem, OVMF, and QEMU identities and hashes where applicable
Rust and native dependency inventory
SBOM path and hash
verifier identity
evidence, collateral, transport, randomness, installation, rebind,
    persistence, and firmware-state provider identities
fixture versus production classification for each provider
expected evidence and operation markers
bundle creation command and timestamp
```

External kernel, OVMF, QEMU, and root-filesystem inputs do not need to be
copied into the MigTD source tree. Their qualified versions and hashes are
explicit bundle-builder inputs and manifest members.

### MigTD repository changes

Create or freeze equivalent repository-owned tooling:

```text
tools/snp/build-emulator-bundle.sh
tools/snp/build-production-bundle.sh
tools/snp/validate-bundle.sh
tools/snp/inspect-production-image.sh
tests/snp/feature-matrix/
tests/snp/integration/
schemas/snp-ma-bundle-manifest-v1.json
```

The emulator builder uses only `SnpEmuAzure`. The production builder uses only
`SnpHardware`. Both use `--no-default-features` and explicit features.

The production builder enforces all T4.15-T4.20 image-isolation rules. The
emulator builder labels fixtures and emulated providers explicitly and cannot
produce a production-classified manifest.

### `snp-ma-vm-harness` ownership and transition

Use the independent `mvasantarao/snp-ma-vm-harness` repository as the bundle-only
VM consumer. Its local checkout is `/home/murthy/repos/snp-ma-vm-harness`;
platform source/build trees are ignored local dependencies under
`.local/platform/`, not nested MigTD sources or vendored harness source.
The former `nested_openvmm/vm_enclave` name remains only in historical evidence.

```text
run-emulator-e2e.sh --bundle <bundle-directory>
```

Required changes:

1. Remove `snp-ma-vm-harness/deps/MigTD` and every nested or copied MigTD source tree.
2. Remove MigTD compilation from `snp-ma-vm-harness`.
3. Remove hard-coded TAV/AAS, feature, fixture, evidence-marker, and source-path
   selection.
4. Read composition, verifier, provider identities, hashes, and expected
   markers from the validated manifest.
5. Reject unknown schema versions, missing files, hash mismatches, unsupported
   compositions, and contradictory fixture/production classifications.
6. Preserve only VM lifecycle, topology, QEMU/OVMF configuration, host
   orchestration, log collection, and result reporting.

The harness remains the separately versioned VM/platform-test repository.
MigTD must not depend on its local checkout or source/build layout to build
or validate a bundle.

### Migration and parity sequence

1. Inventory every active `snp-ma-vm-harness` file and assign MigTD-build ownership
   or VM-harness ownership.
2. Freeze the manifest schema and positive/negative validation vectors.
3. Move or reimplement MigTD build, bundle, feature, dependency, checksum, and
   image-inspection logic inside MigTD while preserving history where
   practical.
4. Build a build-validated, migration-unqualified `SnpEmuAzure` bundle using
   only MigTD-owned tooling; record any unavailable providers explicitly.
5. Run both the old and manifest-driven harnesses against the same bundle.
6. Compare build, launch, bundle-validation, result collection, explicit
   unavailable-provider outcomes, and artifact hashes. Preserve the accepted
   baseline and parity record. Do not require an unimplemented migration
   protocol to succeed or treat matching failures as migration qualification.
7. Switch CI and active emulator instructions to the manifest-driven harness.
8. Remove nested MigTD source and stale verifier/backend assumptions from
   `snp-ma-vm-harness`.
9. Verify a fresh MigTD checkout can build and validate both bundle types using
   only declared toolchain and external artifact inputs.

Acceptance:

- MigTD has no source, script, or documentation dependency on a
  `snp-ma-vm-harness` checkout path;
- `snp-ma-vm-harness` has no nested MigTD source or authority over Cargo features,
  verifier selection, or provider composition;
- emulator and production bundles validate against the same versioned schema;
- corrupted files, hashes, manifests, provider classifications, and schema
  versions fail closed;
- old and new harnesses have equivalent approved artifact-consumption, launch,
  failure-reporting, and result-collection outcomes before the old workflow is
  retired; full migration qualification remains a Task 14 obligation;
- emulator and production outputs have separate roots, manifests, hashes, and
  qualification records;
- a fresh MigTD checkout reproduces the declared builds without an undeclared
  local workspace dependency.

The manifest records only the qualification actually achieved. Successful
bundle construction or harness parity does not grant
`Migration-emulator-verified` status. Task 14 qualifies the completed protocol
through the manifest-driven harness and retains the Phase 2 parity record.

Commit the schema/tooling move and the `snp-ma-vm-harness` consumer conversion as
separately reviewable changes.

## Phase 2 gate

Task 5 cannot begin until P2.1 and P2.2 are accepted and committed.

Status: CLOSED within the documented Phase2 scope. P2.1 was accepted at
`2026-11-06T00:47:34.984Z` and committed as
`1dbb3e6bf8e9f3666d9a5ead2dbb6e66b6d15481`. P2.2 was explicitly accepted at
`2026-11-06T15:39:00.609Z`; its core implementation, evidence and remaining
relocation changes are committed. This documentation commit persists the
acceptance/closure record. Task5 remains NOT STARTED pending separate
authorization. No production qualification, PA advancement or push is implied.

---

# Phase 3 - Complete the Inter-node Migration Emulator

## Task 5 - Remove active inherited TDX behavior from SNP

Status: READY after Phase 2

Replacement matrix:

| Current TDX-shaped item | SNP replacement |
|---|---|
| `tdcall_servtd_rd(MIG_ENC_KEY)` | source-owned final random32 `MigrationKeyV2` after admitted V2 context; no KDF |
| `tdcall_servtd_wr(MIG_DEC_KEY)` | typed `SnpMigrationKeyInstaller` after protected V2 acceptance and role-specific gates |
| `GetTdReport`/TDX quote path | `MaEvidenceProvider` |
| `MigtdMigrationInformation` | `PrepareMigrationRequestV1` and typed SNP operation context |
| target TD UUID | managed tenant and session handles |
| `TDINFO_STRUCT` policy input | typed SNP evidence and policy context |
| `MigrationSessionKey` | zeroizing SNP MSK state |
| directional key records | V2 protected key delivery/acceptance and correlated firmware completion/ack |

Acceptance:

- no active SNP path invokes TDCALL;
- no shared SNP request contains a TDX field;
- unsupported hardware operations fail explicitly;
- TDX and AzCVMEmu behavior remains intact.

## Task 6 - Build signed Version 6 evidence fixtures

Status: READY after Task 5, P0.9A1, P0.9C1, and P0.9D

Produce:

```text
test ARK -> ASK -> VCEK hierarchy
optional VLEK hierarchy
signed 1,184-byte Version 6 MA and tenant reports
configurable 64-byte REPORT_DATA for guest-requested MA reports
exact zero[64] REPORT_DATA and VMPL 0xffffffff for host-requested tenant reports
REPORT_ID and REPORT_ID_MA
all TCB fields
all ETCB fields
complete mitigation vectors
VeniceV1 MIGRATION_DATA and valid bit
positive and malformed scenarios
deterministic manifests and hashes
canonical MaPolicyIdentityInputV1 fixtures
deterministic MA_POLICY_IDENTITY_DIGEST values
signed fixture FixedReleaseAllowlistV1
fixture authorization root and signer chain
exact 220-byte SnpEmulatorSupplementV1
fixture-VCEK P-384 supplement signature
SnpEmulatorV1 evidence bundle containing the signed base report, supplement,
signature, and fixture collateral
```

The base report follows the Firmware ABI 1.59 Version 6 layout and carries
ETCB. It does not set `MIGRATION_DATA_VALID` or place ARG migration data over
the overlapping ETCB region. The signed supplement carries the migration
fields and duplicates ETCB; fixture verification requires byte equality.

Mandatory scenarios:

```text
GuestProvidedReportData
HostRequestedZeroReportData
nonzero ETCB reserved bits
unknown history profile
history-minimum increase attempt
ARG policy below floor
MA identity or policy-digest allowlist mismatch
changed measurement, guest SVN, family/image identity, key digests, HOST_DATA,
or SNP guest policy
unknown authorization root or wrong signer purpose
invalid allowlist signature
expired allowlist
allowlist status other than Approved
fixture root supplied to a production provider
report digest changed after supplement signing
supplement signature changed
supplement reserved bits nonzero
supplement ETCB differs from the signed report
invalid migration-data valid-bit and byte combination
fixture evidence submitted to SnpHardware
```

Synthetic roots remain fixture-only.

Ordered-release custom collateral/SVN/history/lifecycle unit fixtures already
exist under accepted P0.9A2-P0.9C2. Full report/chain and deployment lifecycle
fixtures remain Task 6/Phase 5 qualification work as applicable; those unit
fixtures do not qualify real certificate rotation or production history.

## AAS1A - Extend AAS for Version 6 local SNP report verification

Status: READY for the `SnpEmulatorV1` base-report scope after Task 6 and
P0.12A; production overlapping-field extraction is BLOCKED on AMD
clarification

Target repository:

```text
Azure/azure-guest-attestation-sdk
local checkout: /home/murthy/repos/azure-guest-attestation-sdk
baseline inspected by this plan: 046690a
```

Extend single-report verification:

```text
Firmware ABI 1.59 Version 6 base-report parsing
exact 1,184-byte report-length validation
exact 672-byte signed-body verification
strict 512-byte signature-structure validation
reserved-field validation for the selected base-report profile
guest-requested MA reports with VMPL 0..3
host-requested tenant reports with VMPL 0xffffffff and REPORT_DATA zero[64]
production VCEK, VLEK, and chip-secret VCEK modes selected by H5.2
certificate-chain, signature, report-to-key, product, TCB, and hardware binding
```

The Azure Guest Attestation SDK does not parse or trust
`SnpEmulatorSupplementV1`. The MigTD `SnpEmuAzure` adapter verifies that
test-only record after AAS authenticates the base report. This keeps fixture
extensions out of the production AAS parser.

The implementation is `std`-based and is consumed by both the emulator and
production Linux/Underhill SNP MA images. No `no_std` AAS core is required by
the selected matrix.

For the emulator base-report scope, return authenticated claims available from
the Firmware ABI 1.59 layout:

```text
REPORT_DATA
MEASUREMENT and signed identity fields
REPORT_ID and REPORT_ID_MA
reported, current, committed, and launch TCB
launch and current mitigation vectors
current, launch, and committed ETCB
signing-key kind and collateral status
```

Do not synthesize `MIGRATION_DATA_VALID` or `MIGRATION_DATA`. The MigTD
emulator adapter obtains those only from the authenticated supplement. For a
raw production Version 6 report requiring both ETCB and migration data, return
`UnsupportedVersion6Layout` or `ConflictingAbiLayout` until AMD resolves the
published overlap.

Required APIs preserve a clean separation:

```text
single-report cryptographic verification
authenticated Version 6 claim extraction
caller-supplied report and collateral bytes
```

Tests:

- real or independently generated Version 6 vectors;
- guest- and host-requested reports;
- every supported signing-key mode;
- every authenticated migration claim;
- no migration-data claim returned by the base-report parser;
- malformed layouts and reserved fields;
- wrong certificate/report binding;
- wrong product, TCB, key type, or signing-key mode;
- guest-requested and host-requested VMPL behavior;
- host-requested nonzero `REPORT_DATA` rejection where required by policy;
- stable typed errors and authenticated claims.

Completion requires an accepted commit in `Azure/azure-guest-attestation-sdk`
for the base-report scope and an updated MigTD dependency revision. A local-only
patch or unpinned branch does not complete the emulator portion of AAS1A.
Production overlapping-field extraction remains incomplete until the AMD
clarification is implemented and separately qualified.

## AAS1A-M - Integrate the accepted AAS Version 6 verifier into MigTD

Mandatory P0.6 closure: authenticate the entire composite evidence before
promoting its canonical digest and REPORT_ID_MA into a verified receipt.
Qualify both current V2 purpose-7 roles, exact MA identities, full REPORT_DATA,
and the 325-byte authorization context bound to both purpose-6 session proofs.
No commitment fields or historical 421-byte V1 context enter active V2. Reconcile
complete MA-profile transport at P0.11/T4.12 before activation.

Mandatory P0.5 closure: route identity promotion through the final common
authenticated-claims adapter and bind the complete base-report/supplement
evidence into request/session/retry correlation. A matching base-report
reference alone authenticates no supplement field or handle-to-GCTX mapping.

Mandatory P0.4 closure: verify family-aware Venice TCB/ETCB mapping and signed
launch/history inputs, including the authenticated validity flag and source
tenant-to-MA binding. The production physical-layout failure remains required;
codec test vectors do not substitute for signed-provider conformance.

Status: READY after AAS1A and T4.20

Implement the shared `SnpReportVerifier` adapter frozen by P0.12A and
P0.12A1:

```text
one common SnpReportVerifier trait
one AuthenticatedSnpClaims type
MigTD-owned request, collateral, claims, provenance, leaf, status, and errors
explicit fail-closed mapping from AAS-native outputs into MigTD-owned types
SnpEmuAzure adapter =
    AAS-authenticated Firmware ABI 1.59 base report
    + authenticated SnpEmulatorSupplementV1
    + fixture collateral
SnpHardware adapter =
    raw report plus production collateral
    + explicit layout-conflict failure until AMD clarification
no network call during peer-MA report verification
no alternate verifier or TAV fallback
no TDX/QVL call-site or policy refactor
```

Update the pinned AAS revision deliberately and record:

```text
AAS repository and accepted commit
Rust toolchain and target
OpenSSL/native dependency mode
Cargo.lock change
report/collateral input encoding
authenticated-claim schema
binary and initramfs hashes
```

The existing AAS adapter may convert DER to PEM internally only if the accepted
AAS API still requires PEM. Wire and provider contracts remain DER-based, and
the conversion must be deterministic, bounded, and tested.

Validate both compositions:

```text
SnpEmuAzure:
    signed Version 6 fixtures
    signed SnpEmulatorSupplementV1
    report-digest and ETCB equality checks
    fixture collateral and fixture roots
    AAS verification marker

SnpHardware:
    same SnpReportVerifier contract
    production collateral boundary
    rejects fixture profile and roots
    explicit UnsupportedVersion6Layout or ConflictingAbiLayout
```

Completion for the emulator milestone requires `SnpEmuAzure` to produce the
frozen common claims and `SnpHardware` to compile and fail closed at the named
physical-layout boundary. No TAV dependency may exist in either composition.
Rerun the executable verifier and provider-conformance cases deferred from
T4.17-T4.19 using Task 6 signed fixtures and the accepted AAS implementation.
Close every deferred verifier obligation in the consumer-readiness matrix
before Task 7; test-double results cannot satisfy this gate.
The architecture-level `TdxQuoteVerifier` and `AuthenticatedTeeEvidence`
definitions require no TDX implementation in this milestone; production TDX
adapter work begins only after reconciliation with Microsoft upstream.

## Task 7 - Activate MA evidence, policy, and collateral exchange

Status: READY after AAS1A-M, P0.9A1, P0.9B1, P0.9C1, and P0.9D

Consume the P0.9D fixed-profile verification/provider handoff. Its contract
acceptance is not activation: this task must wire providers and retain exact
policy/evidence/tenant correlation for Tasks 8/9.

Mandatory amended P0.7 closure: implement T4.14-PRE V2 session evidence and
qualify actual SPDM/policy/replay composition. There is no commitment provider
or pre-evidence secret generation. Model fixtures cannot satisfy runtime
admission; qualified randomness is required before Task10 generates the MSK.

Sequence:

1. receive `PrepareMigrationRequest` and establish provisional routing context;
2. resolve and cryptographically verify the host-pushed tenant report,
   requiring Version 6, `VMPL = 0xffffffff`, and exact `REPORT_DATA = zero[64]`;
3. extract the verified tenant `REPORT_ID` and canonical report digest; ensure
   both peers verify the same report through the frozen report/reference
   delivery contract, without treating this as migration authorization;
4. establish inter-node SPDM and obtain TH1;
5. exchange the signed `FixedReleaseAllowlistV1` identity and exact policy
   identity;
6. reconstruct the nonsecret V2 session binding from verified complete tenant
   evidence and actual TH1; do not generate a key at this stage;
7. build fresh purpose-`0x06`, role-specific MA `ReportDataContextV1`;
8. acquire MA evidence;
9. exchange MA evidence, exact AMD collateral, and the signed fixed-release
   allowlist;
10. verify software trust without `MSG_VERIFY_REPORT`;
11. reconstruct `MA_POLICY_IDENTITY_DIGEST`, validate the allowlist signature,
   root, purpose, validity, exact approved identity, report Version 6,
   TCB/ETCB, reserved bits, role, request, policy, collateral, freshness
   classification, and replay state;
12. enter `BothMaEvidenceVerified`; tenant-to-MA correlation and
    purpose-`0x07` authorization remain required under Task 8.

## Task 8 - Activate host-pushed tenant evidence and authorization

Status: READY after Task 7

Consume the P0.9D sealed MA approvals and report-ID/digest handoff; pair
admission does not replace this task's tenant binding or authorization result.

Mandatory P0.6 closure: select authenticated, atomically durable/anchored replay
storage and role-aware current firmware validation; no unavailable-provider or
memory fallback. Use the complete-evidence and325-byte V2 authorization digests,
reserve before advancement, require both purpose7 proofs, and publish no
accepted authorization result before current-state checks and durable commit.

Sequence:

1. consume the exact authenticated tenant report, verified `REPORT_ID`, and
   canonical digest established under Task 7; reject substitution of the
   report, reference, classification, or identity;
2. verify tenant `REPORT_ID_MA` against the authenticated source MA;
3. reconstruct the frozen tenant-authorization context binding the report
   digest, TH1, request, roles, verified tenant identity, and policy;
4. acquire fresh purpose-`0x07` MA evidence for each peer's role using that
   context's canonical domain-separated digest as `PURPOSE_BINDING_DIGEST`
   under P0.3 and P0.6/P0.8;
5. exchange and authenticate that evidence and its collateral, reconstruct the
   expected context independently, and verify all 64 `REPORT_DATA` bytes;
6. require equality with the tenant report, source-MA binding, and approved
   MA/Policy identities already verified for this operation;
7. verify durable bounded-replay state, firmware state, and idempotent-retry
   policy;
8. return `SnpAuthorizationResultV1` with the authorization-context digest only
   after both purpose-`0x07` evidence checks succeed.

Negative tests:

```text
tenant substitution
different operation
different role
different TH1
different policy
report digest replay
host-requested report with nonzero REPORT_DATA
guest-requested report substituted for the required Version 1 host report
replay-journal rollback or conflicting terminal state
zero-bound report falsely marked session-bound
missing, stale, wrong-purpose, or substituted purpose-0x07 MA evidence
provisional tenant identity used in session binding or MA evidence context
```

## Task 9 - Implement Microsoft policy and VeniceV1 history

Status: READY after Task 8, P0.9A1, P0.9B1, P0.9C1, and P0.9D

Use the P0.9D fixed-profile pair admission and freshness contract, including
trusted provider revalidation and separate tenant/history/replay checks.

Separate:

```text
AMD validation:
    structure, signature, encoding, firmware-defined state

Microsoft policy:
    absolute floors
    profile compatibility
    no rollback
    historical minima
    mitigation-vector continuity
    tenant-to-MA binding
    exact FixedReleaseV1 MA/Policy identity
    signed allowlist trust, purpose, validity, and approval status
    replay and freshness classification
```

Implement the exact P0.4 codec and formulas.
Use `migration_data::MigrationDataV1` and its checked logical-input transitions,
not the older `SnpMigPolicy` placeholder. Source reconstruction, destination
computation and the separate CURRENT_ETCB ARG admission check must pass the
P0.4 downstream qualification gate.
Implement the exact P0.9A1 identity digest and allowlist checks and the P0.9B1
current-platform, component-wise, mitigation-vector, exact-identity, and
recovery-mode rules.

The destination computes the accepted `MigrationDataV1` after all tenant,
platform, MA/Policy, endorsement, and history checks pass. It returns the exact
64 bytes and their authorization-context binding to the source. The source
independently reconstructs and verifies those bytes before protected key delivery or
installation.

Reject:

- unknown profiles;
- nonzero reserved ETCB bits;
- malformed components;
- current ARG below policy minimum;
- attempted increase of historical minima;
- changed `INIT_MA_REPORT_ID`;
- profile mismatch without an explicit mapping.
- missing, invalid, expired, or unapproved fixed-release allowlist;
- unknown authorization root or wrong signer purpose;
- MA/Policy identity-digest mismatch;
- a differently ranked or differently identified MA release.

Task 9 fixed-profile work does not activate release SVN, ordered collateral,
initial-MA authorization lookup or cross-release ordering. Their contracts
are accepted under P0.9A2-P0.9C2; live production integration remains Phase 5
work through the P0.9D ordered handoff.

## Task 10 - Deliver the direct-random migration key and accept

Status: READY after Task 9 and P0.10

Consume [T4.14-PRE](snp/task4/t4.14-pre-direct-random.md) and its independent V2
vectors. Enforce current encrypted SPDM, verified purpose6/7 evidence,
policy/history, durable replay and current firmware before key generation or
delivery. No commitment, bilateral contribution, KDF or HMAC provider exists.
Qualify actual protected I/O and once-only generation/retry authority; a
decoded acceptance, model token or matching digest is not that authority.
Wire abort/drop and secret/transport-copy cleanup into every timeout,
cancellation, disconnect and failure path; unknown effects require reconciliation.

Sequence:

1. require accepted MA/tenant authorization, admitted history and replay state;
2. independently reconstruct the identical703-byte V2 nonsecret session recipe;
3. source generates one final fresh random32 MSK; destination generates none;
4. send0x30 key/history through the promoted encrypted SPDM owner;
5. destination explicitly accepts the exact operation/context with0x31;
6. admit destination installation, then require its correlated completion
   under0x32/0x33 before admitting source installation;
7. exchange source completion/ack under0x34/0x35;
8. require both correlated successful firmware outcomes for success; abort,
   zeroize and reconcile failures, partial/unknown effects, replay or reordering.

## Task 11 - Install migration information

Mandatory P0.4 closure: both installation inputs must pass canonical
`MigrationDataV1` decoding and exact accepted-history/source-destination
comparison before persistence. Post-install digest construction is not a
substitute for this admission check; Task 12 must verify the persisted bytes.

Status: READY after Task 10

Implement:

```text
MA workflow
 -> MigrationKeyInstaller
 -> emulator adapter
 -> MSG_SET_MIGRATION_INFO semantics
 -> persistent migration state
```

The emulator models:

```text
legal source and destination states
bound MA identity
one active migration session
role and algorithm
source/destination REPORT_ID rules
installed 32-byte MSK
exact 64-byte VeniceV1 MigrationDataV1
partial installation
abort and cleanup
idempotent retry where permitted
```

Writer and installation ownership:

```text
destination computes accepted MigrationDataV1
source independently verifies the exact 64 bytes
source and destination bind the same bytes into the V2 session/delivery state
both MAs install byte-identical MigrationDataV1
source installs with MIGRATION_ROLE = 0 and matching REPORT_ID
destination installs with MIGRATION_ROLE = 1
```

Any byte mismatch aborts before installation. A retry may reuse only the
already-authorized bytes recorded for the same request and session.

The hardware provider remains unavailable until Phase 5.

## Task 12 - Verify post-install persisted state

Status: DEFERRED FUTURE WORK; NOT A CURRENT IMPLEMENTATION OR READINESS GATE

The user-approved current-scope override defers this entire evidence-generation,
exchange and verification step. It does not block Task 13, Task 14 or later
milestones at this stage. The following original requirements are retained
as historical design, not active gates. Reactivation needs separate approval
and a demonstrated authenticated source of actual persisted tenant state.

### Historical Task 12 requirements (deferred)

Mandatory P0.8 closure: authenticate fresh actual persisted-state evidence
before accepting/sending the typed success result. Bind the existing P0.3
installation-result digest to the same session and exact accepted history;
do not trust a digest copied from the result. Negative/indeterminate outcomes
must be reported explicitly without waiting for success-only evidence.
The destination-result receipt alone never proves source-side installation
or authorizes readiness.

Sequence:

1. destination installation completes;
2. destination produces fresh P0.3 purpose-`0x03`, role-`Destination`
   evidence from modeled persisted state;
3. evidence exposes valid migration data and expected history;
4. the peer reconstructs the exact post-install purpose preimage, verifies all
   64 `REPORT_DATA` bytes, signature, identity, binding, and exact history;
5. the destination sends the typed installation result;
6. both MAs confirm successful role-specific installation and persistence
   verification before reporting migration readiness to BASE.

Post-install evidence confirms persistence. It is not an input needed to
authorize the same installation.
The peer-visible success ordering is persisted-state evidence, peer
verification, typed installation result, then readiness. A local installer
return is not the peer-visible result; failures are reported explicitly and
never wait for success-only evidence or authorize readiness.

## Task 13 - Integration, replay, failure, and recovery tests

Status: READY after Tasks 7-12

Mandatory P0.6 closure: run process-restart/crash/concurrent-writer and
independently anchored rollback tests using actual providers, including
ambiguous commits, missing state, terminal retries, changed commitments and
effects-once behavior. Controller-reopen and separate-field memory models are
not physical persistence or rollback-resistance qualification.

Cover:

```text
cross-record equality
wrong request, role, direction, or tenant
zero-bound report substitution and replay
duplicate or reordered contributions
duplicate or reordered confirmation tags
wrong policy or collateral
stale evidence classification
canonical MA/Policy identity digest equality
changed identity input field
invalid fixed-release allowlist signature
unknown authorization root
wrong signer purpose
expired allowlist
non-Approved allowlist status
fixture root rejected by production composition
different MA release rejected in FixedReleaseV1
history rollback and profile mismatch
first-migration INIT_MA_REPORT_ID establishment
subsequent-migration INIT_MA_REPORT_ID preservation
attempted current, outgoing, incoming, or replacement MA substitution
source/destination INIT_MA_REPORT_ID mismatch
missing previously valid migration history
initial-MA authorization record REPORT_ID mismatch
timeout and cancellation
partial installation
restart and retry
abort cleanup
durable replay journal
transport correlation
```

## Task 14 - Migration emulator qualification

Status: READY after Task 13

Validate:

```text
SingleProcessMigration
InterNodeTwoProcessMigration
FixedReleaseV1 exact MA/Policy authorization
signed allowlist verification
fixed-release identity negative vectors
fixture trust isolation
AAS Version 6 verifier behavior
authenticated migration-claim extraction
P0.12A/P0.12A1 verifier-boundary vectors
provider selection
SnpEmuAzure/std build
SnpHardware/std compile and fail-closed provider composition
absence of TAV from both SNP dependency graphs
TDX and AzCVMEmu preservation
positive and negative protocol scenarios
build and feature matrix
MigTD-owned SnpEmuAzure bundle builder
valid snp-ma-bundle-manifest-v1
manifest-driven two-VM harness with no nested MigTD checkout
Phase 2 artifact/launch harness parity record and completed-protocol qualification
corrupt, missing, mismatched, and unsupported manifest negative tests
```

Allowed conclusion:

```text
inter-node migration emulator milestone complete
FixedReleaseV1 MA authorization emulator-verified
signed allowlist and trusted-root verification complete
hardware interfaces compile or fail closed
```

Not allowed:

```text
cross-release MA upgrade supported
ordered MA/Policy SVN authorization
initial-MA SVN continuity
production custom collateral or revocation lifecycle qualified
hardware-qualified
BASE-integrated
real PSP/ARG command execution
production replay-state persistence qualified
```

## Phase 3 gate

The inter-node migration emulator is end-to-end, deterministic, negative-test
complete, and cleanly separated from production claims. Its qualified bundle
is produced entirely by MigTD-owned tooling and consumed through the frozen
manifest contract without a `snp-ma-vm-harness` source dependency.

The Phase 3 authorization result is explicitly:

```text
FixedReleaseV1 only
all participating MAs match the policy-selected identity exactly
no cross-release ordering or initial-MA SVN claim
```

---

# Phase 4 - Local MA Handoff and Recovery Emulator

This phase validates local rebind protocol and state-machine behavior. It does
not execute the real PSP command.

## R4.1 Build authoritative firmware binding-state emulator

Status: READY after Phase 3

The state owner is independent of both MA processes and maintains:

```text
unique tenant and MA context handles
current tenant-to-MA binding
MA and tenant lifecycle state
incoming and outgoing handoff-secret slots
handoff or recovery mode
per-tenant command attempts and results
atomic per-tenant binding transition
```

Essential handoff behavior:

```text
if target.current_ma == old_ma
   and old_ma.outgoing_secret is valid
   and new_ma.incoming_secret is valid
   and constant_time_equal(old_secret, new_secret)
   and all context-state checks pass:
       atomically set target.current_ma = new_ma
       return SUCCESS
else:
       preserve target.current_ma
       return the modeled firmware error
```

## R4.2 Implement `LocalMaHandoffTwoProcess`

Status: READY after R4.1

Actors:

```text
Rust process 1: old MA
Rust process 2: new MA
Host/BASE coordinator
authoritative firmware-state emulator
```

The two MA processes establish local authenticated encrypted SPDM. The host
routes opaque records but does not terminate the session or learn the secret.

### Current framework assessment

The repository already contains the framework needed to establish encrypted
SPDM between two same-host Rust processes, but it does not yet contain the
complete SNP handoff workflow.

| Capability | Current state |
|---|---|
| Two Rust emulator processes | Available |
| TCP loopback peer channel | Available |
| SPDM requester and responder | Available |
| Mutual authentication and encrypted session | Available |
| Old/new rebind SPDM skeleton | Available, but TDX-specific |
| SNP local logical contracts/codecs | Accepted and frozen by P0.11; no runtime activation |
| SNP handoff runtime | Missing |
| `MSG_SET_HANDOFF_SECRET` emulator | Missing |
| Authoritative binding-state emulator | Missing |
| Emulated `SNP_REBIND_MA` | Missing |
| BASE handoff coordinator | Missing |

### Existing reusable framework

`snpemu` already configures one process as a TCP client and the other as a TCP
server:

```text
src/migtd/src/bin/migtd/snpemu.rs:178-211
```

The standalone default peer endpoint is loopback:

```text
src/migtd/src/runtime/snp/config.rs:9
127.0.0.1:8001
```

The generic SPDM contexts accept any asynchronous read/write stream:

```text
Requester:
    src/migtd/src/spdm/spdm_req.rs:44-94

Responder:
    src/migtd/src/spdm/spdm_rsp.rs:87-150
```

They already negotiate:

```text
SPDM 1.2
mutual authentication
ECDSA P-384
SHA-384
ECDHE P-384
AES-256-GCM
```

Existing rebind-specific requester and responder loops are in:

```text
src/migtd/src/spdm/spdm_rebind.rs
```

No new SPDM library or cryptographic implementation is required.

### Why the current implementation is not complete

`SnpEmu` explicitly rejects rebinding requests:

```text
src/migtd/src/bin/migtd/snpemu.rs:296-300
```

The existing rebind implementation is inherited TDX/Service-TD logic. It uses:

```text
tdcall_servtd_rebind_approve
tdcall_vm_write
TDCS_FIELD_SERVTD_REBIND_ACCEPT_TOKEN
TDCS_FIELD_SERVTD_REBIND_ATTR
TargetTdUuid
ServtdExt
```

These dependencies are visible in:

```text
src/migtd/src/migration/rebinding.rs:13-40
```

That implementation cannot represent SNP `MSG_SET_HANDOFF_SECRET` or
`SNP_REBIND_MA` and must not be reused as the SNP platform-binding operation.

### Required R4.2 implementation

#### 1. Add handoff-specific runtime roles

```rust
enum HandoffRole {
    OldMa,
    NewMa,
}
```

Do not overload the inter-node migration `Source` and `Destination` roles.

#### 2. Add an explicit peer-session purpose

```rust
enum PeerSessionPurpose {
    InterNodeMigration,
    LocalMaHandoff,
}
```

The purpose fixes the permitted roles, policy, evidence purposes, and
application records. Migration VDM messages must be rejected during local
handoff and handoff records must be rejected during inter-node migration.

#### 3. Create a local peer transport

For the emulator, reuse TCP loopback initially:

```text
new MA:
    listen on 127.0.0.1:<handoff-port>

old MA:
    connect to that address
```

The durable design is a `PeerTransportFactory` that returns an asynchronous
read/write stream. The SPDM layer must not depend directly on the global
`tdx_tdcall_emu` TCP state. This also permits a later Unix-domain socket,
VMBus, or Underhill transport without changing the SPDM protocol.

#### 4. Create SNP handoff SPDM drivers

Reuse the existing SPDM requester/responder negotiation, but replace the
TDX-shaped rebind context with:

```rust
struct SnpHandoffContext {
    handoff_id: [u8; 16],
    old_ma_identity: MaIdentity,
    new_ma_identity: MaIdentity,
    tenant_set_digest: [u8; 48],
    policy_digest: [u8; 48],
    deadline: u64,
}
```

Implement:

```text
spdm_requester_handoff_old
spdm_responder_handoff_new
```

The old MA may be the requester and the new MA the responder, matching the
existing requester/responder rebind shape. The role assignment must be frozen
and verified rather than inferred from which endpoint connected first.

#### 5. Define protected handoff VDM records

Inside the established SPDM session, define and version:

```text
HandoffAttestation
HandoffMetadataManifest
HandoffMetadata
HandoffSecret
HandoffReady
HandoffAbort
```

Every record binds:

```text
handoff_id
old and new MA roles
tenant-set digest
policy digest
record version
request or correlation identity
```

The handoff secret is carried only as encrypted SPDM application data.

#### 6. Extend `HostControlTransport`

Add runtime dispatch for:

```text
PrepareMaHandoffRequest
MaHandoffReady
MaRebindResult
ConfirmRebindResult
FinalizeMaHandoff
AbortMaHandoff
QueryMaHandoffStatus
RetryMaRebind
```

The existing TCP host-control transport can carry these typed control
messages. It must never carry the handoff secret, SPDM session keys, or
plaintext protected metadata.

#### 7. Implement handoff-secret providers

Each process needs an interface equivalent to:

```rust
trait HandoffSecretProvider {
    fn install_outgoing(...);
    fn install_incoming(...);
    fn clear(...);
}
```

The emulator provider writes only into the authoritative firmware-state
emulator. The production provider later maps these operations to
`MSG_SET_HANDOFF_SECRET`.

#### 8. Implement authoritative rebind state

A coordinator or state service independent of both MA processes owns:

```text
tenant-to-MA bindings
old and new MA contexts
incoming and outgoing handoff-secret slots
context lifecycle state
atomic per-tenant rebind
firmware-style status results
```

Neither Rust MA process may directly modify the authoritative tenant binding.

#### 9. Add process orchestration

```text
1. BASE emulator starts the new MA.
2. The new MA opens its local peer listener.
3. BASE supplies the opaque endpoint and expected peer context to the old MA.
4. The old MA connects.
5. SPDM negotiation and mutual authentication complete.
6. The handoff application records are exchanged.
7. Both MAs install their secret slots and report readiness.
8. BASE invokes the emulated firmware rebind operation.
```

The listening address is transport routing data. It is not proof of peer
identity; peer acceptance comes from the SPDM evidence and policy checks.

#### 10. Add negative and lifecycle tests

Cover:

```text
peer authentication failure
incorrect old/new roles
wrong handoff_id
mismatched tenant-set digest
mismatched policy digest
mismatched or missing handoff secrets
replayed handoff records
connection loss before readiness
connection loss after secret installation
partial tenant rebind
duplicate host-control messages
premature old-MA shutdown
secret cleanup on success, abort, timeout, and failure
```

### Hardware reuse and provider selection

Most R4.2 protocol and application-layer work is shared with hardware. The
emulator-specific transport and platform providers are replaced without
changing the handoff roles, authenticated context, records, sequencing, or
failure policy.

| R4.2 step | Hardware applicability |
|---|---|
| 1. `HandoffRole { OldMa, NewMa }` | Shared unchanged |
| 2. `PeerSessionPurpose::LocalMaHandoff` | Shared unchanged |
| 3. Local peer transport | Interface is shared; replace TCP loopback with VMBus, Underhill, shared memory, or another approved local transport |
| 4. SNP handoff SPDM drivers | Shared; hardware uses real MA evidence and production trust policy |
| 5. Protected handoff VDM records | Shared wire protocol, assuming SPDM remains the approved production handoff channel |
| 6. `HostControlTransport` messages | Shared contract; replace TCP host control with the BASE/Hyper-V backend |
| 7. `HandoffSecretProvider` | Shared interface; hardware invokes `MSG_SET_HANDOFF_SECRET` |
| 8. Authoritative rebind state | Shared state model; PSP owns actual bindings and executes `SNP_REBIND_MA` |
| 9. Process orchestration | Shared sequence; BASE launches and coordinates the production MA instances |
| 10. Negative and lifecycle tests | Shared cases plus real firmware, GCTX, state, timeout, and status-code validation |

Production substitutions:

```text
TCP loopback peer transport
    -> production local MA transport

TCP HostControlTransport
    -> BASE/Hyper-V control transport

fixture MA evidence
    -> real Version 6 attestation evidence

emulated handoff-secret slots
    -> MSG_SET_HANDOFF_SECRET

firmware binding-state emulator
    -> PSP guest-context state

emulated rebind
    -> SNP_REBIND_MA command 0xF5
```

The following behavior must remain identical:

```text
old and new MA roles
LocalMaHandoff session purpose
handoff context and identity binding
SPDM authentication requirements
VDM record layouts
handoff-secret lifetime and non-exposure
readiness and confirmation semantics
partial-failure ownership
retry and idempotency policy
old-MA shutdown criteria
```

#### Current backend-switch capability

The current implementation does not provide a complete emulator-to-hardware
switch. It contains partial abstraction points:

| Component | Current state |
|---|---|
| Roles and session purpose | Common types; handoff-specific types still need implementation |
| Peer transport | TCP exists; Underhill is configurable but rejected as unimplemented |
| SPDM | Transport-generic requester/responder exists; SNP handoff drivers are missing |
| Handoff records | Missing |
| Host control | Trait and TCP backend exist; production BASE backend is missing |
| Handoff-secret provider | Missing |
| Binding authority | Missing for both the SNP emulator and hardware |
| Handoff orchestration | Missing |
| Emulator/hardware handoff test matrix | Missing |

The runtime configuration can represent:

```text
--platform-services fixture|hardware
--peer-transport tcp-emulation|underhill
```

However, `snpemu` currently rejects `hardware` and `underhill`. These are
configuration placeholders, not functioning backend switches.

#### Required provider composition

The handoff workflow must depend on a provider set selected at the composition
root:

```rust
struct HandoffProviderSet {
    peer_transport: Box<dyn PeerTransportFactory>,
    host_control: Box<dyn HostControlTransport>,
    evidence: Box<dyn MaEvidenceProvider>,
    secrets: Box<dyn HandoffSecretProvider>,
    bindings: Box<dyn MaBindingManager>,
    randomness: Box<dyn RandomSource>,
}
```

Emulator composition:

```text
peer_transport = TCP loopback or local socket
host_control   = TCP host-control backend
evidence       = signed fixture Version 6 reports
secrets        = emulated MA secret slots
bindings       = authoritative firmware-state emulator
randomness     = emulator OS CSPRNG; scripted source only in unit tests
```

Hardware composition:

```text
peer_transport = approved VMBus/Underhill/local platform transport
host_control   = BASE/Hyper-V backend
evidence       = real Version 6 attestation provider
secrets        = MSG_SET_HANDOFF_SECRET provider
bindings       = SNP_REBIND_MA and binding-query provider
randomness     = production PAL CSPRNG
```

Provider selection occurs once at process startup or compile-time composition.
It must not change during an active handoff. Hardware mode fails closed if any
required hardware provider is unavailable and must never fall back to an
emulator provider.

### R4.2 completion criteria

R4.2 is complete when:

```text
two independent same-host Rust MA processes establish SPDM 1.2
both MAs mutually authenticate under the local handoff policy
the session is explicitly typed as LocalMaHandoff
handoff metadata and the secret travel only in encrypted SPDM
BASE sees readiness and status but never secret material
the firmware-state emulator remains the sole binding authority
all negative session-purpose, role, replay, and cleanup tests pass
```

The difficult SPDM transport and cryptographic foundation already exists.
R4.2 primarily refactors it into a handoff-specific local peer session, adds
SNP handoff records and host control, and connects it to the independent
binding-state emulator.

## R4.3 Implement planned handoff

Mandatory P0.4 closure: verify all 64 authoritative pre/post history bytes,
not just the initial-MA ID, across success, retry, partial failure and restart.

Status: READY after R4.2 and P0.11

Consume the applicable fixed/ordered P0.9D handoff; contract availability alone
does not authorize cross-release activation or replace P0.11 recovery/history
and firmware-state checks.

This milestone qualifies same-release handoff only. Before metadata or secret
transfer:

```text
old_ma.MA_POLICY_IDENTITY_DIGEST ==
    policy-selected FixedReleaseV1 identity

new_ma.MA_POLICY_IDENTITY_DIGEST ==
    policy-selected FixedReleaseV1 identity
```

A different incoming MA identity is rejected even if separately signed or
otherwise recognizable. Cross-release handoff requires P0.9A2-P0.9C2.

Sequence:

1. start the state emulator with tenants bound to the old MA;
2. start the new MA;
3. allocate `handoff_id`, operation epoch, and frozen tenant-set digest;
4. send `PrepareMaHandoffRequest` to both MAs;
5. establish local SPDM and exchange fresh P0.3 purpose-`0x04`
   prepare-authorization evidence for roles `Outgoing` and `Incoming`;
6. verify peer evidence, roles, policy, context, and exact purpose preimages;
7. transfer versioned metadata;
8. generate the handoff secret;
9. install outgoing and incoming secret slots;
10. receive matching `MaHandoffReady`;
11. invoke emulated `SNP_REBIND_MA` per tenant;
12. deliver exact `MaRebindResult`;
13. exchange and verify purpose-`0x04` firmware-result-confirmation evidence;
14. receive `ConfirmRebindResult` from the new MA;
15. reconcile partial failures and retries;
16. send `FinalizeMaHandoff`;
17. clear both secrets with `VALID=0`;
18. stop the old MA only after finalization;
19. query authoritative bindings and prove new-MA service;
20. verify every rebound tenant retains its pre-handoff
    `INIT_MA_REPORT_ID` byte-identically.

Success cannot be established from logs alone.

## R4.4 Test planned-handoff failure policy

Status: READY after R4.3

Cover:

```text
peer attestation rejection
policy or tenant-set mismatch
old or new MA identity differs from the FixedReleaseV1 identity
absent, mismatched, expired, or deleted secrets
unauthorized tenant
per-tenant failure with unchanged binding
partial multi-tenant success
idempotent retry
duplicate control messages
old-MA crash before readiness
old-MA crash after secret installation
old-MA crash after partial rebind
new-MA crash before confirmation
secret cleanup on every terminal path
old-MA shutdown attempted too early
attempted replacement of INIT_MA_REPORT_ID with old-MA, new-MA, or current-MA
identity
changed or missing MIGRATION_DATA across partial success, retry, or restart
```

During partial success:

```text
old MA owns tenants whose binding did not change
new MA owns tenants successfully rebound
BASE records and reconciles the split ownership
```

## R4.5 Implement recovery-mode emulator

Mandatory P0.4 closure: preserve and verify all 64 authoritative history bytes;
never initialize fresh history or replace the initial-MA ID during recovery.

Status: READY after R4.1 and R4.4

Sequence:

1. terminate or mark the old MA unavailable;
2. launch a replacement satisfying the modeled identity and launch-state
   requirements;
3. send `PrepareMaRecoveryRequest`;
4. receive and verify fresh P0.3 purpose-`0x05`, role-`Incoming`
   prepare-authorization evidence;
5. receive `MaRecoveryReady`;
6. invoke emulated recovery-mode `SNP_REBIND_MA` per tenant;
7. deliver `MaRebindResult`;
8. receive and verify purpose-`0x05` firmware-result-confirmation evidence;
9. receive `ConfirmRecoveryResult`;
10. send `FinalizeMaRecovery`;
11. verify authoritative bindings and restored service;
12. verify every recovered tenant retains its pre-recovery
    `INIT_MA_REPORT_ID` byte-identically.

There is no old/new SPDM and no handoff secret in recovery mode.

## R4.6 Handle active inter-node migration during local handoff

Status: READY after R4.3

Default Version 1 policy:

```text
abort the old inter-node SPDM session
preserve only explicitly transferable authenticated operation state
new local MA establishes a fresh inter-node SPDM session
remote MA re-attests the new local MA
restart the migration operation unless an approved resume record proves the
exact request, tenant, policy, history, replay state, and peer state
```

The remote MA never receives the local handoff secret and never participates
in local `SNP_REBIND_MA`.

## R4.7 Rebind emulator qualification

Status: READY after R4.4-R4.6

Allowed conclusion:

```text
same-release local planned-handoff state machine emulator-verified
local recovery state machine emulator-verified
two Rust MA process workflow verified
FixedReleaseV1 authorization preserved across handoff
```

Not allowed:

```text
cross-release planned handoff or MA upgrade
initial-versus-incoming MA/Policy SVN comparison
production custom collateral, revocation, or rotation qualification
real SNP_REBIND_MA support
real GCTX or RMP validation
Hyper-V or BASE production integration
firmware atomicity qualification
```

## Phase 4 gate

Planned handoff and recovery pass their complete positive, negative, retry,
partial-failure, cleanup, authoritative-state, and immutable
`INIT_MA_REPORT_ID` tests. Planned handoff remains limited to two MAs matching
the same policy-selected `FixedReleaseV1` identity. Phase 4 does not satisfy
the ordered-release production gate.

---

# Phase 5 - Production Integration and Hardware Qualification

## H5.0 Production contract and physical-parser readiness

Status: BLOCKED on the named production contracts and AMD layout clarification;
does not block Phases 1-4

Before production report-dependent integration:

1. Review the accepted P0.9A2/B2/C2 endorsement, ordering and lifecycle
   contracts and P0.9D consumer handoffs against deployment requirements.
   Obtain any required explicitly versioned change and actual publishing/
   deployment approval; do not silently refreeze or reinterpret accepted
   bytes. H5.2 integrates/qualifies real providers against those contracts,
   not an invented replacement prerequisite.
2. Resolve PA-009 with an authoritative AMD layout, selector, erratum, or
   report version for ETCB and migration data. Record exact ABI citations and
   obtain any required versioned contract/profile addendum; do not silently
   reinterpret the frozen emulator profile or conflicting raw layouts.
3. Complete the production portion of AAS1A in
   `Azure/azure-guest-attestation-sdk`: authenticate and extract both claim
   groups under the resolved layout using real or independently generated
   production-profile vectors.
4. Accept and pin the upstream AAS implementation, update the MigTD production
   adapter and provenance mapping, and rerun production verifier conformance,
   malformed-input, collateral, and fixture-rejection tests.
5. Record the production parser readiness evidence against PA-009. Until this
   gate passes, `SnpHardware` continues to fail closed without partial claims.

Contract, compile-only, and isolated provider work may proceed while the
physical parser is blocked, but production report-dependent acceptance for
H5.1-H5.6 and hardware qualification under H5.7 may not. P0.12B remains a
separate composite-evidence contract freeze before AAS1B.

## H5.1 BASE migration host-control integration

Owner: BASE team and MigTD host-control owners

Mandatory P0.5 closure: qualify actual SNP_HV_REPORT_REQ acquisition, BASE-owned
handle-to-GCTX mapping, delivery/cache lifecycle and correlated outcomes using
the shared identity lifecycle. P0.5 adds no OHCL kernel implementation and makes
no assertion that later kernel work is unnecessary.

Mandatory P0.6 closure: implement BASE propagation so both local prepare
requests carry the same complete source tenant report/package or a reference
to its already-pushed local copy before any purpose-1 contribution evidence.
Destination routing must not substitute a different tenant report or treat
its managed destination handle as the source tenant REPORT_ID.

Implement:

```text
host-push PrepareMigrationRequest
tenant handle to GCTX mapping
tenant report acquisition and delivery
request correlation
cancel, abort, and status
actual firmware outcome reporting
```

Host-push is selected and is not an open architectural decision.

## H5.2 Production collateral integration

Status: PRODUCTION QUALIFICATION GATED on H5.0 deployment-contract review,
actual provider readiness and production parser readiness. P0.9A2-P0.9C2
bounded contracts are already accepted; P0.9D defines their consumer handoff.

Promote authorization from `FixedReleaseV1` to `OrderedReleaseV1`. Preserve
the canonical `MA_POLICY_IDENTITY_DIGEST`; add separate versioned production
records rather than extending the fixed-release allowlist with dormant fields.

Implement:

```text
VCEK, VLEK, or chip-secret VCEK acquisition as selected for production
ASK acquisition
trusted ARK configuration
freshness and revocation
TCB/ETCB profile selection
cache lifecycle
failure policy
MA/Policy endorsement acquisition
release-to-SVN mapping
endorsement trust roots, expiration, revocation, and signer/key rotation
```

Required ordered-release artifacts:

```text
MaReleaseEndorsementV1 (custom signed SNP collateral v1)
MA_POLICY_IDENTITY_DIGEST -> combined MA/Policy SVN mapping
stable MA/Policy signer identity
InitialMaAuthorizationV1
signed revocation and trust-update inputs
root and signer rotation policy
```

Required comparisons:

```text
destination MA/Policy SVN >= source MA/Policy SVN
incoming MA/Policy SVN >= outgoing MA/Policy SVN
incoming MA/Policy SVN >= initial MA/Policy SVN
all MA/Policy SVNs >= configured absolute floor
```

Required tests:

```text
multiple releases with equal SVN
approved forward SVN move
source/destination downgrade
outgoing/incoming downgrade
incoming/initial downgrade
missing and conflicting mapping
expired or revoked release
leaf and intermediate rotation
root transition
unknown signer purpose
revocation information unavailable
fixed-release and ordered-release profile confusion
```

H5.2 completes only when PA-001, PA-002, PA-004, and PA-005 in
`doc/snp-production-readiness.md` are `QUALIFIED`.

## H5.3 Production migration installation

Validate:

```text
platform key operation if used
MSG_SET_MIGRATION_INFO
exact VeniceV1 MigrationDataV1
status and error mapping
abort and recovery
SNP_ARG_BEGIN_MIGRATION host ownership
```

## H5.4 Qualify bounded tenant-report replay and durable state

Mandatory P0.6 closure: qualify the real storage/anchor and authoritative
firmware providers against the frozen journal/digest contract. Demonstrate
durable atomic commit, bounded decoding, no empty-state fallback, independent
rollback rejection across restart/rebind, full terminal result retention and
safe cleanup/capacity management. Readback alone proves none of these physical
guarantees. Both BASEs must deliver the same complete source evidence before
purpose 1, without MA-pull or claiming report first-use freshness.

Version 1 intentionally uses host-requested tenant reports with
`REPORT_DATA = zero[64]`. The tenant report is not required to prove first use
or directly contain LM-session data. Fresh MA evidence binds the canonical
tenant-report digest to TH1, request, roles, tenant identity, and policy.

Owners:

```text
BASE team
MigTD persistent-state owners
Microsoft security and protocol owners
```

Implement and validate:

```text
durable report-digest and request journal
tenant and operation-state correlation
protocol-defined idempotent retry
conflicting-reuse and terminal-state rejection
restart and crash recovery
rollback-resistant trusted-state storage
current firmware binding and lifecycle revalidation
retention, cleanup, cache lifetime, and resource limits
auditable replay and recovery outcomes
```

Acceptance:

- zero-filled host-requested tenant reports are accepted as the production
  Version 1 format;
- no component claims that the tenant report itself is fresh or session-bound;
- duplicate delivery for an allowed idempotent retry produces the recorded
  result;
- conflicting reuse, replay-state rollback, and reuse after terminal outcome
  fail closed;
- restart and recovery preserve the required replay decisions;
- hardware qualification demonstrates the durable-state behavior.

## H5.5 Production MA handoff and recovery integration

Implement:

```text
MSG_SET_HANDOFF_SECRET
SNP_REBIND_MA command 0xF5
handoff mode
recovery mode
managed handle to GCTX mapping
per-tenant command result
partial-failure reconciliation
binding and accounting query
secret deletion
old-MA shutdown authorization
```

Validate the three-plane separation:

```text
BASE host control
local old/new MA SPDM for planned handoff
host-to-PSP firmware command path
```

Recovery must not attempt old/new MA communication.

Validate that planned handoff and recovery preserve the tenant's existing
`MIGRATION_DATA` byte-for-byte. Do not issue `MSG_SET_MIGRATION_INFO` as part
of rebind and do not report a history update.

Production cross-release handoff additionally requires the accepted
`OrderedReleaseV1` comparisons from H5.2. Same-release hardware handoff may be
qualified independently but must be labeled as `FixedReleaseV1`.

## H5.6 Production relying-party evidence and AAS integration

Owners:

```text
Azure Guest Attestation SDK owners
MigTD owners
BASE team and attestation-client owners
Microsoft MA release and security endorsement owners
application relying-party owners
```

### AAS1B - Complete composite relying-party verification

Status: READY after H5.0 production-parser readiness, P0.9A2-P0.9C2,
P0.12B, AAS1A, Tasks 7-14, and H5.2-H5.4

Extend AAS beyond the AAS1A single-report verifier:

```text
verify each report and its exact collateral
parse and evaluate MigrationDataV1
correlate tenant, current-MA, and initial-MA identities
verify MA/Policy endorsements and release-to-SVN mappings
apply expiration, revocation, and rotation policy
classify bounded replay without claiming tenant-report first-use freshness
return CompositeSnpVerificationResultV1
```

This external relying-party work does not execute inside Task 7 and does not
block the migration emulator. It may share the AAS1A report-verification and
authenticated-claim implementation.

Implement:

```text
production CompositeSnpEvidenceV1 assembly
the P0.12B-selected initial-MA evidence carry or lookup mechanism
tenant, current-MA, and initial-MA collateral association
production MA/Policy endorsement publication and retrieval
AAS single-report and composite-verifier integration
canonical local or remote evidence encoding
authenticated result claims and typed failure mapping
cache, retention, privacy, and size-limit enforcement
```

End-to-end tests:

```text
valid tenant/current-MA/initial-MA evidence
current MA REPORT_ID mismatch
initial MA REPORT_ID mismatch
missing or ambiguous initial-MA evidence
wrong, expired, revoked, or rotated MA/Policy endorsement
MigrationDataV1 rollback or profile mismatch
wrong collateral associated with one report
unsupported signing-key kind
malformed, oversized, truncated, duplicate, or reordered envelope members
bounded-replay classification and durable-state restart
identical claims from internal and remote envelope representations
```

Completion requires:

- the AAS dependency points to the accepted upstream implementation;
- evidence assembly ownership and deployment paths are operational;
- the initial-MA mechanism works across migration hops and service restarts;
- relying-party decisions consume authenticated verifier claims rather than
  unverified envelope metadata;
- negative cases fail closed with stable typed reasons.
- PA-003, PA-006, and PA-007 in `doc/snp-production-readiness.md` are
  `QUALIFIED`.

## H5.7 Hardware and end-to-end qualification

Status: READY after H5.0-H5.6, including P0.12B and AAS1B

Run on supported Venice-capable hardware and firmware.

Required evidence:

```text
firmware and ARG versions
command and status traces
real reports and collateral
Version 6 field validation
real migration installation
real planned handoff and recovery
negative-state behavior
restart and partial-failure behavior
binding/accounting verification
production composite evidence assembly
AAS Version 6 and composite verification results
initial-MA evidence resolution
MA/Policy endorsement appraisal
end-to-end relying-party allow and deny decisions
hashes, logs, commits, and environment record
```

Authorization qualification must separately report:

```text
FixedReleaseV1 hardware result
OrderedReleaseV1 cross-release result
initial-MA continuity result
revocation and rotation result
composite relying-party result
```

No result from the fixed-release emulator or same-release hardware path may be
used as evidence for an ordered-release or initial-MA continuity claim.

Production image-hygiene qualification:

```text
build with --no-default-features and the explicit SnpHardware feature
record cargo tree -e features and the complete dependency inventory
produce an SBOM for Rust crates, OpenSSL/native libraries, kernel, loader,
    initramfs, and production userspace dependencies
prove fixture reports, fixture certificates, synthetic roots, deterministic
    test randomness, state-emulator code, TCP emulator transports, mock
    installation, mock rebind, and test attestation bypasses are absent
prove no TAV crate, implementation, trace marker, or fallback remains in the
    final SNP production dependency graph or image
record static versus dynamic linking and the exact loader/library versions
verify the kernel, initramfs, root filesystem, MA binary, and native
    dependencies are transitively authenticated by the measured and endorsed
    production boot chain
boot with unavailable production evidence, collateral, installation,
    persistence, transport, and rebind providers and verify explicit
    fail-closed behavior rather than fixture fallback
record the final MA ELF, initramfs, kernel, root filesystem, manifest, SBOM,
    AAS commit, Cargo.lock, and expected measurement hashes
build and validate the SnpHardware bundle from a fresh MigTD checkout with no
    snp-ma-vm-harness checkout or undeclared local source dependency
validate the production bundle with the same
    snp-ma-bundle-manifest-v1 schema used by the emulator
prove the production harness consumes only the validated bundle and declared
    external platform inputs
```

Production and emulator bundle builders are separate. Neither builder may
overwrite, relabel, or reuse the other composition's manifest or qualification
record.

Only this gate may claim hardware qualification.

---

# Canonical Inter-node Migration Sequence

Current sequence applies the approved fresh-post-install-attestation deferral.
Numbered slots 19-20 retain traceability without requiring that deferred
exchange. Existing historical P0.8 success admission must be reconciled before
this current sequence is activated; no runtime behavior changes here.

```text
1. BASE obtains a tenant report and sends PrepareMigrationRequest.
2. The MA records provisional routing identity only.
3. Both peers cryptographically verify the same host-pushed tenant report,
   including Version 6, VMPL 0xffffffff, and zero REPORT_DATA.
4. Its verified REPORT_ID and canonical digest become authoritative inputs,
   but do not yet authorize migration.
5. Source and destination MAs establish inter-node SPDM and obtain TH1.
6. They exchange and authenticate policy identity.
7. Each MA generates a fresh contribution and attested commitment using the
   verified tenant identity.
8. They exchange purpose-0x01 MA evidence and exact collateral, authenticate
   both MAs, and correlate the tenant REPORT_ID_MA with the source MA.
9. They construct the tenant-authorization context over the report digest,
   TH1, request, roles, verified tenant identity, and policy.
10. They acquire, exchange, and verify fresh purpose-0x02 MA evidence over
    that context, including all 64 REPORT_DATA bytes.
11. TCB, ETCB, reserved bits, ARG floor, binding, replay, and freshness
    classification are checked.
12. The destination computes the accepted VeniceV1 history.
13. The destination sends the typed authorization result and exact
    MigrationDataV1 bytes.
14. The source independently reconstructs and verifies the exact bytes.
15. Raw contributions are exchanged over inter-node SPDM.
16. Both peers verify commitments and derive the identical MSK.
17. Destination and source confirmation tags bind the accepted history.
18. Both MAs install byte-identical VeniceV1 data with their respective roles.
19. DEFERRED: fresh post-install persisted-state evidence generation/exchange.
20. The destination returns its correlated typed installation outcome;
    fresh purpose-3 evidence/verification is not a current prerequisite.
21. Both MAs report readiness to BASE only after successful role-specific
    installation on both sides and all other active authorization, history
    and confirmation gates. Partial/indeterminate outcomes cannot authorize
    readiness; independently attested persistence is not claimed.
22. BASE invokes SNP_ARG_BEGIN_MIGRATION.
```

# Canonical Local Planned-Handoff Sequence

```text
1. BASE launches the new local MA.
2. BASE freezes handoff_id, epoch, policy, and tenant-set digest.
3. BASE sends PrepareMaHandoffRequest to old and new MAs.
4. The MAs establish local SPDM and mutually attest.
5. They transfer and verify versioned metadata.
6. The old MA generates the context-bound handoff secret.
7. The old and new MAs install outgoing/incoming secret slots.
8. Both return MaHandoffReady.
9. BASE invokes SNP_REBIND_MA per tenant.
10. BASE reports the exact firmware result to both MAs.
11. The new MA confirms service readiness per successful tenant.
12. BASE reconciles retries and partial failures.
13. BASE sends FinalizeMaHandoff.
14. Both MAs clear the handoff secret.
15. The old MA exits only after BASE authorizes shutdown.
```

# Canonical Crash-Recovery Sequence

```text
1. BASE detects that the old MA is unavailable.
2. BASE launches a qualifying replacement MA.
3. BASE sends PrepareMaRecoveryRequest.
4. The replacement returns MaRecoveryReady.
5. BASE invokes recovery-mode SNP_REBIND_MA per tenant.
6. Firmware checks required identity and launch-state equivalence.
7. BASE reports exact firmware outcomes.
8. The replacement confirms restored service.
9. BASE finalizes recovery.
```

There is no old/new SPDM and no handoff secret in this sequence.

# Decision Register

| ID | Decision | Status | Owner/remaining action |
|---|---|---|---|
| D-01 | Host-push tenant-report acquisition | RESOLVED | Implement in P0.5/T4.9/H5.1 |
| D-02 | Zero-bound report with additional binding | RESOLVED | Production Version 1 uses MA evidence over the tenant-report digest; H5.4 qualifies durable bounded replay |
| D-03 | Provisional versus verified tenant identity | RESOLVED | Enforce P0.5 lifecycle |
| D-04 | Policy canonicalization | DIGEST/AUTHORIZATION CONTRACTS FROZEN; APPROVED SCHEMA/PROVIDER EXTERNAL | Accepted P0.9 fixed/ordered contracts; P0.9D provider handoff; PA-010 remains unresolved, H5.0/H5.2 qualify deployment |
| D-05 | Collateral binding | FIXED/ORDERED CONTRACTS FROZEN; PRODUCTION LIFECYCLE QUALIFICATION OPEN | Accepted P0.9C1/C2; P0.9D handoff; H5.2 qualifies real acquisition, trust and state providers |
| D-06 | Secret-contribution key establishment | RESOLVED | P0.7-P0.10 |
| D-07 | VeniceV1 migration-history profile | RESOLVED | P0.4 |
| D-08 | Production collateral and revocation | OPEN FOR PRODUCTION | H5.2 |
| D-09 | Platform-key primitive availability | OPEN FOR PRODUCTION | T4.10/H5.3 |
| D-10 | Durable replay and operation state | SELECTED; PRODUCTION QUALIFICATION OPEN | Tasks 8, 11, 13, R4 and H5.4 |
| D-11 | Planned-handoff eligibility and metadata | SAME-RELEASE SELECTED; ORDERED COLLATERAL CONTRACT ACCEPTED; HANDOFF QUALIFICATION OPEN | P0.11 freezes handoff-specific rules; R4.3 consumes the applicable P0.9D handoff; cross-release integration is not implicitly activated |
| D-12 | Partial handoff and old-MA shutdown | LOGICAL V1 ACCEPTED; RUNTIME QUALIFICATION OPEN | P0.11 freezes conservative split-ownership, cleanup and shutdown gates; R4.4/H5 qualify real effects and crash recovery |
| D-13 | Active migration during local handoff | VERSION 1 DEFAULT SELECTED | Abort/re-attest/restart unless approved resume record exists |
| D-14 | Real `SNP_REBIND_MA` availability | OPEN FOR PRODUCTION | H5.5 |
| D-15 | Emulator versus hardware claim boundary | RESOLVED AND FROZEN | `P0.12A-SnpEmulatorV1-2026-11-02` freezes authenticated provenance, fixture trust, supplement binding, and production rejection; `P0.12A1-CommonVerifierBoundary-2026-11-02` finalizes owned leaf types and adapter ownership |
| D-16 | CompositeSnpEvidenceV1 contract | TO FREEZE; PRODUCTION-ONLY GATE | P0.12B/AAS1B/H5.6 |
| D-17 | Initial-MA evidence mechanism | TO SELECT; DOES NOT BLOCK EMULATOR | P0.12B; implement in H5.6 |
| D-18 | AAS Version 6 and host-requested-report support | EMULATOR BASE-REPORT CONTRACT FROZEN; PRODUCTION OVERLAPPING-FIELD PARSER BLOCKED | Implement AAS1A base-report scope and AAS1A-M supplement composition; H5.0 completes the production parser and adapter after AMD physical-layout clarification |
| D-19 | MA/Policy authorization and release-to-SVN mapping | FIXED/ORDERED CONTRACT AND FIXTURE CONFORMANCE ACCEPTED; PRODUCTION INTEGRATION OPEN | `P0.9-FixedReleaseCollateralV1-2026-11-03` and `P0.9-OrderedCollateralV1-2026-11-03`; P0.9D handoff; H5.2 runtime/providers and H5.6 composite qualification remain open |
| D-20 | Composite verifier ownership | SELECTED | Azure/azure-guest-attestation-sdk owns AAS1A/AAS1B verification; MigTD and BASE/attestation-client owners supply evidence |
| D-21 | Exact forward-policy comparisons | FIXED/ORDERED COMPARISON CONTRACTS ACCEPTED; CONSUMER QUALIFICATION OPEN | P0.9D directs B1 to Task 9/P0.11/R4.3 same release and B2 to explicitly authorized cross-release/H5.2 integration; history/recovery gates remain separate |
| D-22 | Migration-data writer and rebind behavior | RESOLVED | Task 9/Task 11 compute, verify, and install identical bytes; P0.11/H5.5 preserve history during rebind |
| D-23 | Final build-mode matrix | SELECTED | TDX hardware/no_std; AzCVMEmu/std; SnpEmuAzure/std; SnpHardware/std |
| D-24 | SNP report verifier | COMMON CONTRACT AND EMULATOR PROFILE FROZEN | AAS authenticates the Firmware ABI 1.59 base report; MigTD verifies the fixture supplement; production uses the same semantic contract and no TAV |
| D-25 | SNP production/emulator isolation | CONTRACT FROZEN; IMPLEMENTATION AND PRODUCTION QUALIFICATION PENDING | T4.15-T4.20 enforce supplement/root rejection and no fallback; prove final production image hygiene in H5.7 |
| D-26 | Atomic MigTD repository and bundle boundary | IMPLEMENTED; ACCEPTED (BOUNDED) | P2.2 makes MigTD the artifact producer; VM harnesses consume versioned bundles and contain no nested MigTD source |
| D-27 | Authorization profile staging and production-gap tracking | FIXED/ORDERED CONTRACTS AND REPOSITORY TRACKING ACCEPTED; PRODUCTION GATED | P0.9D fixes consumer boundaries; `P0.9E-ReadinessLedgerV1-2026-11-03` tracks PA-001 through PA-011 under @mvasantarao with stable ledger links; production qualification, external approval and publication remain open |
| D-28 | Session-binding purpose preimages, recovery behavior, and wire registry | APPROVED AND FROZEN | Implement `P0.3-ReportDataContextV1-2026-11-01`; update the existing Task 3 codec and vectors without changing the 220-byte total size |
| D-29 | Version 6 ETCB/MIGRATION_DATA conflict and emulator continuation | EMULATOR STRATEGY APPROVED AND FROZEN; PRODUCTION EXTERNAL DEPENDENCY | Implement `P0.12A-SnpEmulatorV1-2026-11-02`; H5.0 closes PA-009 with AMD clarification and accepted production AAS parser/adapter conformance; production fails closed until then |
| D-30 | TDX verifier and common-TEE boundary | BASIC ARCHITECTURE FROZEN; PRODUCTION ADOPTION DEFERRED | Preserve Intel QVL and the working TDX path during the emulator milestone; after reconciliation with Microsoft upstream, implement the production `TdxQuoteVerifier` adapter and use `AuthenticatedTeeEvidence` only at TEE-neutral orchestration boundaries |

# Required execution record for every step

The centralized execution-status record is `doc/implementation_record.log`.
All phase gates and step execution records are appended to this one
version-controlled file. The master plan remains the contract and ordering
authority; the log records actual execution and acceptance evidence.

Start each phase with a `PHASE START` entry naming its number and title.
Start each step entry with its phase and exact identifier, for example
`Phase 0 / P0.1`. Append entries at step start, validation, blocked or failed
outcomes, acceptance, and phase-gate acceptance. Use UTC timestamps and the
status vocabulary defined above. A phase-start entry does not satisfy its gate.

Never overwrite earlier entries. Correct errors with a dated addendum
referencing the earlier entry. Raw test logs and CI artifacts may be stored
separately, but their durable references and results belong in this file.
Do not log secrets, credentials, key contributions, or protected metadata.
Unknown or unverified fields are explicitly marked pending, not successful.
Mark a step `DONE` only after its evidence is persistent and user acceptance
is recorded; record phase-gate acceptance before beginning the next phase.

Each entry uses the format initialized in the centralized log and preserves:

```text
phase and step identifier
UTC timestamp and event
status, prerequisites, and owner
baseline commit and dirty paths
files changed
contract and ABI citations
implemented behavior
explicitly deferred behavior
validation commands and results
feature and provider matrix
known blockers with named owners
commit or freeze identifier
user acceptance
```

# Exact Execution Order

Execute in this order:

Current-scope exception: entry 25 is deferred, not a dependency for entry 26
or later milestones. Its numbered slot is retained to preserve the canonical
37-entry ordering and historical traceability. All other prerequisites remain.
Within entry13, T4.14-PRE must complete and be accepted before T4.14 starts.
Entry7/8 historical V1 freezes are superseded by that amendment, not redone as
untracked steps. The numbered37-entry sequence is unchanged.

```text
1.  P0.1  Baseline the active MigTD worktree.
2.  P0.2  Freeze Firmware ABI 1.59 and ARG ABI v1.20 commands/reports.
3.  P0.3  Complete 64-byte REPORT_DATA validation.
4.  P0.4  Freeze VeniceV1 history and vectors.
5.  P0.5  Freeze host-push tenant evidence and identity lifecycle.
6.  P0.6  Freeze zero-bound additional binding and replay behavior.
7.  P0.7  Freeze key establishment; historical V1 superseded by T4.14-PRE.
8.  P0.8  Freeze acceptance/outcome contracts; V1 superseded by T4.14-PRE.
9.  P0.9  Freeze MA/Policy identity, forward policy, and collateral binding.
10. P0.11 Freeze local handoff/recovery contracts and policies.
11. P0.12A/P0.12A1 Freeze the SNP report-verifier contract, owned leaf types,
    AAS adapter boundary, and non-disruptive future TDX/common-TEE boundary.
12. P0.10 Produce migration cryptographic golden vectors against all frozen
    inputs, including handoff/recovery and the emulator supplement.
13. T4.9-T4.20 Complete and freeze Task 4 provider architecture and interface
    tests; record executable AAS conformance obligations for AAS1A-M.
14. P2.1  Complete terminology and composition cleanup.
15. P2.2  Make MigTD an atomic artifact producer and convert vm_enclave to a
    bundle-only consumer; validate builds and harness parity without claiming
    migration qualification.
16. Task 5 Remove active TDX behavior from SNP.
17. Task 6 Build Version 6 signed evidence fixtures.
18. AAS1A Complete accepted AAS Version 6 local report verification.
19. AAS1A-M Integrate the shared AAS verifier into SnpEmuAzure and
    SnpHardware; close deferred executable verifier-conformance obligations.
20. Task 7 Verify host-pushed tenant identity before V2 session-bound MA
    evidence, then activate MA evidence, policy, and collateral.
21. Task 8 Correlate tenant-to-MA binding and exchange fresh purpose-0x07 MA
    evidence before accepting tenant authorization.
22. Task 9 Implement VeniceV1 Microsoft policy.
23. Task 10 Generate/deliver one source random32 key and accept securely.
24. Task 11 Install migration information.
25. Task 12 DEFERRED: verify persisted post-install state; not a current gate.
26. Task 13 Complete integration and failure testing.
27. Task 14 Qualify the inter-node migration emulator.
28. R4.1 Build the authoritative firmware binding-state emulator.
29. R4.2 Build the two-local-Rust-process handoff model.
30. R4.3 Implement planned handoff.
31. R4.4 Complete handoff failure, retry, and crash tests.
32. R4.5 Implement and test recovery mode.
33. R4.6 Test active migration behavior during local handoff.
34. R4.7 Qualify the local rebind emulator.
35. H5.0-H5.5 Freeze production authorization contracts, resolve the AMD layout
    blocker, complete and pin the production AAS parser/adapter, then complete
    BASE, collateral, installation, bounded replay, and rebind integration.
36. P0.12B/AAS1B/H5.6 Complete production relying-party evidence and
    composite AAS integration.
37. H5.7 Perform production-image, hardware, and end-to-end qualification.
```

Implementation may begin after this plan is accepted and P0.1 records the
current worktree. Production replay-state qualification and real firmware
rebind availability do not block the migration or local-rebind emulator
milestones, but every production provider must fail closed until its Phase 5
integration is complete.
