# Q162 ARG v1.20 command addendum (P0.2)

Current authority: [Current P0.2 addendum (2026-11-02)](#current-p02-addendum-2026-11-02)
uses Firmware ABI 1.59 and ARG ABI v1.20. The 2026-10-24 body below is
preserved as historical execution evidence, including its original pending
acceptance and unresolved-decision statements. It is not the current command
or report-profile authority.

Date: 2026-10-24

Status: executed as a documentation-only correction; acceptance pending.

## Authority and scope

This is the current command matrix for the Q162 SNP MA design, provider
operation inventory, Tasks 7/8 sequences, and hardware qualification criteria.
It supersedes conflicting command assumptions in older design material,
without modifying frozen contracts or historical execution records.

Normative references checked locally:

- [ARG ABI v1.20, 2026-09-28](../../../../../Docs/ARG_ABI_v120.pdf):
  revision history; sections 4.2.1, 4.2.2, 6.2.2, 7.11-7.13, and 8.1-8.2.
  SHA-256: `15fcef80db1c38ae00738571c77ffe9971cb40fa9d6b9ed593cba0f2c58d5869`.
- [SNP Firmware ABI 1.58, May 2025](../../../../../Docs/SEV-Secure-Nested-Paging-Firmware-ABI_1.58_SEV_SNP.pdf):
  sections 7.2, 7.3 (including Table 23), and 8.32.
  SHA-256: `7f8dad86ba5111cc3e0d885fac079ff8ab8301c7baced1d99aec3f440a406d99`.
- [Revised master plan](../../q162-revised-master-execution-plan.md):
  P0.2 and its source-of-truth hierarchy.

The ABI defines firmware operations, not a Microsoft BASE/OHCL transport,
the Q162 SPDM application protocol, or the complete migration authorization
policy. This addendum selects none of those unresolved integration details.

## Current command and responsibility matrix

| Operation | Caller/target and purpose | Current reference | Q162 disposition |
|---|---|---|---|
| `MSG_REPORT_REQ` | Guest requests its own attestation report with guest-selected 64-byte REPORT_DATA | Firmware ABI 1.58 section 7.3 | MA evidence acquisition; tenant evidence only with tenant participation or an approved mechanism |
| `SNP_HV_REPORT_REQ` | Host requests a report for a target guest; host-requested REPORT_DATA is firmware-zeroed | Firmware ABI 1.58 sections 7.3/Table 23 and 8.32; ARG v1.20 section 7.11 extends allowed states | BASE acquisition/delivery remains unresolved; not a separate MA's direct guest-report call |
| Software evidence verification | MA validates report signature, certificate trust, identity, bindings, and policy | ARG v1.20 section 4.2.1 leaves MA trust/channel details implementation-defined | `SnpEvidenceVerifier`; not an ARG firmware verification command |
| `MSG_EXPORT_REQ` | Guest message for exported guest-context information, including existing migration data when valid | ARG v1.20 sections 4.2.1 and 7.13 | Not a tenant attestation-report generator and not a substitute for session-bound REPORT_DATA |
| `MSG_KEY_REQ` | Guest-derived-key service | Firmware ABI 1.58 section 7.2 | Not MSK installation or a report verifier; need, availability, and production adapter remain D-08/T4.10 work |
| `MSG_SET_MIGRATION_INFO` | Bound MA installs migration key/data/options for a guest | ARG v1.20 section 8.2 | Retained; `MigrationKeyInstaller` boundary, initially fail closed on unavailable hardware |
| `SNP_ARG_BEGIN_MIGRATION` | Host begins architectural migration after key setup | ARG v1.20 sections 4.2.2 and 6.2.2 | BASE/hypervisor responsibility, not MA evidence verification |
| `MSG_VERIFY_REPORT` | Historical operation | Removal documented in the ARG v1.20 revision history under revision 0.85 | Removed; forbidden as a current hardware dependency, provider operation, or qualification requirement |

The removal predates v1.20: it is recorded under revision 0.85
(2026-04-28). Therefore, "pre-v1.20" historical material is not automatically
a valid description of every earlier ABI revision.

Neither a mock `MSG_KEY_REQ` trace nor the existence of a firmware command
establishes production deployment support. No unavailable hardware operation
may silently select a fixture, test root, TCP emulator, TDX operation, or
success-shaped mock.

## Software-verification requirements

The following are requirements for the completed workflow, not a claim that
the current captured-fixture path already implements them:

1. Validate report encoding/profile and the report signature.
2. Validate the applicable VCEK/VLEK certificate path, issuing chain, configured
   trust anchor, certificate claims, and production freshness/revocation policy.
   Unsupported certificate/trust profiles fail explicitly.
3. Authenticate report identity, tenant identity, and tenant-to-MA REPORT_ID_MA
   binding. Host routing metadata is not cryptographic evidence.
4. Validate complete 64-byte REPORT_DATA against an independently constructed
   expected value and the approved evidence-binding classification.
5. Validate processor-aware TCB/ETCB and the accepted policy, including
   migration data and history.
6. Enforce purpose, request, role/direction, session, policy/collateral binding,
   freshness, replay protection, and legal protocol state.

For the Q162 context construction, the complete expected value is
`SHA384(canonical context) || zero[16]`. P0.3 corrects padding validation;
it does not make a captured fixture fresh. Host-requested zero-bound tenant
reports cannot silently satisfy a session-bound requirement.

These responsibilities replace any proposed reliance on the removed command.
They do not reproduce a historical local-chip firmware verification primitive.

## Corrected Tasks 7/8 sequences

### Task 7: MA evidence and collateral

Use the accepted identity lifecycle, establish SPDM/TH1, authenticate policy
identity, reconstruct the nonsecret V2 tenant/TH1 session binding and purpose6
role-specific context under the [direct-random amendment](t4.14-pre-direct-random.md),
acquire MA evidence and exact collateral through providers, and exchange the
typed records. Software verification must finish successfully for both peers
before entering `BothMaEvidenceVerified`.

There is no `MSG_VERIFY_REPORT` step and no fixture-based hardware substitute.
Runtime activation remains owned by Task 7 after its existing prerequisites.

### Task 8: tenant evidence and authorization

Acquire tenant and pending-destination evidence through the approved provider
boundaries, preserving achieved binding classification. Independently verify
signatures, collateral, identities, tenant-to-MA binding, accepted launch state,
TCB/ETCB, history, policy, and request/session state. Construct final accepted
migration data and authorization context, then return the typed result.

P0.1A/P0.1B and P0.4 remain blocked. A freshly delivered zero-bound tenant
report is not automatically session-bound. There is no removed-command gate.

## Retained installation contract: ARG v1.20 section 8.2

The installer must model the target guest context, 32-byte guest REPORT_ID,
32-byte key, 64-byte migration data, role, algorithm, and reserved-zero fields.
The supported migration algorithm is AES-256-GCM, encoded as `0x0003`.

For the bound-MA path, firmware checks MA binding, legal guest state, and
absence of an active migration session. The sending/RUNNING case requires
the matching guest REPORT_ID and sending role; the receiving/
PENDING_MIGRATION case requires receiving role and ignores the REPORT_ID
parameter. The ABI also defines a guest-self path using `PADDR_INVALID`;
this is not a replacement for the Q162 bound-MA target selection.

Preserve explicit mappings for `SUCCESS`, `INVALID_GUEST`,
`INVALID_GUEST_STATE`, and `INVALID_PARAM`. Installation must precede the
host's `SNP_ARG_BEGIN_MIGRATION`.

Firmware treats the supplied migration data as opaque; Q162 defines its
internal policy/history format. Reciprocal confirmation and Q162 authorization
are MA workflow prerequisites, not additional firmware status codes.

No ioctl number, GHCB encoding, or production backend is invented here.

## Historical supersession register

The following records are retained as history, not current command authority:

| Historical material | Superseded assumption and current interpretation |
|---|---|
| Technical Notes Q151 verifier discussion, and related Q14/Q18/Q76 flows | Any current MA verifier path relying on `MSG_VERIFY_REPORT` is superseded by this software-verification contract |
| Venice Live Migration Rev 0.52 flows | Removed-command sequences are historical; use ARG v1.20 as current authority |
| Earlier Technical Notes Task 7/8 or hardware test sequences | Do not require the removed command or report its emulation as hardware coverage |
| Earlier SNP emulator phase roadmap | The Phase 3 removed-command milestone is withdrawn; report binding and policy validation remain required |

Local historical reference:
[Technical Notes](<../../../../../Docs/AMD SEV SNP Venice Live Migration – Technical Notes.docx>),
SHA-256 `108768b02797acf665ebfc28be84ba658c334df35648440139ce3fcd463cd478`.
The original DOCX/PDF files are not edited.

## Hardware qualification criteria

Require evidence of the actual report-acquisition path, approved production
software verification/trust policy, tenant binding mechanism, real installation
requests/statuses, legal/negative firmware states, and BASE-owned migration
initiation. Record actual firmware versions, reports/collateral, traces, and
recovery behavior.

Do not require or claim execution of `MSG_VERIFY_REPORT`. Fixture signatures,
mock key operations, and software-only tests do not establish hardware
qualification. Production tenant acquisition/binding and platform integration
remain named external dependencies.

## Execution result

- Baseline: `90acaff28de9277e35a017f4b07a05003a852d1e`, with pre-existing
  dirty source/submodule changes and P0.3 work preserved.
- Added this current command matrix and historical supersession register.
- Updated the Task 4 architecture index and diagrams' explanatory text to
  reference the current command contract.
- Replaced the active emulator roadmap's removed-command milestone.
- Verified source citations against local ABI text, including the removal
  history and section 8.2 installation semantics.
- Documentation-only: no Rust, provider, wire, dependency, or runtime changes;
  no build or runtime tests needed for this step.
- No decisions made for P0.1/P0.4; no commit/push or acceptance/freeze claimed.

## Current P0.2 addendum (2026-11-02)

Status: APPROVED AND FROZEN on 2026-11-02; documentation-only implementation
and source verification complete.

Freeze identifier: `P0.2-CurrentAbi159Arg120-2026-11-02`.

User accepted and froze this contract without additional conditions.
Acceptance covers the documented command/report profile, not production
capability or resolution of the physical-layout conflict.

This versioned addendum supersedes the historical command matrix, Firmware
ABI 1.58 citations, and acquisition/binding pause statements above. It follows
the [canonical master plan](../../q162-revised-master-execution-plan.md);
execution and acceptance are recorded in
[the centralized log](../../implementation_record.log).

### Verified authority

| Source | Exact local input | SHA-256 |
|---|---|---|
| AMD SNP Firmware ABI, publication 56860, revision 1.59, August 2026 | `/home/murthy/Docs/56860_PUB_1.59_SEV_SNP.pdf` | `523d30d5728a4fdac2c5651d1031e63f7ed6020a36493dfd84dd8a550aa3cff7` |
| AMD ARG ABI v1.20 | `/home/murthy/Docs/ARG_ABI_v120.pdf` | `15fcef80db1c38ae00738571c77ffe9971cb40fa9d6b9ed593cba0f2c58d5869` |

These are the inputs actually inspected, not an assertion that a later
publication has resolved their inconsistencies. Local ABI inputs are not
copied into the repository or uploaded by this step.

### Current command, ownership, and status matrix

`MSG_REPORT_REQ` is the plan's shorthand for the Firmware ABI
`SNP_MSG_REPORT_REQ` guest message. Host firmware-command identifiers are not
SPDM VDM opcodes or Linux ioctl numbers.

| Operation | Caller and target | Authority / request and response | Required result handling |
|---|---|---|---|
| `SNP_HV_REPORT_REQ` (`0x96`) | BASE/hypervisor requests a target tenant report | Firmware 1.59 §8.33, Tables 121-122; report/response in §7.3, Tables 27/29; ARG v1.20 §7.11 extends guest states | Preserve `SUCCESS`, `INVALID_PLATFORM_STATE`, `INVALID_GUEST`, `INVALID_GUEST_STATE`, `INVALID_ADDRESS`, `INVALID_PAGE_STATE`, `INVALID_PARAM`, and `INVALID_KEY` |
| `MSG_REPORT_REQ` / `SNP_MSG_REPORT_REQ` | MA guest requests its own report | Firmware 1.59 §7.3, Tables 26-29 | Response `STATUS`: `0x00` success, `0x16` invalid parameters, `0x27` invalid key selection; validate report size and signature |
| `MSG_SET_MIGRATION_INFO` | Bound MA installs key/history for the target guest | ARG v1.20 §8.2, Tables 8-2 through 8-4 | Preserve `SUCCESS`, `INVALID_GUEST`, `INVALID_GUEST_STATE`, and `INVALID_PARAM` |
| `MSG_SET_HANDOFF_SECRET` | Each MA guest sets or clears its own secret slot | ARG v1.20 §8.3, Tables 8-5 through 8-7 | ABI lists `SUCCESS`; transport failures remain separate failures and must not be mapped to success |
| `SNP_REBIND_MA` (`0xF5`) | Hypervisor requests target-guest binding to a new local MA | ARG v1.20 §7.4, Tables 7-3/7-4 | Preserve `SUCCESS`, `BAD_MEASUREMENT`, `INVALID_ADDRESS`, `INVALID_GUEST`, `INVALID_GUEST_STATE`, `INVALID_PARAM`, `INVALID_PLATFORM_STATE`, and `POLICY_FAILURE` |
| `SNP_ARG_BEGIN_MIGRATION` | BASE/hypervisor begins source or destination migration after installation/readiness | ARG v1.20 §6.2.2, Tables 6-22/6-23 | Preserve `SUCCESS`, `ARG_NOT_ACTIVATED`, `ASID_OWNED`, `BAD_MEASUREMENT`, `DF_FLUSH_REQUIRED`, `INVALID_ADDRESS`, `INVALID_ASID`, `INVALID_CONFIG`, `INVALID_GUEST`, `INVALID_GUEST_STATE`, `INVALID_PARAM`, `POLICY_FAILURE`, `RESOURCE_BUSY`, and `RESOURCE_LIMIT` |

Adapters must retain raw firmware status and operation identity alongside
typed errors; unknown status values fail explicitly. Transport errors,
firmware rejection, software-verification failure, and policy denial are
different error domains. P0.2 adds no new Rust error enum or protocol status.
Only an authenticated and verified report may supply authorization claims.
Successful acquisition alone does not prove software verification or policy
acceptance.

### Request-layout freeze

Offsets below are byte offsets within each ABI payload. Multi-byte integers
use the ABI little-endian encoding; reserved fields remain zero. GCTX and
other physical addresses stay inside host/platform adapters; shared MA logic
uses managed handles and verified identities. No BASE transport is invented.

| Operation | Frozen request fields |
|---|---|
| `SNP_HV_REPORT_REQ` | `0x00`: `LENGTH` u32; `0x04`: `KEY_SEL` bits 1:0 with remaining bits reserved; `0x08`: `GCTX_PADDR` bits 63:12 with bits 11:0 zero; `0x10`: `HV_REPORT_PADDR` u64 |
| `SNP_MSG_REPORT_REQ` | `0x00`: `REPORT_DATA[64]`; `0x40`: `VMPL` u32; `0x44`: `KEY_SEL` bits 1:0 with remaining bits reserved; `0x48..0x5f`: reserved zero |
| `MSG_SET_MIGRATION_INFO` | `0x00`: `GCTX_PADDR` with low 12 bits reserved; `0x08`: `REPORT_ID[32]`; `0x28`: `MIGRATION_KEY[32]`; `0x48`: `MIGRATION_DATA[64]`; `0x88`: reserved u32; `0x8c`: `ALGORITHM` bits 15:0, `MIGRATION_ROLE` bit 16, bits 31:17 reserved |
| `MSG_SET_HANDOFF_SECRET` | `0x00`: `VALID` bit 0, `MODE` bit 1, bits 63:2 reserved; `0x08`: `HANDOFF_SECRET[32]` |
| `SNP_REBIND_MA` | `0x00`: target `GCTX_PADDR` bits 63:12, low 12 bits reserved; `0x08`: `NEW_MA_GCTX_PADDR` bits 63:12, bits 11:1 reserved, `MODE` bit 0 |
| `SNP_ARG_BEGIN_MIGRATION` | `0x00`: `GCTX_PADDR` bits 63:12, bits 11:2 reserved, `ENC_OPTIONS` bits 1:0; `0x08`: `INCOMING_GCTX_PADDR` u64; `0x10`: `ASID` u32; `0x14`: reserved u32 |

Both `MSG_SET_*` response payloads contain `STATUS` u32 at `0x00` and
12 reserved bytes at `0x04`. `SNP_MSG_REPORT_RSP` contains `STATUS` u32 at
`0x00`, `REPORT_SIZE` u32 at `0x04`, reserved bytes `0x08..0x1f`, then the
report at `0x20`.

Operation-specific preconditions and ownership:

- Host-push acquisition is selected: BASE obtains the tenant report; the MA
  verifies it. Firmware host reports use `VMPL = 0xffffffff` and
  `REPORT_DATA = zero[64]`. ARG §7.11 adds `PRE_COPY`, `POST_COPY`,
  `PENDING_MIGRATION`, `IMPORTING`, and `READY` to the Firmware ABI host-report
  state rules. A host routing identifier is not a verified tenant identity.
- Guest-requested MA reports use a legal `VMPL` from 0 through 3, no lower than
  the caller's VMPL. `KEY_SEL` selects default, legacy VCEK, VLEK, or
  chip-secret VCEK as specified by Firmware §7.3/§8.33. Verifier support,
  collateral, and production deployment are separate gates; unsigned reports
  cannot satisfy this plan.
- Bound-MA installation requires a legal `RUNNING` or `PENDING_MIGRATION`
  target, the correct bound MA, and no active migration session.
  `RUNNING` uses matching tenant `REPORT_ID` and `MIGRATION_ROLE = 0`;
  `PENDING_MIGRATION` uses `MIGRATION_ROLE = 1` and firmware ignores
  `REPORT_ID`. The only supported algorithm is `0x0003` (AES-256-GCM).
  The ABI guest-self `PADDR_INVALID` option is not the selected bound-MA path.
  Firmware stores opaque migration data; P0.4 defines the VeniceV1 meaning.
- Each MA has one handoff-secret slot, selected as outgoing (`MODE = 0`) or
  incoming (`MODE = 1`). `VALID = 1` installs; `VALID = 0` deletes.
  Planned handoff transfers the secret only over local encrypted SPDM;
  BASE never receives it. Clear it on success or terminal failure.
- Rebind `MODE = 0` is recovery and `MODE = 1` is planned handoff. Platform
  state must be `INIT`; target is `LAUNCH` or `RUNNING`; current and new MA
  contexts must meet the ABI `RUNNING` state checks, even when the old MA
  process is unavailable. The new MA must not itself have a bound MA.
  Planned handoff verifies matching outgoing/incoming secrets. Recovery
  verifies exact launch TCB, launch ETCB, launch mitigation vector, host data,
  and the ABI's ID-block-dependent identity/key fields. Process availability
  is not permission to bypass firmware context-state or identity checks.
- Begin-migration requires activated ARG and accepted role-specific
  installation/readiness. Sending `RUNNING` transitions to `PRE_COPY`;
  receiving `PENDING_MIGRATION` transitions to `IMPORTING`.
  Q162 uses `ENC_OPTIONS = 0` for the MA-established key; the ABI's debug-only
  fixed-key/null-cipher alternatives do not authorize a production fallback.
  Sending uses `INCOMING_GCTX_PADDR = PADDR_INVALID` and `ASID = 0`.
  Receiving supplies encrypted incoming GCTX and a valid ASID.

Retry/idempotency state machines belong to P0.6/P0.8/P0.11 and their runtime
consumers. Do not assume every firmware operation is idempotent or retry every
failure. ARG §6.2.2 explicitly permits restarting `RESOURCE_BUSY`; retries
still require correlation and legal operation state. Secret lifetimes and
zeroization remain governed by P0.7/P0.11 and T4.14.

### Version 6 signed report profile

Firmware ABI 1.59 §7.3, Table 27 defines report `VERSION = 6`, exact report
length `0x4a0` (1,184 bytes), signed body `0x000..0x29f` (672 bytes), and
signature structure `0x2a0..0x49f` (512 bytes). This freezes the published
field facts, not permission to combine conflicting layouts.

| Field | Offset | Width |
|---|---|---|
| `CURRENT_TCB` | `0x038` | 8 bytes |
| `REPORTED_TCB` | `0x180` | 8 bytes |
| `COMMITTED_TCB` | `0x1e0` | 8 bytes |
| `LAUNCH_TCB` | `0x1f0` | 8 bytes |
| `LAUNCH_MIT_VECTOR` | `0x1f8` | 8 bytes |
| `CURRENT_MIT_VECTOR` | `0x200` | 8 bytes |
| `CURRENT_ETCB` | `0x220` | 32 bytes |
| `LAUNCH_ETCB` | `0x240` | 32 bytes |
| `COMMITTED_ETCB` | `0x260` | 32 bytes |

Current platform admission consumes `CURRENT_*`; history consumes
`LAUNCH_*`; signing-key collateral uses `REPORTED_TCB`. P0.9B1 defines
policy operands; do not substitute committed or reported values for current
platform policy.

### Venice ETCB component profile

Firmware ABI 1.59 §2.4, Table 6 defines a 256-bit ETCB. The fourteen component
bytes occupy bits 111:0; bits 255:112 are reserved. Q162 Version 1 rejects
nonzero reserved components until an approved profile transition.

| Bits | Component | Byte index in little-endian ETCB |
|---|---|---|
| 111:104 | `ARG` | 13 |
| 103:96 | `DPE_DRIVER` | 12 |
| 95:88 | `FHP_DRIVER` | 11 |
| 87:80 | `ASP_OS_DRIVER` | 10 |
| 79:72 | `SOC_DRIVER` | 9 |
| 71:64 | `MICROCODE` | 8 |
| 63:56 | `TMPM` | 7 |
| 55:48 | `PRE_ESID` | 6 |
| 47:40 | `BOOT_DRIVER` | 5 |
| 39:32 | `HAD_DRIVER` | 4 |
| 31:24 | `ART_RT` | 3 |
| 23:16 | `ART_FMC` | 2 |
| 15:8 | `MP1` | 1 |
| 7:0 | `IP_KEY_MANAGER` | 0 |
| 255:112 | Reserved | 14 through 31 |

Component-wise comparisons and exact VeniceV1 history encoding belong to
P0.4/P0.9B1. This addendum does not approve the older `ArgSvnV1` projection
or eight-byte ETCB placeholder as the final Venice profile.

### Physical-layout conflict and fail-closed contract

ARG ABI v1.20 §7.12, Table 7-9 places `MIGRATION_DATA_VALID` at byte `0x48`,
bit 5 and `MIGRATION_DATA[64]` at `0x208..0x247`. Firmware ABI 1.59 Table 27
reserves byte `0x48`, bit 5 and places:

```text
CURRENT_ETCB    0x220..0x23f
LAUNCH_ETCB     0x240..0x25f
COMMITTED_ETCB  0x260..0x27f
```

The ARG migration-data span overlaps all 32 bytes of `CURRENT_ETCB` and
the first eight bytes of `LAUNCH_ETCB`. Thus no production parser may claim
to extract both logical claim groups from these conflicting physical fields
by automatic detection, caller-selected offsets, or zero/default values.

P0.12A/P0.12A1 remain authoritative: `SnpEmuAzure` uses the fixture-signed
Firmware 1.59 base report plus the signed `SnpEmulatorV1` supplement.
`SnpHardware` rejects fixture evidence and fails with
`UnsupportedVersion6Layout` or `ConflictingAbiLayout` until AMD supplies an
authoritative correction and H5.0 completes the accepted production parser
and adapter. This is PA-009, owned externally by AMD. P0.2 does not close it.

### Removed operation and completion boundary

ARG revision history records removal of `MSG_VERIFY_REPORT` under revision
0.85 (2026-04-28). It is not a current provider operation, firmware gate, or
hardware-qualification requirement. Older material is historical only;
being pre-v1.20 does not by itself make that command valid.

The whole-tree source/script/dependency scan found no executable reference to
the removed operation. Remaining documentation references explicitly describe
removal or historical supersession. Verification is software report/chain
authentication followed by MigTD binding, replay, history, and policy checks.

P0.2 completes upon source/layout consistency checks and user acceptance of
this versioned addendum. It changes no Rust source, Cargo feature, wire
registry, provider selection, or dependency revision. Later steps own codecs,
signed fixtures, common verifier implementation, installation, rebind,
durability, and hardware qualification. The historical execution results
above are retained and are not silently promoted to this freeze.
