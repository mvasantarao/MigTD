# Q162 Task 3 feasibility-audit impact review

Historical review, not the current secret-establishment decision. The
[T4.14-PRE V2 amendment](t4.14-pre-direct-random.md) supersedes contribution,
commitment, HKDF and HMAC requirements; V1 allocations/results below remain
historical and must not be reinterpreted as V2.

## Result and scope

Review completed against the available implementation, revised execution plan,
feasibility audit, and local Technical Notes reference. This is a compatibility
and implementation-readiness review, not acceptance of a revised protocol.
No Rust code, wire allocation, BASE acquisition decision, or AMD mechanism was
changed by this review.

**Disposition: retain the Task 3 V1 baseline; extend and clarify it before
activating its runtime consumers. Do not discard or silently reinterpret V1.**

P0.5 is the revised plan's contribution-record extension, not a rewrite of Task
3 or activation of the SNP runtime. It may proceed after sequence acceptance.
Unresolved identity/binding dependencies must remain explicit: a layout can
reference an agreed session context without claiming that production tenant
identity acquisition has been solved. Finalizing dependent semantics requires
the corresponding identity and context rules; it does not require guessing a
BASE or AMD design.

This report does not execute P0.5 or mark any contract accepted/frozen.

## Evidence and limitations

Repository HEAD at review: `90acaff28de9277e35a017f4b07a05003a852d1e`.
Task 3 implementation provenance:
`9a7f539` (`feat(pal/snp): freeze version 1 wire contract`).
The working tree contains prior user work and P0.2/P0.3 changes. Findings refer
to the current working tree, not a claim of a pristine checkout.

External inputs, read locally:

- `/home/murthy/Docs/q162-tasks4-14-feasibility-audit.md`, all A-01 through A-22.
  SHA-256: `3460f378ca8cbdf93090d44b14cce3ee255dc1c892935243dda6a48c49bc0372`.
- `/home/murthy/Docs/q162-revised-master-execution-plan.md`, especially
  P0.1-P0.8 and the Phase 0 gate.
  SHA-256: `9092a66b984f8873520c4cbe737363bb9e5e478176e5aac3dc4e7179b8085c5d`.
- `AMD SEV SNP Venice Live Migration - Technical Notes.docx`
  (the local filename uses an en dash), particularly Q162, Q165, and Q166.
- The prior [P0.2 command addendum](q162-arg-v120-command-addendum.md) and
  [P0.3 execution record](p0.3-step7-addendum.md).

The separately named Task 2 semantic-contract and Task 3 step/freeze Markdown
documents were not found under the available Docs or repository documentation
trees. The implementation and its freeze commit were reviewed, but independent
document-to-code certification against those absent records is not claimed.
Before accepting an amendment, reconcile its exact bytes and cryptographic
definitions with those authoritative freeze records.

## Record-by-record assessment

Paths below are relative to this report.

| Task 3 surface | Current behavior | Impact and required disposition |
|---|---|---|
| [Evidence header](../../../src/pal/src/snp/evidence_header.rs) | 32 bytes; MA/tenant evidence; explicit request, role, purpose, production/fixture and TCB profiles | Preserve V1. Production/fixture is a trust classification, not a statement of REPORTDATA binding or freshness. New record kinds need an explicit record-type allocation as well as VDM allocations. |
| [REPORTDATA context](../../../src/pal/src/snp/report_data_context.rs) | 220 bytes; tenant ID, TH1, contribution commitment, policy digest, request, role, purpose, version and algorithm | Preserve its meaning. Tenant ID must become authoritative through P0.4, not host routing. A host-requested zero-REPORTDATA tenant report does not satisfy this context's digest binding. |
| [MA evidence](../../../src/pal/src/snp/ma_evidence.rs) | 1,540 bytes; context, policy identity, collateral digest and 1,184-byte report | Preserve the layout. Raw 32-byte contributions are not present. Header/context equality, expected live context, report signature and REPORTDATA checks remain consumer obligations. The header currently admits only `MaKeyContribution` for this envelope. |
| [Tenant evidence](../../../src/pal/src/snp/tenant_evidence.rs) | 1,556 bytes; source role and `TenantMigrationAuthorization` purpose required | Preserve existing source-evidence semantics. It cannot simply be reused as destination pending evidence or post-install confirmation: current structural checks reject those header combinations. Select an explicit extension/version if needed. |
| [Policy identity](../../../src/pal/src/snp/policy_identity.rs) | 56 bytes; canonical digest envelope | No size change established. P0.7 must define authenticated policy availability, canonicalization and equality with the context digest before verification. Encoding a digest is not authenticating a policy. |
| [Tenant policy context](../../../src/pal/src/snp/tenant_policy_context.rs) | 16 bytes; TCB profile, `ArgSvnV1`, migration-data version and required-rule mask | Preserve it as an interpretation contract. It is not a codec or implementation of the 64-byte `MigrationDataV1` history. Q165 requires separate history processing and a typed adapter for complete authenticated ETCB input. |
| [Collateral set](../../../src/pal/src/snp/collateral_set.rs) | Canonical leaf VCEK/VLEK plus ASK; bounded DER, strict roles/order/count | Preserve canonical bytes and limits. P0.7 must settle whether authorization authenticates the exact verified collateral transitively through evidence digests or explicitly. No request ID inside this set is not itself a defect if its owning evidence/session binds it correctly. |
| [Authorization result](../../../src/pal/src/snp/authorization_result.rs) | 88 bytes; destination decision/failure and authorization-context digest | Preserve its purpose. It is not a confirmation tag or firmware-installation acknowledgement. Its digest must be reconstructed after verified evidence, policy and accepted history are available. |
| [VDM registry](../../../src/migtd/src/spdm/spdm_vdm.rs) and [static validation](../../../src/migtd/src/spdm/snp_vdm.rs) | Opcodes `0x20..0x25`; elements `0x0100..0x0103`; one bounded element per message | P0.5/P0.6 require additions in reserved ranges, not reuse of TDX forward/backward MSK elements. Runtime dispatcher still does not execute the new SNP exchanges. |
| [Limits](../../../src/pal/src/snp/limits.rs) and [strict wire helpers](../../../src/pal/src/snp/wire.rs) | Exact lengths, reserved-zero rules, checked sizes, trailing-byte rejection; 8,192-byte application cap | Preserve existing guarantees. Recalculate each new record and framed size. Do not consume reserved bytes or relax decoder rejection without an approved compatibility rule. |

### Important semantic distinctions

1. **Purpose enum is not an implemented workflow.**
   `PostInstallConfirmation` exists in the context enum, but neither existing
   MA nor tenant evidence envelope accepts that header purpose. Pending
   destination evidence likewise has no applicable existing destination-tenant
   envelope. These need an explicit contract, not just a new call site.
2. **Structural decoding is not evidence acceptance.**
   Current codecs validate canonical shape but do not establish equality
   between header and context request/role/purpose, policy identity and context
   digest, verified report claims and declared profiles, or the expected live
   session. Consumers must check these before authorizing or deriving keys.
   Keeping that validation outside a frozen codec is valid; omitting it from
   the eventual runtime is not.
3. **P0.3 closes the padding defect, not freshness.**
   The shared verifier now checks the expected 48-byte digest and all 16 zero
   padding bytes. The legacy fixture path still obtains its expected digest
   from the fixture report. That does not prove binding to the current TH1.
4. **Evidence digest coverage must be specified.**
   A collateral digest is present in an envelope but not directly in
   `ReportDataContextV1`. Its presence alone does not make it report-attested.
   Define the exact canonical evidence bytes covered by authorization, verify
   the collateral digest against the actual verified set, and test substitution.
5. **Session and authorization contexts have different availability.**
   Do not feed the later authorization digest back into initial MA evidence.
   P0.5 must name the exact context/reference usable at contribution exchange;
   P0.6 must state which verified context its confirmation/result binds.
6. **History is still missing implementation work.**
   Q165 retains 64 bytes, with explicit TCB/ETCB projection profiles, full
   32-byte initial MA report ID, and an eight-byte ARG-SVN projection.
   Complete authenticated 256-bit ETCB input must be validated before
   projection; unsupported nonzero components must fail, not be truncated.
   Historical minima cannot increase, mitigation continuity uses bitwise AND,
   and initial MA identity is immutable. Pending-destination accepted values
   must come from authenticated evidence, not an untrusted desired value.
   An authenticated producer/ABI adapter for those complete claims must be
   identified; a profile tag alone does not establish that input.

## Complete feasibility-audit mapping

Dispositions distinguish missing runtime work from wire incompatibility.
Plan steps below assign work; they are not a claim that it is implemented.

| Audit | Task 3 impact | Disposition / owning gate |
|---|---|---|
| A-01 Removed firmware verifier | No V1 record-layout change required | P0.2 corrects command documentation; Task 7 must use software chain/signature/claims verification. Removal predates v1.20: its history records revision 0.85. No firmware verification success may be assumed. |
| A-02 Undefined tenant acquisition | Affects provenance and availability of tenant record contents | External P0.1A decision; keep acquisition neutral and unavailable where unsupported. No invented ioctl or host-push/MA-pull choice. |
| A-03 Zero-bound host report | Current session-bound context cannot silently mean zero-bound evidence | P0.1B plus explicit binding classification/contract. A weaker scenario needs approved policy and its own truthful semantics. P0.5 must not resolve this implicitly. |
| A-04 Missing raw contributions | Existing commitment is not the contribution | P0.5: additive contribution record, registry, strict codec, vectors, failures and secret lifetime. Exactly one per role/request; authenticated peer transport only. |
| A-05 Missing confirmations/install result | Authorization result is not either record | P0.6: destination tag, source tag, destination installation result, with explicit context binding and ordering. |
| A-06 Active TDX-shaped runtime | New codecs are not yet the active SNP application protocol | P0 TDX-to-SNP replacement inventory and later Task 4/5-12 runtime integration. Preserve shared SPDM while replacing processor-specific application behavior. No broad V1 rewrite implied. |
| A-07 48/64 validation | Not a context-layout defect | P0.3 implemented the full padding check and regression coverage. Preserve it; separate fixture-session binding gap remains. |
| A-08 Tenant identity ordering | Tenant ID appears in context, commitments and later key derivation | P0.4 remains blocked on P0.1. Distinguish provisional routing ID from verified REPORT_ID. Early evidence needing different semantics requires an explicit purpose/version, not weakening V1. |
| A-09 Later pending-destination phase | Source-only tenant envelope cannot represent it unchanged | Define authenticated phase-specific evidence contract before Tasks 8/12; not a reason to relax the source-only V1 check. |
| A-10 Exact install adapter absent | Wire success must reflect actual installer result | Task 11 and P0.6 result mapping: exact target, role, 32-byte key, 64-byte history, algorithm, legal states and firmware status. P0.2 supplies the corrected command baseline, not an adapter implementation. |
| A-11 Injection incomplete | A codec can be built but bypassed by runtime | Complete Task 4 provider composition/caller injection, with typed unavailable errors. No V1 field change by itself. |
| A-12 Hardware collateral unavailable | Production collateral record cannot yet be sourced | Hardware provider dependency; do not fill it with fixture trust or label emulator success hardware qualification. |
| A-13 Codec-only records | Task 3 output exists; runtime handlers do not | Keep codec baseline; activate exchanges only in their designated runtime tasks. Static layout tests do not demonstrate dispatch. |
| A-14 Semantic validation inactive | Cross-record and live-session consistency not enforced by decoding | Task 7/8/9 consumers, with Task 13 negative integration tests. Define the validation contract before consumers, without silently changing V1 bytes. |
| A-15 Feature fallback | Production/fixture byte is insufficient isolation | Task 4 fail-closed provider and feature selection; test SNP hardware cannot select TDX/fixture implementations. No wire redesign alone fixes selection. |
| A-16 Durable state/replay/recovery missing | Request/context references need lifecycle and retry semantics | Explicit state ownership and durable recovery before Tasks 11-13 rely on install results. Distinguish authenticated message receipt from persisted installation and two-sided completion. |
| A-17 Fixture isolation | Fixture profile does not establish session binding or production trust | Task 6 trust/provenance and zero-bound/session-bound scenario classes; separate roots and negative trust-profile tests. |
| A-18 Policy availability | Context already contains a local-policy digest | P0.7: canonical bytes/authenticated identity availability before binding checks; no dummy or late-reinterpreted policy digest. |
| A-19 Collateral binding ambiguity | Evidence contains a digest; authorization coverage unspecified | P0.7: select exact transitive or explicit coverage and vectors before finalizing affected authenticated contexts. Do not choose either silently. |
| A-20 Missing cryptographic vectors | Existing byte-layout vectors are not KDF/confirmation vectors | P0.8, then Task 10 implementation: preserve frozen Task 2 construction, source/destination ordering, shared PRK-derived confirmation keys, labels and cleanup. Reconcile absent freeze records before acceptance. |
| A-21 Context-input timing | Authorization digest includes later evidence/history inputs | Freeze phase availability and avoid circular dependencies. Distinguish early session context from later authorization context in P0.5/P0.6 and runtime state. |
| A-22 Test/qualification scope | Codec coverage does not prove workflow correctness | Retain Task 3 tests; Task 13 covers state/correlation/replay/recovery; Task 14 qualifies emulator behavior only. Separate hardware gate remains. |

## Amendment and compatibility checklist

Before accepting P0.5/P0.6:

- Reconcile the authoritative Task 2/3 freeze records with the implementation
  and proposed addendum. Preserve existing V1 vectors.
- Allocate exact opcodes and elements inside the plan's reserved ranges
  (`0x26..0x2F`, `0x0104..0x010F`); allocate record type/version explicitly
  wherever the new envelope uses one. This review allocates none.
- Specify endian order, widths, total lengths, reserved bytes, maximum framed
  sizes and error mapping for every added record.
- State sender/receiver role, request and session correlation, phase,
  authenticated channel requirements, duplicate/reorder/replay behavior,
  and secret-buffer cleanup ownership.
- Decide version/capability compatibility explicitly. Existing record decoders
  reject unknown record types and unsupported versions; existing runtime
  dispatch rejects unhandled SNP opcodes. "Additive" does not mean old peers
  can execute the extension. Do not fall back to TDX key exchange.
- Identify which rules depend on P0.4/P0.7. Keep them pending or reference an
  agreed contract rather than guessing identity or digest coverage.
- Preserve the distinction between codec implementation now, runtime
  enforcement later, and hardware support still blocked.

### Required test additions by owner

| Owner | Additional verification |
|---|---|
| P0.5 | Exact contribution golden bytes, every truncation/trailing byte, wrong version/type/length/reserved bytes; commitment mismatch, role reversal, wrong request/tenant/session, duplicate contributions, and cleanup on failure in the enforcing consumer. |
| P0.6 | Exact tag/status bytes and invalid status combinations; wrong direction/tag/context, destination/source ordering, replay, timeout and partial installation at the workflow layer. |
| P0.7 | Independent policy reconstruction; authenticated collateral substitution rejected or changes the agreed authorization digest; fixture roots rejected in production. |
| P0.8 | Independent commitment, session digest, salt, PRK, MSK, both confirmation keys and both HMAC tags; mutation of request, TH1, tenant ID, policy, contributions, order and roles. |
| Tasks 7-9 / 13 | Header/context equality; signature/chain and actual report claims; full 64-byte REPORTDATA; binding classification, tenant substitution, purpose/profile mismatches, actual dispatcher behavior and transport correlation. |
| History / Tasks 11-13 | Exact 64-byte history vectors, full-ETCB projection rejection, first/later migration, immutable initial MA ID, minima/no-increase and mitigation AND, authenticated accepted destination claims, persistent readback and interrupted-install recovery. |
| Task 14 / separate hardware qualification | Emulator fixture/feature isolation and regressions separately from physical report/certificate availability, deployed ARG/PSP commands and BASE host-control behavior. |

## Recommended next disposition

1. Review/accept the revised sequence and this impact inventory; acceptance is
   still pending.
2. Execute P0.5 as an additive wire-contract task, with no runtime activation
   or implicit BASE/AMD choice. State the exact context dependency.
3. Execute P0.6 after P0.5. Complete P0.7's policy/collateral decisions before
   freezing definitions or vectors that depend on them.
4. Execute P0.8 after P0.5-P0.7.
5. Keep P0.1/P0.4 unresolved and explicitly production-blocking until their
   owners decide them; do not count zero-bound evidence as session-bound.
6. Apply the plan's Phase 0 gate and reassess Task 4 readiness. This review
   does not bypass that gate or authorize hardware tenant operation.

## Validation and result log

Read-only source review plus existing regression tests:

```bash
AS=nasm AR=llvm-ar CC=clang \
  cargo test -p pal --features snp-emu
# 102 passed; 0 failed. Doc tests: 0.

AS=nasm AR=llvm-ar CC=clang \
  cargo test -p migtd --lib --no-default-features \
  --features SnpEmuAzure spdm::snp_vdm::tests
# 5 passed; 0 failed; 58 filtered out.
```

Logs:

- [PAL test log](../../../target/task3-impact-review/pal-tests.log)
- [VDM test log](../../../target/task3-impact-review/vdm-tests.log)

Both commands passed with existing compiler warnings. These tests establish
current codec/static-framing regression status, not active evidence exchange,
session freshness, key derivation, installation, persistence, or hardware
qualification. No emulator integration run or full CI was performed for this
documentation-only review. The earlier P0.3 validation remains separately
recorded in its addendum.
