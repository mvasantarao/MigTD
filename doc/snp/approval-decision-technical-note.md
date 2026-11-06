# Technical notes: approved SNP design and implementation decisions

Date: 2026-11-04

## Current supersession: direct-random secrets

The user has now explicitly chosen source-generated random32 MSK,
independent outgoing-generated random32 handoff secret, and SPDM-protected
acceptance receipts **without application HMAC confirmations**. See
[T4.14-PRE](task4/t4.14-pre-direct-random.md) and section13 below.
Earlier contribution/commitment/HKDF/HMAC explanations and approvals are
preserved historical rationale, not current requirements. Section12's
"no replacement approval" describes the earlier impact-review state, not the
subsequent user direction. Other policy/replay/ABI and recovery requirements
remain current unless explicitly superseded.

## 1. Scope and strength of the conclusions

This note explains P0.5, P0.6, P0.7/P0.10, P0.8, P0.11, T4.10, T4.11 and T4.12.
It is analysis, not a new approval, protocol amendment or runtime activation.
The [canonical plan](../q162-revised-master-execution-plan.md) and its current
purpose-3 deferral remain authoritative.

The original complete approval-form menus are not recoverable for every
decision. The selected dispositions are preserved in the plan and
[central record](../implementation_record.log). Unless explicitly identified
as recorded, the alternatives below are reconstructed engineering alternatives,
not a claim that the user was originally offered those exact options.

"Best available" has three different meanings:

1. **Best fit for the accepted V1 constraints:** preserves the frozen contracts
   and satisfies a stated requirement without an unsupported provider.
2. **Best minimal design if starting over:** may be a simpler alternative.
3. **Proven superior:** requires a threat-model comparison, implementation
   evidence and sometimes performance/hardware data that we do not yet have.

The available evidence generally supports the first meaning, not the third.
Prior approval and the cost of changing a frozen protocol are implementation
considerations, not independent security proofs.

### Source basis

- The current local TDX implementation, not a pristine/latest Intel upstream
  snapshot: [migration session](../../src/migtd/src/migration/session.rs),
  [SPDM requester](../../src/migtd/src/spdm/spdm_req.rs),
  [SPDM responder](../../src/migtd/src/spdm/spdm_rsp.rs), and
  [rebinding](../../src/migtd/src/migration/rebinding.rs).
- User-specified ARG ABI v1.20: sections 7.4, 8.2 and 8.3.
- User-specified Firmware ABI v1.59: sections 7.2, 7.3, 8.33, report Table 27,
  and Chapter 7 protected guest messaging.
- Accepted logical contracts and their explicitly bounded test evidence.

AMD section references below are paraphrased; they do not prescribe the custom
application protocols. Existing vectors/model tests do not establish active
SPDM behavior, durable storage, OHCL integration or firmware effects.

### Decision provenance

Use this document for rationale where TDX behavior is not directly portable or
the selected design/implementation goes beyond the checked AMD PDFs. Distinguish:

- **[AMD]:** a field, operation or behavior defined by the cited ABI section.
- **[TDX]:** behavior demonstrated by the checked local TDX source; analogy
  does not transfer module guarantees or require identical SNP code.
- **[OHCL]:** an integration choice for the selected kernel/userspace layering,
  not an AMD-prescribed Linux API.
- **[DESIGN]:** an additional application contract with explicit alternatives
  and tradeoffs, not automatically a specification requirement or violation.
- **[IMPLEMENTATION]:** a representation, compatibility or tooling choice,
  not an additional security authority.
- **[SCOPE]:** an explicitly approved boundary or deferral; it does not prove
  that deferred deployment behavior works.

For each added decision, identify the problem, selected option, alternatives,
source basis, why literal TDX reuse does or does not fit, and remaining
assumptions. Approval history and scope changes remain in the append-only
central record; a rationale entry is not itself approval.

## 2. P0.5: BASE-pushed tenant evidence and package/cache/reference delivery

### Recorded choice and problem

The [P0.5 contract](../q162-revised-master-execution-plan.md#p05-freeze-host-push-tenant-evidence-and-identity-lifecycle)
selects host acquisition, inline report or SHA-384 cache reference, and no
MA-pull acquisition. The
[acceptance](../implementation_record.log:1351) is for shared contract
conformance, not a qualified host/kernel implementation.

The MA needs the tenant's authenticated REPORT_ID and relevant claims, but a
host-supplied tenant handle is only a routing identifier. It is not proof of
which firmware guest context or signed identity it denotes.

Firmware ABI section 8.33 provides a host-report acquisition mechanism. Table
27 distinguishes host reports by VMPL `0xffffffff` and zero REPORT_DATA.
Consequently, a report can be signed and useful for identity without
containing the MA's current challenge.

### Options

| Alternative | Benefit | Limitation / disposition |
|---|---|---|
| BASE acquires and pushes the report/package | Uses the layer already orchestrating the tenant and its host acquisition | Host routing remains untrusted; MA verification and lower-layer target binding are mandatory. Selected. |
| MA requests tenant evidence through a logical lower-layer API | Can give the MA an explicit acquisition workflow without exposing physical addresses | Still needs a real host/kernel service; does not by itself add a nonce to the host report. No such V1 pull contract was selected. |
| Tenant guest obtains a challenge-bearing guest report | Can bind REPORT_DATA to a fresh challenge at acquisition | Requires tenant cooperation, a guest endpoint and lifecycle handling; is a materially different acquisition model. Not the production V1 selection. |
| BASE sends only a raw REPORT_ID or opaque handle | Small/simple request | Unauthenticated identity cannot authorize migration. Rejected as an authority source. |
| Always inline the full evidence | Simplest ownership and fewer cache failure cases | More repeated bytes; still a valid simplification if cache complexity is unjustified. |
| Inline or exact content-addressed reference | Supports retry/deduplication while retaining byte identity | Needs explicit cache ownership, misses, lifetime and substitution checks. Selected. |

### Why copying TDX literally does not solve this boundary

TDX gives MigTD target-bound module access using a binding handle and target
UUID. For example, [read_msk](../../src/migtd/src/migration/session.rs:1282)
reads the target's module-owned key, and the requester reads
[SERVTD_EXT](../../src/migtd/src/spdm/spdm_req.rs:536) through module access.
Its policy/initial-TD-information path is technology-specific; it is not an
implementation of an SNP host-report package service.

The reusable TDX idea is **host routing followed by independent trusted
checks**. A TDX UUID, TDCS field or SERVTD authorization cannot simply become an
SNP REPORT_ID, GCTX address or evidence-provider guarantee.

### Why the selected option is a good current fit

- BASE/lower-layer acquisition does not require adding a cooperative service
  to every tenant guest.
- The MA receives bytes or a reference, but only a verified receipt promotes
  provisional routing identity into an authenticated identity.
- Acquisition, verification and migration authorization remain separate.
- Content addressing makes an exact retry identifiable without trusting the
  host's cache label. The original base report is 1,184 bytes; its SHA-384
  reference is 48 bytes, excluding framing. This is a byte-count comparison,
  not a measured latency or throughput result.

There are two distinct digest scopes. P0.5's base-report cache reference
identifies that report only. P0.6 binds complete evidence, including separately
authenticated emulator supplements where applicable. T4.9's
[TenantEvidencePackage](../../src/pal/src/snp/tenant_source.rs:75) additionally
owns evidence and collateral; construction of that package is not verification.
A base-report cache hit authenticates neither a supplement nor collateral.

### OHCL implications and residual conditions

The MA should pass logical handles and approved logical operands, not own
GCTX_PADDR allocation/resolution. The actual lower-layer interface must
establish access, target lifetime, stale-handle rejection, request correlation,
protected messaging and secret-buffer ownership.

This ownership split is the selected OHCL architecture, not an AMD-specified
Linux API. The supplied OpenVMM checkout is userspace/OpenHCL source; its
[guide](../../../openvmm/Guide/src/dev_guide/getting_started/build_ohcl_kernel.md)
points to a separate kernel repository. An exact kernel patch is not yet
established. [PA-008](../snp-production-readiness.md#pa-008) tracks that gap.

**Assessment:** BASE push is the best-supported acquisition fit under the
chosen no-tenant-cooperation/no-MA-pull V1 scope. Cache references are useful
but optional; current data does not establish that they outperform an
inline-only design. Host push alone provides neither session freshness nor
current firmware binding.

## 3. P0.6: purpose-2 association, exact context and durable replay journal

### Recorded choice and problem

The [accepted P0.6 contract](../q162-revised-master-execution-plan.md#p06-freeze-zero-bound-tenant-report-operation-binding)
explicitly does not require first-use freshness of the host report. Instead,
fresh MA evidence binds the complete verified tenant evidence to the current
operation, with trusted replay state and current firmware revalidation.

A genuine signed host report can be replayed. A matching REPORT_ID also does
not prove that an old REPORT_ID_MA value is the current binding. These are
different questions from signature verification.

### Options

| Alternative | What it provides | Why it was not the selected complete solution |
|---|---|---|
| Accept signed tenant evidence plus fresh SPDM alone | Authentic report and fresh protected channel | Does not itself define tenant/report-to-operation authorization or restart-persistent consumption rules. |
| Require a fresh challenge in a tenant guest report | Direct report-level freshness | Changes P0.5's acquisition model and requires guest cooperation. |
| Bind tenant evidence into the initial purpose-1 proof | Potentially avoids another hardware-evidence round | Viable in a redesigned context; existing purpose-1 encoding/commitment dependencies were already frozen. Not intrinsically insecure or ruled out by AMD. |
| Send an authenticated application authorization statement | Can bind the same operation fields using the authenticated peer channel | Potentially simpler if the assurance model trusts measured MA code and channel ownership sufficiently; not the accepted evidence contract. |
| Separate fresh purpose-2 MA evidence | Explicit attestable statement after tenant/source-MA correlation | Selected; costs extra evidence generation, exchange, verification and scheduling. |
| In-memory duplicate table | Cheap operation-local replay handling | Loses terminal history across restart and cannot meet the accepted durable-replay requirement. |
| Firmware state alone | Hardware enforcement of current state and bound MA | Valuable and mandatory, but no checked ABI contract establishes all application request/journal/terminal semantics. |
| Durable authenticated state with rollback resistance | Carries accepted replay decisions across restart/handoff | Selected; substantial provider, anchor, recovery and retention obligations remain. |

### Exact association and what it establishes

The [421-byte encoder](../../src/pal/src/snp/tenant_authorization.rs:107)
canonically binds:

- version, request ID, migration version, algorithm and roles;
- verified tenant REPORT_ID and complete-evidence digest;
- current TH1 and both authenticated MA REPORT_IDs;
- both MA/Policy identity digests and both purpose-1 commitments.

The source tenant's REPORT_ID_MA must match the authenticated source MA
REPORT_ID. Both peers reconstruct the context, then verify the source and
destination purpose-2 proofs; merely repeating a received digest is insufficient.

Fresh MA evidence over these fields says that this MA produced that
REPORT_DATA in this session. It does **not** make the older tenant report fresh,
prove that a host handle maps to that tenant, or independently query current
firmware binding. The trusted application and firmware provider must establish
those facts separately.

### TDX comparison

TDX already has attested peer/session binding plus target-bound module access.
Those are useful patterns. The checked path does not implement this specific
host-zero-report bootstrap, purpose-2 round and cross-restart consumption
journal. Its module guarantees cannot be imported as an SNP journal.

Conversely, TDX's absence of an extra round does not prove that the round is
necessary for SNP. A redesigned initial proof or authenticated application
statement could be adequate under an explicitly approved assurance model.

### Why the selected option is defensible, and its cost

Purpose-2 was a coherent incremental fit: verify the tenant first, verify the
source MA, check their signed association, then attest the complete joined
context without changing frozen purpose-1 records or introducing hash cycles.
The exact length has no special security value; canonical, complete and
independently reconstructed fields do.

The [journal contract](../../src/pal/src/tenant_replay.rs:140) uses
Reserved -> Authorized -> Terminal states, atomic revision-checked persistence,
authenticated reload and an independent rollback-resistant anchor. Missing
or ambiguous state fails closed; authorization/retry rechecks current firmware.
A MACed or sealed file alone does not detect restoration of an older valid file.
Guest-to-firmware VMPCK sequence numbers protect that message channel, not this
entire distributed workflow across restarts.

The current [conflict policy](../../src/pal/src/tenant_replay.rs:287) treats
reuse of a request ID or complete-evidence digest by a different binding as a
conflict, including after a terminal result. This is stronger than AMD's ABI.
It can require refreshed evidence for a legitimate new workflow; capacity,
terminal retention and any future safe reclamation policy need explicit
deployment treatment, not silent journal reset.

**Assessment:** a durable anti-rollback mechanism is the best fit **if** the
accepted cross-restart replay semantics remain a requirement and no qualified
existing platform authority supplies them. The separate purpose-2 round is
the least disruptive fit to frozen V1, not proven the minimal or uniquely best
security design. Production anchor/storage and authoritative-state providers
are still unqualified.

## 4. P0.7/P0.10: two contributions, commitments, HKDF and HMAC

### Recorded choice and the actual TDX mismatch

[P0.7](../q162-revised-master-execution-plan.md#p07-freeze-secret-contribution-key-establishment)
selects contributions rather than application ECDH.
[P0.10](../q162-revised-master-execution-plan.md#p010-produce-migration-cryptographic-golden-vectors)
records a newly approved exact recipe because the original Task 2 formula and
its acceptance were not recovered. That replacement authority must not be
presented as an AMD recipe or recovered historical choice.

TDX [reads MIG_ENC_KEY](../../src/migtd/src/migration/session.rs:1282) from the
module and [writes the peer's MIG_DEC_KEY](../../src/migtd/src/migration/session.rs:1297).
It does not derive one shared migration key using this application protocol.
ARG section 8.2 instead accepts a caller-supplied 32-byte migration key.
It does not identify a corresponding module-generated key-read operation.
MSG_KEY_REQ is a different derived-key service.

### Options

| Alternative | Advantages | Tradeoff / evidence available |
|---|---|---|
| Copy TDX's module-key-read operation | Minimal application key generation when hardware owns that key | No corresponding SNP migration-key-read contract established in the checked ABI. Not directly portable. |
| One MA generates MSK32 and sends it through authenticated encrypted SPDM | Simple; compatible with ARG's supplied-key model | One endpoint selects the key; does not satisfy the accepted bilateral-contribution design goal. A technically viable alternative if that goal is relaxed. |
| Derive an application key from a qualified SPDM exporter | Reuses the existing authenticated key agreement | Requires an approved exporter/API, context separation and lifecycle contract. None has been established here; exporter availability is not disproved. |
| Add application ECDH | Separate application agreement with standard primitives | Extra ephemeral keys, validation, attestation binding and integration on top of SPDM's existing ECDHE; not automatically better. |
| Two fresh contributions without precommitment | Both endpoints contribute entropy | The later sender can choose after observing the earlier secret; may still suffice under a different trust model. |
| Commit both contributions in evidence, reveal inside SPDM, then HKDF | Pins each contribution before disclosure and retains bilateral input | Selected; extra records, evidence dependencies and custom protocol review burden. |
| Use MSG_KEY_REQ output as the shared MSK | Hardware-rooted derivation can serve some separately designed purposes | Does not by itself establish the same fresh session key at both peers or satisfy the accepted contribution recipe. |

### What the selected recipe actually does

Each role generates a fresh 32-byte CSPRNG secret. Its commitment is:

```text
SHA384("SNP-LM-CONTRIBUTION-v1" || ctx0[220] || role_secret[32])
```

`ctx0` is that role's canonical purpose-1 context with only the commitment
slot zeroed. The commitment is inserted before generating purpose-1 evidence.
Both commitments are authenticated before the secret-exchange phase. Each
received secret must be checked against its authenticated commitment.

After authorization, both peers reconstruct the exact accepted 799-byte
session context: P0.6 association, complete MA evidence, tenant collateral,
history, trust/evidence interpretation, profiles and actual approval records.

```text
D = SHA384(canonical_session_context[799])
salt = SHA384("SNP-LM-HKDF-SALT-v1" || D)
PRK = HKDF-Extract-SHA384(salt, source_secret || destination_secret)
MSK32 = HKDF-Expand-SHA384(PRK, "SNP-LM-MSK-v1" || D, 32)
```

Separate source/destination confirmation keys expand from PRK with the
accepted distinct labels, not from MSK32.

### Reasons for this choice

1. Fresh contributions avoid treating a stable identity-bound key as an
   automatically fresh migration key.
2. Fixed source/destination order avoids endpoint-relative concatenation.
3. Commit-before-reveal prevents changing a contribution after learning its
   peer's secret without breaking the authenticated commitment.
4. Standard HKDF extract/expand is preferable to inventing a hash-concatenation
   KDF; labels separate MSK and confirmation uses.
5. Session context makes evidence, policy, history and role disagreements
   affect derived outputs rather than relying solely on routing metadata.

These are engineering arguments, not a formal proof of this whole protocol.
An unpredictable contribution can supply entropy under the usual HKDF
assumptions, but both MAs eventually know both secrets. A compromised endpoint
is not excluded from the final key. Commitments do not repair weak randomness.
The scheme also does not create an independent secrecy layer against later
disclosure of the protected contribution exchange.

The [Rust reference](../../src/pal/src/snp/crypto_vectors.rs:5) and independent
137-entry corpus establish byte-for-byte construction agreement and tested
negative cases, not comparative security superiority or a live implementation.

**Assessment:** the selected recipe is a defensible fit **if bilateral entropy,
attested precommitment and frozen V1 contexts are retained requirements**.
If the requirement is only "establish a fresh shared MSK through authenticated
SPDM," the evidence does not establish that it is better than a one-generator
scheme or a properly qualified exporter. That additional goal deserves
explicit review rather than being attributed to AMD or TDX.

## 5. P0.8: directional confirmations, record formats and ordering

### Options and TDX context

| Alternative | Benefit | Limitation |
|---|---|---|
| Rely on SPDM FINISH alone | Already authenticates establishment of the SPDM session | FINISH occurs before application migration-key exchange in the checked TDX flow; it does not confirm later application HKDF/context results. |
| Rely on authenticated application request/response | Simpler; resembles TDX's protected migration-info exchange | Can carry adequate acknowledgements, but without an additional derived-key check does not explicitly detect independently reconstructed PRK/context disagreement. |
| One confirmation direction | Fewer records | Does not provide both endpoints an explicit peer confirmation. |
| Two confirmations using the same key/context | Bilateral derived-key check | Needs careful direction/type separation to avoid interpreting a tag in the wrong role. |
| Two direction-separated confirmations and typed install result | Explicit application agreement and effect reporting | Selected; more state and final SPDM scheduling work. |

The TDX requester performs
[FINISH before EXCHANGE_MIGRATION_INFO](../../src/migtd/src/spdm/spdm_req.rs:201).
The responder
[writes the peer key before preparing its reply](../../src/migtd/src/spdm/spdm_rsp.rs:936).
Thus TDX does have a useful protected application-result pattern. It does not
have this two-contribution application KDF whose independent results need
checking. "TDX lacks the right context" applies to that difference, not to
authenticated acknowledgements in general.

### Selected construction and reasons

The accepted records are 128-byte confirmations and a 136-byte destination
installation result. Tags are HMAC-SHA384 under direction-specific PRK-derived
keys over a canonical confirmation with its tag slot zeroed, prefixed with the
accepted confirmation domain. The record includes local request/session
reference, sender role/direction and status.

These choices provide:

- explicit agreement on the application derivation context and confirmation
  key, not merely agreement on the SPDM traffic keys;
- direction/type separation against accidental cross-role interpretation;
- one unambiguous canonical encoding rather than compiler-dependent layout;
- typed success, failure, abort and indeterminate outcomes, with raw firmware
  status presence distinguished from a genuine observed zero.

The accepted logical order is destination confirmation, source confirmation,
then destination installation result. Destination-first is a deterministic
protocol convention that prevents both peers waiting to receive first. It
matches the broader receiver-before-sender readiness intent, but neither AMD
nor the checked TDX path requires that exact tag order. Source-first or another
correctly scheduled exchange could also work.

The byte counts and registry numbers are interoperability allocations, not
security optima. Logical order still needs a legal SPDM request/response or
polling schedule; unsolicited extra responses cannot be assumed valid.

### Important limits and current deferral

A successful tag confirms the matching confirmation key/context. With a
correct implementation of the common recipe, that supports agreement on the
intended MSK. It is not a direct check of actual firmware-installed MSK bytes.
Even an MSK expansion bug could escape a confirmation-key check if the
confirmation branch remains correct.

Neither a tag nor a peer's success statement is fresh hardware persistence
evidence. The fresh post-install purpose-3 exchange is currently **deferred**.
The historical
[confirmation controller](../../src/pal/src/snp/confirmation.rs:402) still has
an AwaitingPersistedState transition; it must be explicitly reconciled before
activation, not satisfied with fake evidence or an invented success receipt.

**Assessment:** explicit confirmation is a reasonable defense for retaining
the custom application KDF and independently rebuilt context. Its necessity
is conditional on that design; it is not an additional AMD requirement.
Separate direction keys are sound separation practice. Exact order/lengths
are defensible conventions, not demonstrated uniquely best choices.

## 6. P0.11: local codecs, HKDF, serial lifecycle, retry and partial ownership

### Hardware facts versus application lifecycle

ARG section 7.4 defines per-tenant rebind operations:

- planned handoff checks matching outgoing/incoming MA secrets;
- recovery checks the specified identity and launch-state equivalence;
- firmware checks target and MA guest-context states and changes the binding.

Section 8.3 provides **one secret slot per MA guest**, used in incoming or
outgoing mode, accepting a 32-byte secret and allowing deletion. It is not a
per-operation/per-tenant batch transaction interface.

The [recorded lifecycle approval](../implementation_record.log:2775) selects
serial rebinding, split ownership after partial success, retry only after
authoritative unchanged-state appraisal, and no rollback/secret persistence/
live-session resume. Authenticated 32-byte MA REPORT_IDs were separately
[selected as HKDF operands](../implementation_record.log:2779).

### Subdecision A: local codecs

Options are raw firmware/UAPI structures end-to-end, reuse inter-node records
unchanged, introduce typed local logical records, or keep orchestration wholly
inside a single trusted process with no new application wire.

Typed local records were selected: the SNP-MA-L namespace has twelve bounded
kinds and records up to 512 bytes; the SNP-MA-M metadata descriptor has at most
32 canonical tenant entries and a 6,420-byte maximum. It describes evidence,
history and replay-state packages without carrying secrets or live sessions.
These sizes are frozen V1 scope limits, not AMD limits.

This isolates control-plane decoding and planned/recovery roles from kernel
addresses and firmware ABI layout. TDX also uses typed host messages and
application records, so the **pattern suits** the choice. Its exact record
contents do not cover the selected SNP multi-tenant/replay metadata.

The codecs are logical contracts, not an implemented OHCL ioctl or final
transport. Reusing an existing confirmed interface could reduce integration
work; we must not invent a second kernel protocol solely to match these types.

### Subdecision B: handoff-secret derivation

| Option | Evaluation |
|---|---|
| Fresh random32 secret, protected transfer | Directly fits AMD's operand; closely resembles TDX's fresh random rebind token. A strong simpler alternative. |
| Fresh random seed plus context-bound HKDF | Selected; domain separation and explicit binding in application key construction. |
| Reuse MSK/SPDM traffic key or persist a long-lived handoff secret | Mixes purposes/lifetimes or expands secret exposure; no selected need. |
| MSG_KEY_REQ-derived handoff secret | Needs a separately approved derivation/lifetime contract and protected agreement; unnecessary for the selected fresh-secret flow. |

V1 hashes the handoff ID, authenticated old/new REPORT_IDs, tenant-set digest
and verified policy digest under its handoff domain, then uses that context as
HKDF-SHA384 salt, fresh random32 as input, a separate handoff-secret label,
and 32-byte output. The old MA sends the result only over the authenticated
encrypted local peer session; both MA slots must be cleared on applicable
terminal/cleanup paths.

TDX [create_rebind_token](../../src/migtd/src/migration/rebinding.rs:475)
already generates random32. Therefore **TDX's random-token choice does suit
the secret-generation need**; HKDF is not forced by a hardware incompatibility.
HKDF adds application domain/context separation but no additional entropy.
Its retained use is reasonable for frozen V1, not proven superior to random32
with equally strong authenticated operation binding.

Firmware compares secret values and modes; it does not parse the HKDF context
or enforce a tenant allowlist encoded in the application's digest.

### Subdecision C: serial versus parallel effects

Options are serial per-tenant rebind, controlled parallel rebinds for one
reserved MA pair, or an imagined atomic batch.

Serial is selected because it minimizes simultaneously ambiguous effects and
simplifies canonical result sets, retries and cleanup. It is a sound first
implementation without measured throughput requirements or a qualified
concurrency model. The checked ABI does not supply an all-tenants atomic
transaction.

One MA secret slot makes conflicting MA-level operations require reservation.
It does **not** by itself prove that firmware forbids parallel tenant rebinds
under one stable pair/secret. Serial is a conservative software policy, not a
hardware-mandated scheduling theorem.

Effect scope remains an important condition: the matching slots authorize the
MA pair at firmware level, not the application's entire exact tenant inventory.
HKDF context binding and serial software dispatch alone do not prove that
only approved tenants can be affected. A real integration must qualify target
scope, inventory and MA-slot reservation under the accepted authority model.

### Subdecision D: partial ownership and retry

| Option | Consequence |
|---|---|
| Pretend the batch was all-or-nothing | Inconsistent with per-tenant committed effects. |
| Automatically reverse successful rebinds | Requires separately authorized reverse operations and qualified failure semantics; not an assumed rollback primitive. |
| Retry every timeout/failure | Can repeat an operation whose result was lost after a real effect. |
| Preserve observed successes and reconcile uncertain/failed tenants | Selected; tracks actual ownership rather than desired batch outcome. |

The chosen behavior is:

1. Confirm a known success as belonging to incoming; never reissue it as a new
   move on retry.
2. Leave a failed tenant assigned to outgoing only after authoritative
   unchanged-binding/history appraisal.
3. Mark unknown effects ReconciliationRequired; do not infer "no effect"
   from transport timeout.
4. Retry only an authorized, qualified status under the same operation,
   snapshot/epoch and next attempt, with fresh required appraisal/evidence.
5. Keep the production retry whitelist empty until statuses/effects are
   qualified. The framework's ability to model retry is not retry permission.

This is the strongest part of the choice: it aligns application state with
per-tenant hardware effects. A durable journal supports recovery but does not
turn multiple firmware operations into an atomic transaction.

### Why the TDX handoff is not a complete replacement

TDX provides a directly useful precedent: policy-gated protected token
exchange, replacement token recording and the old MigTD's
[target-bound approval](../../src/migtd/src/migration/rebinding.rs:439).
The checked path is not a complete multi-tenant shutdown, metadata/journal
transfer or partial-reconciliation implementation.

SNP recovery is additionally not that live-old-MigTD exchange. It can lack a
live old MA process/peer session, but ARG still requires the relevant old/new
MA **guest contexts** to satisfy its RUNNING-state checks. Recovery is not
permission to rebind an arbitrary destroyed or decommissioned old context.
It uses firmware identity/launch equivalence, not a handoff-secret fallback.

**Assessment:** typed logical boundaries and serial, state-reconciled effects
are the best-supported conservative implementation under current evidence.
Exact codecs/limits and the HKDF recipe remain optional design choices.
Production authority/effect scope, durable metadata, cleanup, status mapping
and actual kernel/firmware integration are still required; an unavailable
provider or logical test cannot qualify them.

## 7. T4.10: empty active derived-key operation set and unavailable interface

### Recorded choice and options

The [T4.10 approval](../implementation_record.log:3297) explicitly selects no
active V1 platform-derived-key operation. This means no mandatory
MSG_KEY_REQ call in this workflow, not "SNP has no keys" or "MSG_KEY_REQ is
obsolete."

| Option | Evaluation |
|---|---|
| Mandatory MSG_KEY_REQ as generic preparation | No specified purpose/output consumer; introduces a false prerequisite and unqualified key scope. |
| Implement a new root-derived MSK/handoff recipe | Changes accepted cryptography and needs new scope/lifetime/agreement analysis. |
| Keep a success-only mock preparation call | Misrepresents an unavailable effect and teaches tests to expect a fictitious requirement. |
| Remove the runtime requirement; keep legacy API explicitly unavailable | Selected; truthful capability boundary with limited compatibility churn. |
| Remove the trait/API entirely | Reasonable eventual cleanup once remaining compatibility consumers/interfaces are deliberately retired. |

Firmware section 7.2 defines root-derived guest keys with selected identity,
TCB and related inputs. A derived key may be useful for sealing or another
separately designed service. Merely invoking it does not establish a fresh,
shared migration key on two platforms.

ARG section 8.2 consumes an already supplied migration key and does not
require an earlier MSG_KEY_REQ. Chapter 7's VMPCK-protected firmware channel
already has its own provisioned keys and message sequencing; eliminating the
unused application derived-key call does not eliminate that protection.

### Why TDX's key read must not be copied as this service

TDX's key read retrieves migration-specific state from the target TDCS. SNP
MSG_KEY_REQ derives a guest key with a different purpose and binding model.
Calling both "platform key preparation" obscures a real semantic difference.

P0.10 consumes fresh contributions and P0.11 consumes a fresh random seed.
Neither current recipe consumes MSG_KEY_REQ output. Without a real consumer
there is no sound basis to choose root, purpose, scope, lifetime or recovery
semantics for such an operation.

The retained [UnavailablePlatformKeyProvider](../../src/pal/src/traits.rs:62)
returns `PalError::NotAvailable` if a legacy caller invokes it. The normal V1
flow no longer calls it or requires it in the provider set. It is an error,
not a successful no-op. Tests rejecting MSG_KEY_REQ traces ensure the removed
prerequisite is not silently reintroduced into the bounded legacy workflows.

**Assessment:** this is the clearest minimal choice supported by the data:
do not invent or simulate an unused key operation. The compatibility trait
could later be removed explicitly. Future sealing/replay-store requirements
may justify a separately scoped derived-key service; T4.10 neither approves
nor rules out that future need. Real MSK installation remains separate.

## 8. T4.11: typed migration-key and history installation boundary

### Accepted scope and source of authority

The [canonical T4.11 contract](../q162-revised-master-execution-plan.md#t411-migration-key-and-history-installer)
was explicitly approved and its bounded implementation accepted on
2026-11-04 at 16:35:15 UTC, conditions None. Completion identifier:
`T4.11-TypedInstallerConformance-2026-11-04`.
The [central acceptance](../implementation_record.log:3820) distinguishes
that acceptance from runtime activation and hardware qualification.

**[AMD]** ARG section 8.2 defines installation of a supplied 32-byte MSK,
64-byte opaque migration data, REPORT_ID, role and algorithm 0x0003, subject
to bound-MA and firmware-state checks. **[TDX]** the corresponding architectural
precedent is target-bound
[write_msk](../../src/migtd/src/migration/session.rs:1297), not the SNP request
format or its policy/history semantics.

The approved boundary is
[`SnpMigrationKeyInstaller`](../../src/pal/src/snp/migration_install.rs).
It takes a validated borrowed logical request and returns correlated local
completion or an explicit failure/effect observation. The alternatives below
explain that selection; they are not claims of separate user approvals.

### A. Separate typed API rather than a fabricated legacy adapter

**[DESIGN / IMPLEMENTATION]** Alternatives were to extend the legacy trait in
place, introduce a SNP-specific interface while preserving the old caller,
or adapt the old call by filling absent fields. The second was selected.

The legacy `set_migration_info(context, &[u8])` call has no verified tenant,
admitted history, complete session reference or authorization input. Defaults
cannot manufacture those facts. The new request therefore borrows the existing
`SnpOperationContext`, `VerifiedTenantIdentity`,
`VerifiedTenantAuthorizationV1` and `SnpSessionReferenceV1`, plus MSK32 and
history64. It checks all operation fields against authorization, the tenant
identity, session request ID, algorithm and exact history encoding.

TDX's direct module write is a useful narrow-effects pattern, but cannot supply
these SNP application operands. Keeping the old trait/mock/runtime separate
preserves working legacy behavior without falsely claiming it implements the
new workflow. Caller migration remains later work, not an automatic adapter.

### B. Reuse existing proof types without inventing another authority

**[DESIGN]** A new sealed "installation authorized" hierarchy was considered
as an alternative to reusing existing types and explicit orchestration
prerequisites. The approved bounded scope selects reuse.

The existing purpose-2 authorization type proves its documented role-proof
scope only. The session reference is data that the caller must reconstruct
from the accepted P0.10 recipe; its presence does not verify its digest.
No new session hash or token format is introduced by this installer.

Policy approval, exact-history admission, durable replay/current-firmware
authorization and reciprocal confirmations remain caller prerequisites.
Providers independently enforce current target/state conditions. Constructor
success cannot replace those checks. This avoids an additional proof framework
without weakening the required workflow, provided later composition actually
enforces the documented prerequisites. That composition is still unqualified.

### C. Logical handles, exact operands and role-specific REPORT_ID

**[AMD / OHCL / DESIGN]** The MA-facing API uses a managed handle. Kernel/lower
layers own physical guest-context resolution, buffers, protected invocation
and firmware encoding. Passing raw GCTX_PADDR through the MA was rejected as
the selected architectural ownership model, not as an AMD prohibition.

TDX's binding handle/target UUID illustrates target-bound access, but its
TDCS fields and access controls are not an SNP implementation. The actual
OHCL contract still needs confirmation; no ioctl number or kernel patch was
invented in T4.11.

For source, the logical firmware REPORT_ID operand is the verified tenant ID.
For destination, ARG says the operand is ignored: returning zero[32] is an
application canonicalization choice, not a requirement that firmware reject a
nonzero destination operand. The logical correlation still retains the
verified tenant identity on both sides.

**[AMD / DESIGN]** The 32/64-byte widths come from ARG. The VeniceV1 meaning
inside those 64 bytes comes from P0.4, not AMD. The installer uses the existing
decoder to check canonical shape and forwards every byte unchanged. Computing
minima, changing initial-MA identity or admitting peer-proposed history here
would mix policy evaluation with effects and risk installing a different
history from the one already agreed.

### D. Borrowed secrets and explicit local correlation

**[IMPLEMENTATION / TDX]** Alternatives included owned/cloned secret buffers
or a borrowed fixed-width key. T4.11 selects a non-cloneable borrowed request.
The TDX key type's zeroizing ownership is useful precedent, but need not be
copied as a second key owner in this interface.

The request cannot outlive its borrowed key, and its Debug representation
redacts key, identity, authorization, history and session material. The caller
still owns zeroization; providers must clear any copies they create for the
kernel/transport. Borrowing does not prove register/compiler erasure or make
downstream copies disappear.

Local outcomes retain the full operation, verified tenant ID and existing
session reference. This is diagnostic/caller correlation, not new cryptographic
proof. Callers must compare it before advancement. Error correlation is boxed
to avoid the observed 168-byte large-error return diagnostic while preserving
all fields. That error-path allocation is a Rust representation choice, not an
AMD requirement, TDX difference or security improvement.

### E. Completion, raw status and uncertain effects

**[AMD / DESIGN]** Alternatives were a bare boolean/`Result<()>`, a new
attested persistence receipt, or typed local completion/error observation.
The approved choice is the third.

Only an observed raw firmware status zero can construct local completion.
The constructor trusts its provider's observation; it is not an attestation
verifier and does not prove that a test provider invoked firmware. Completion
does not reuse a P0.8 wire record or claim independently attested persistence.
This follows the useful TDX distinction between a platform-call result and
an additional attestation protocol.

Errors distinguish unavailability, firmware rejection, transport failure,
observed partial installation and indeterminate effects. Optional raw status
preserves "not observed" versus zero versus nonzero. Effects are NotApplied,
Partial or Unknown; partial/unknown require reconciliation and no error
authorizes success.

Shared AMD INVALID_GUEST/INVALID_GUEST_STATE statuses cannot by themselves
uniquely identify bound-MA versus REPORT_ID, or lifecycle versus active-session
failure. No unsupported diagnostic precision or numeric mapping is invented.
Current nonzero raw statuses conservatively retain Unknown effects pending a
qualified mapping; this is stricter than treating every declared precondition
failure as ambiguous after its exact semantics have been established.

A transport failure is NotApplied only if the provider actually knows no
effect occurred. A lost response after submission is not that evidence.
Neither TDX's multi-field write loop nor a timeout establishes SNP atomicity
or retry safety. This interface performs no automatic retry.

### F. Unavailable implementation, not a success-only stand-in

**[SCOPE / IMPLEMENTATION]** Alternatives were real stateful emulation or
OHCL integration now, a success-only mock, or an explicit unavailable provider
plus unit-test conformance doubles. The last was approved for this milestone.

`UnavailableMigrationKeyInstallerV1` returns a correlated unavailable error
without effects, for either role and explicit repeat calls. It is suitable
where either emulator or hardware support is absent, not a claim that the
eventual emulator should remain unavailable. Test-only recording/failure
injection verifies the interface but is not a stateful platform implementation.
The legacy success-only mock remains isolated in the old workflow, not selected
as the new provider.

**[SCOPE / AMD / TDX]** The user-deferred fresh purpose-3 exchange is not added
back as an installation success gate. Checked TDX key-install completion does
not require that fresh exchange, and ARG section 8.2 does not mandate it.
The historical P0.8 controller still requires explicit reconciliation before
activation; no fake persistence verifier satisfies that work.

### Evidence and remaining conditions

The accepted evidence includes 16 new unit tests and two compile-fail tests;
PAL default 27/5, TAV 335/18, Azure 336/18; separate emulator 7 and MigTD 66;
format/lint/build checks, Stage A/B legacy regressions and the unchanged
137-entry P0.10 oracle. Final-source and acceptance preservation manifests
are recorded centrally. These validate the bounded implementation, not the
comparative superiority of every API choice.

**Assessment:** a narrow, typed, fail-closed boundary is the best-supported
incremental fit without a confirmed OHCL API or activated SNP workflow.
Borrowing, a separate trait, canonical destination zero and boxed correlation
are reasonable implementation choices, not uniquely required designs.
Actual provider composition, policy/replay/confirmation scheduling, P0.8
reconciliation, stateful emulator behavior, firmware effect/status mapping,
OHCL/kernel support and hardware qualification remain open.

## 9. T4.12: correlated host control and separate binding effects

### Authority and scope

The user explicitly approved the bounded A-E contract
`T4.12-CorrelatedHostControlAndBindingV1` on 2026-11-04. The first form returned
only "None"; that was not treated as approval. A follow-up boolean returned
true. The [canonical contract](../q162-revised-master-execution-plan.md#t412-host-control-and-ma-binding-interfaces)
contains exact framing, assignments and lifecycle rules. Approval of that
contract is distinct from implementation acceptance and hardware qualification.
The bounded implementation was separately accepted at 2026-11-04T17:41:29Z,
completion `T4.12-HostControlBindingConformance-2026-11-04`, with downstream
gates retained and no additional conditions supplied. This is not hardware
or production-provider acceptance.

### A. Separate logical protocol versus extending legacy TCP payloads

**[TDX / DESIGN / OHCL]** Checked TDX
[host dispatch](../../src/migtd/src/migration/session.rs:349) and
[status reporting](../../src/migtd/src/migration/session.rs:731) provide the
command/result layering precedent. They do not define BASE/SNP tenant evidence,
profiles, local handoff or a GHCB ABI.

Options were to extend the existing TDX-shaped TCP payload, define a separate
SNP logical frame and adapt transports later, or prematurely specify a new
kernel ioctl/GHCB operation. The second avoids accidental legacy reinterpretation
and unsupported external API claims. `SnpHostControlTransportV1` carries logical
frames; a production adapter must still use the confirmed kernel/BASE path,
including GHCB handling where applicable. A Rust trait is not a kernel bypass.
The existing emulator TCP path remains unchanged, not a production substitute.

**[IMPLEMENTATION]** Versioned magic, little-endian fields, strict exact lengths,
reserved-zero validation, explicit option-presence bits and a 65,536-byte cap
are application framing choices. The cap accommodates complete tenant plus
two MA packages without imposing the separate 8,192-byte SPDM cap on local
host delivery. They are not AMD-required byte layouts. The large local-control
enum variant is boxed to avoid a measured Clippy large-enum warning; this is
representation, not an additional security property.

### B. Whole-package association without redefining base references

**[DESIGN / IMPLEMENTATION]** A base-report hash alone does not identify its
supplement, supplement signature and collateral association. Options were
silently redefining the old reference, requiring every retry to push everything,
or retaining SHA384(base report) and separately binding the exact versioned
package. T4.12 selects the third.

Inline delivery carries the complete package. Reference delivery resolves only
an already BASE-pushed local package and checks both digests. Source and
destination MA profiles also carry full existing report/supplement/signature/
collateral bytes, rather than only selected identity fields. These bytes and
hashes confer no authority: the existing verifier must promote tenant identity,
and later composition must appraise complete MA profiles, policy and actual
session bindings. Host-provided profiles cannot select roots or REPORT_DATA.
The package hash is association, not a new attestation or freshness mechanism.

### C. Pre-proof reservation closes a different restart gap from P0.6

**[DESIGN]** Options were relying only on the accepted P0.6 journal, allowing
fresh startup whenever that journal lacked a record, or tracking pre-proof
operation reservations separately. P0.6 cannot reserve a verified binding
until purpose1 proves both MAs; manufacturing one at host-request receipt
would contradict that accepted boundary.

The selected `HostControlContextAuthorityV1` therefore reserves the complete
logical operation durably before any peer session is started. An existing
pre-proof reservation requires reconciliation even if P0.6 is empty.
Authenticated P0.6 terminal results are queryable without re-running proofs;
restored active operations do not reconstruct keys or silently replace SPDM.
Missing/unprovisioned context is an error, never a new empty journal.

This added state is needed by the selected cross-restart semantics, not by an
AMD-specified storage protocol. TDX does not supply a directly reusable SNP
pre-proof tombstone service. The provider must qualify integrity, independent
rollback anchoring, bounded retention, conflict checking and durable reservation
under [PA-011](../snp-production-readiness.md#pa-011). No production store is
implemented here. Tests explicitly use trusted-interface doubles.

**[DESIGN / SCOPE]** Before a verified P0.6 binding exists, cancellation records
an authenticated durable abort through the pre-proof context authority, not a
fabricated verified replay binding. After verified reservation, cancellation
uses the existing P0.6 journal. A pre-proof terminal record cannot claim
migration success. After installation starts, cancellation requires
reconciliation, not an assertion that effects were undone. All terminal
acknowledgements require durable success; ambiguous writes stop advancement.
Broader lifecycle/recovery composition remains downstream work.

### D. Reconcile P0.8 without fabricating persistence verification

**[DESIGN / SCOPE / TDX]** The historical P0.8 controller requires actual fresh
purpose3 evidence before a persisted-state success receipt. Options were
faking that verifier, changing the frozen success field's meaning, or retaining
the historical API inactive and introducing a distinctly named completion
observation. Only the third respects both frozen records and the user's
later deferral.

`FirmwareCompletionRecordV1` carries role/session, local firmware outcome,
effect classification and optional raw status. It has no persisted-state
digest. It is not `SnpInstallationResultV1`, an authorization record or a
hardware persistence proof. Local conversion validates the complete existing
T4.11 correlation; cross-node delivery uses the frozen P0.10 session reference.
No new session digest hierarchy is introduced.

TDX's target-bound module write/result is the architectural precedent for a
trusted MA reporting platform completion without a fresh attestation exchange.
It does not prove SNP atomicity, effects after transport loss or retry safety.
Partial/unknown effects remain indeterminate and raw status remains available.
Neither confirmation nor a host acknowledgement proves actual installation.

### E. Three correlated request/response exchanges

**[DESIGN / IMPLEMENTATION]** Three logical records cannot simply be emitted as
unsolicited SPDM responses. Alternatives include polling, more complex async
delivery, or changing the requester/responder relationship. The bounded schedule
keeps source as requester: poll/destination tag, source tag/destination
completion, then source completion/correlated acknowledgement.

This preserves destination-then-source confirmation order and allows destination
installation only after the source tag is verified. Source installation also
requires the destination completion response. Explicit pending-request/session
checks reject unsolicited, duplicate, reordered and cross-session records.
New 0x28-0x2D opcodes and 0x0107-0x0108 elements are additive; frozen records and
local P0.11 namespaces are not repurposed.

The numeric assignments, poll/ack formats and three-pair choice are application
decisions, not requirements from AMD or literal TDX wire behavior. This is a
simple fit to the existing SPDM request/response model, not proof it is uniquely
best. Later tasks must wire real transport, actual HMAC verification, keys,
policy and cleanup. Private scheduling receipts attest only to this controller's
checks with the injected verifier, not live-session authority.

### F. Binding effects remain separate from host intent

**[AMD / DESIGN / OHCL]** ARG planned/recovery rebind and handoff-slot semantics
are the underlying operations. `MaBindingManagerV1` is the selected logical
provider boundary, not an AMD Linux API. Passing raw GCTX addresses or treating
BASE's proposed result as authoritative was not selected.

Rebind requests reuse Ready P0.11 contracts, exact binding and tenant membership.
Providers must recheck current authority, method/mode, target resolution,
secret-slot/effect scope and firmware recovery equivalence. Protected set-secret
requests borrow/redact plaintext; they have no host-control codec. Recovery
does not gain an old-process/proof/session/secret requirement.

Unavailable providers make missing support explicit. They are preferable to
success-only stand-ins but do not implement authoritative emulator state or
kernel firmware effects. Real APIs, transport behavior, status/effect mapping,
buffer safety, cleanup and hardware tests remain
[PA-007/PA-008 obligations](../snp-production-readiness.md#pa-007-t412-ohclbase-host-control-integration-actions).

## 10. T4.13: purpose-separated peer-channel boundary

### Authority and scope

The user explicitly approved `T4.13-PurposeSeparatedPeerBoundaryV1` A-E,
recorded 2026-11-04T18:01:40Z. Approval is of bounded interface/conformance work,
not production transport, crypto/policy composition or hardware. The bounded
implementation was separately accepted at 2026-11-04T18:25:34Z, completion
`T4.13-PeerChannelConformance-2026-11-04`, with downstream gates retained
and no additional conditions supplied.

### Transport reuse versus typed isolation

Options were to reuse an unrestricted transport/SPDM context directly, add one
untyped session with a purpose flag, or expose distinct migration/local-handoff
application owners over a shared trusted backend. The third is selected:
it retains transport reuse while making crossed application uses unrepresentable
through the public typed methods and rejecting crossed packets at runtime.

TDX supplies actual
[feature-selected setup/close](../../src/migtd/src/migration/transport.rs),
[migration SPDM establishment](../../src/migtd/src/spdm/spdm_req.rs) and
[separate rebind orchestration](../../src/migtd/src/spdm/spdm_rebind.rs).
Those are layering precedents, not evidence that TDX already has these two SNP
types. Their Rust names, factory API and exact isolation mechanism are DESIGN,
not dictated by the cited AMD firmware ABI. A single rigorously checked tagged
session could also work; separate types make accidental cross-use harder.

### Establishment versus application authority

Options were to treat a connected transport as trusted, accept a caller's
claimed TH1/authenticated flag, or separate evidence bootstrap from typed
application promotion. The third is selected. The trusted backend must expose
the actual encrypted SPDM engine session/TH1. The boundary replaces template
TH1, borrows existing verified local/peer MA and LM-policy objects, matches exact
contexts/policy digests and invokes current selected admission before promotion
and around application I/O. Local old/new REPORT_IDs are correlated as well.

TDX's [TH1 context construction](../../src/migtd/src/spdm/mod.rs#L212)
is relevant precedent. SNP must retain its own report-data preimages, roles
and evidence verification, not TDX offsets/TDREPORT/quote assumptions. This is
not new attestation: the backend/policy verifier remain trusted authorities.
Fixed/ordered-release pair admission, expiry and full local binding reconstruction
must be qualified there; test-only policy callbacks prove none of that.
Explicit encrypted bootstrap is this contract's requirement, not a claim that
the legacy TDX handshake has identical ordering or security properties.

### Frozen messages versus invented local wire reuse

Inter-node framing retains the accepted 0.0 application header, one element,
existing 0x20-0x2D allocations, exact record codecs and 8 KiB limit. One registry
lookup is shared by the boundary and MigTD's static validator. The alternative
of copying mappings into another dispatcher was rejected to avoid drift.
Contribution and secret buffers own zeroizing storage and redact diagnostics.

Local metadata and 32-byte secret operations are logical protected records.
Assigning them invented inter-node tags or sending the secret in a host-control
record was rejected. Actual local framing/scheduling remains explicitly open.
Planned secret transfer is outgoing-to-incoming and prepare-stage only.
P0.11 recovery remains incoming-only; no fictitious old-MA proof/session/secret
is introduced. AMD firmware semantics constrain the effects; these software
records, SPDM selection and scheduling are application design.

The P0.10 session-context digest is not SPDM TH1 or its numeric session ID.
It is supplied once by trusted orchestration for T4.12 confirmation/completion
correlation. Structural checks do not verify HMACs, purpose2 admission,
contribution commitments or installation ordering; their controllers still do.
Fresh purpose3 stays deferred, and frozen historical P0.8 success is unchanged.

### Failure, deadlines and production obligations

Options included transparent reconnect/retry or terminating a failed owner.
The latter is selected because a replacement live session cannot recover lost
secrets or override anchored operation/replay decisions. One outstanding
inter-node request fixes the expected paired response; no full migration state
machine is duplicated. Absolute trusted time is checked around operations,
including clock rollback. Actual I/O must honor its deadline internally:
checking before/after cannot interrupt a blocking backend.

Primary and abort-cleanup failures are retained separately; cleanup uncertainty
requires reconciliation. Drop attempts channel abort and logs failure, but
does not attest cleanup or clear firmware slots. These lifecycle choices are
conservative DESIGN/IMPLEMENTATION decisions, not AMD-specified Rust behavior.
Real SPDM, routing/UAPI, local wire design, current policy composition,
cancellation, erasure and restart evidence remain
[PA-007 peer obligations](../snp-production-readiness.md#pa-007-t413-peer-channel-qualification-actions).
Kernel changes cannot be specified honestly before actual API-gap inspection.

<a id="10-consolidated-conclusion-and-evidence-that-could-change-it"></a>

## 11. Consolidated conclusion and evidence that could change it

| Decision | Current conclusion | Evidence/design input still needed |
|---|---|---|
| P0.5 push | Best fit for selected host-owned acquisition; cache optional | Actual OHCL acquisition/routing API, cache ownership, full-profile verification and freshness policy |
| P0.6 association/replay | Coherent frozen-V1 design; separate evidence round not uniquely necessary | Explicit need for hardware quote versus authenticated statement, qualified current-state provider, durable anchor/retention/recovery design |
| P0.7/P0.10 MSK | Defensible if bilateral contribution/precommitment is a real requirement | Comparative threat model against one-generator/exporter alternatives and runtime cryptographic/protocol review |
| P0.8 confirmation | Reasonable with custom KDF; exact record/order conventional | T4.12 defines current-scope scheduling without the historical purpose3 success path; live derivation/confirmation and activation remain open |
| P0.11 lifecycle | Serial partial-effect reconciliation strongly justified | Kernel/firmware effect scope, slot reservations, ownership observations, status qualification and cleanup |
| P0.11 HKDF/codecs | Reasonable retained conventions, not uniquely best | Need for exact local wire/API, bounds and context-derived secret beyond random32 |
| T4.10 | Strongest minimal justification: no unused key preparation | A real future consumer would require a new purpose-scoped contract |
| T4.11 | Accepted typed boundary; no fabricated authorization or platform effects | Real provider/caller composition, P0.8 reconciliation, stateful emulation and qualified OHCL/kernel/effect mapping |
| T4.12 | Accepted bounded framing/lifecycle, separate completion schedule and binding boundary | Anchored pre-proof/replay storage, actual SPDM/HMAC composition, kernel/BASE APIs and hardware qualification |
| T4.13 | Accepted bounded purpose-separated channel/authority conformance | Real encrypted SPDM, current fixed/ordered admission, local wire framing, actual routing/UAPI, cancellation/erasure and restart qualification |

No evidence here supports saying that all selected designs are uniquely best,
or that all departures from TDX are forced by SNP. Several are deliberate
additional assurance or conservative integration choices. Their advantages,
costs and unresolved assumptions must remain visible when deciding whether
to retain or simplify them.

No accepted choice is silently revoked by this assessment. T4.11's bounded
interface/conformance implementation is accepted; runtime and hardware gates
remain open. Fresh inter-node purpose-3 evidence remains deferred.

## 12. Impact review: single-generator MSK and direct-random handoff secret

### 12.1 Status, scope and conclusion

Review date: 2026-11-04. User request: "complete the impact review".
This is a completed dependency/design impact review, NOT approval of a
replacement protocol. P0.3/P0.6/P0.7/P0.8/P0.10/P0.11 and T4.9-T4.13
acceptances retain their existing scope. No source, frozen encoding, vector,
runtime selection or production gate is changed by this review. T4.14 has
not started. Earlier explanations and acceptance evidence remain historical
authority until an explicit amendment supersedes the affected portions.

The candidate under review is:

- Source MA generates a fresh 32-byte MSK using a trusted CSPRNG and sends
  that same MSK over the authorized encrypted inter-node SPDM session.
  Both sides install the same key and approved history with their own roles.
- Outgoing MA independently generates a fresh random32 planned-handoff
  secret, transfers it through the authorized encrypted local peer session,
  and both sides install their respective firmware secret slots.
- Recovery remains incoming-only, without an old-MA secret or peer session.

Conclusion: technically compatible with the reviewed AMD supplied-secret
interfaces and simpler than bilateral contribution/HKDF generation. It is
not a drop-in replacement for the accepted V1 protocol. Handoff generation
is a localized change; migration generation has cross-contract effects.
Most evidence, policy, replay, installer and channel architecture remains
reusable, but its dependent contexts, receipts and tests need reconciliation.
No defensible percentage of code reuse or engineering effort follows from
counting completed milestones or matching source lines.

### 12.2 Checked AMD/TDX basis and what is not established

Reviewed supplied documents: ARG ABI v1.20 sections 3.3.2, 3.3.3, 8.2 and
8.3, and Firmware ABI v1.59 Chapter 7 / section 7.2. These are paraphrased:

- ARG 8.2 accepts a 256-bit migration-key operand, 64-byte migration data
  and algorithm 0x0003. The sender and receiver have different role/state
  checks; source REPORT_ID and bound-MA checks remain. It does not prescribe
  the reviewed two-contribution, commitment, HKDF or confirmation-key recipe.
  Compatibility with this operand is not end-to-end migration qualification.
- ARG 3.3.2 explicitly describes an old MA creating/installing its outgoing
  secret, establishing trust in a new MA, securely transferring the secret,
  and the new MA installing that same incoming value. ARG 8.3 supplies one
  256-bit incoming/outgoing slot per MA guest and deletion through VALID=0.
  It does not prescribe the P0.11 context-bound HKDF construction.
- ARG 3.3.3 recovery depends on firmware identity/launch equivalence checks,
  not a session or secret obtained from an unavailable old MA.
- Firmware ABI Chapter 7's VMPCK/sequence/AEAD protection is the guest-to-PSP
  channel, not the MA-to-MA SPDM channel. Section 7.2 derived-key service
  does not itself specify agreement on an inter-node migration key.
- TDX [read_msk](../../src/migtd/src/migration/session.rs:1282) reads a
  module key; it is not precedent for a software CSPRNG-generated common MSK.
  TDX [create_rebind_token](../../src/migtd/src/migration/rebinding.rs:475)
  is direct random32 generation precedent for the proposed handoff secret.
  TDX [MigrationSessionKey](../../src/migtd/src/migration/data.rs:206)
  remains useful zeroizing-storage precedent.

These observations support the simpler designs as candidates; they do not
prove that a connected SPDM transport has authorized peers, correct tenant/
history inputs, successful firmware effects or qualified failure recovery.

### 12.3 Assurances retained, relinquished and separately undecided

Retain mutual evidence/policy appraisal tied to actual current SPDM TH1;
verified complete tenant evidence; purpose2 authorization; approved byte-exact
history; durable replay/current-state admission; role-correct firmware calls;
correlated outcomes, partial/unknown-effect reconciliation and secret cleanup.
Generate independent migration and handoff secrets; never reuse an MSK,
SPDM traffic key or handoff secret for another purpose. A retry in the same
authorized operation must not silently regenerate/replace a key or occupied
handoff slot. Restart/session loss retains fail-closed reconciliation rules.

The migration candidate relinquishes bilateral entropy/key-selection input
and precommitment against adaptive contribution selection. It trusts the
source's randomness and generation policy. The destination cannot establish
unbiased generation from a received random-looking key. Both schemes expose
the final MSK to both participating MAs; bilateral construction does not stop
a compromised MA from leaking it or intentionally failing migration.

Removing handoff HKDF relinquishes derivation-level context/domain binding,
not the required authenticated binding of transfer and slot use to the exact
operation, MA identities, tenant set, policy, epoch, attempt and deadline.
Fresh independent random32 can provide the secret without adding entropy
through HKDF; its lifecycle still must prohibit conflicting slot reuse.

Key confirmation is a SEPARATE choice:

| Candidate | What it provides / costs |
|---|---|
| Explicit application key confirmation | Can test possession/agreement on the same key and context. Existing V1 tags require PRK-derived directional keys; deleting PRK requires a newly approved separated confirmation recipe, not automatic reuse of MSK as an HMAC key. Less protocol reordering may be possible, but exact V1 crypto cannot remain unchanged. |
| SPDM-protected delivery/acceptance receipt plus installation outcomes | Simplest candidate if explicit key-possession proof is not required. Receiver explicitly acknowledges accepting the protected key/context. This is not a cryptographic proof that it retained or installed that key; firmware outcomes and uncertainty remain separately tracked. Requires new receipts/admission rules and changes to T4.12, not an always-success confirmation verifier. |

Recommendation: review the second as the simplicity baseline, subject to an
explicit decision accepting the loss of application key-possession assurance.
If that assurance is required, retain it deliberately with a reviewed recipe.
No choice is selected here. Do not send plaintext keys or public fixture-style
key fingerprints in host control, durable journals or logs.

### 12.4 Accepted-contract impact matrix

| Surface | Disposition if the candidate is approved |
|---|---|
| P0.1/P0.2 baseline and AMD command freeze | Retain history and ABI facts; capture a new implementation baseline, not a retroactive rewrite. |
| P0.3 / Task 2-3 evidence and wire contracts | Amend contribution-purpose semantics and exact purpose-binding construction. The existing purpose1 name/commitment slot cannot silently become an unbound zero or MSK-delivery digest. Review domain/profile/version discrimination and reject incompatible peers. The 64-byte REPORT_DATA mechanism, roles and TH1 binding remain. |
| P0.4 Venice history and P0.5/T4.9 BASE evidence delivery | Retain history computation/admission and complete tenant package/cache/reference rules. Update only dependent proof fixtures/callers. Key simplification does not solve the raw Version 6 layout blocker. |
| P0.6 tenant association and replay | Keep both-role authorization, source REPORT_ID_MA checks, complete-evidence correlation and anchored journal/state machine. Its exact 421-byte authorization encoding currently includes BOTH commitment digests, so a replacement preimage/proof constructor is required. Existing authorization/replay digests change; version their meaning and deny historical-context reinterpretation or empty-journal restart. |
| P0.7 contribution protocol | Supersede active bilateral contribution generation, commitment verifier, pair receipt and request/response semantics with single-generator key delivery/acceptance. Preserve old frozen definitions/tests as historical or explicitly isolated legacy evidence, not the selected new protocol. |
| P0.8 / T4.12 confirmation admission | Explicit confirmation versus protected receipt is unresolved. Existing confirmed-session receipts gate installation and cannot be bypassed. Preserve typed firmware outcomes and unknown/partial handling; revise receipts/order only under the selected new contract. Historical purpose3 codecs/controller remain inactive and purpose3 stays deferred. |
| P0.9 MA/Policy and P0.12A/A1 verifier contracts | Retain trust roots, signature/report checks, identity/policy appraisal, fixed/ordered-release and shared verifier layering. Regenerate only evidence/fixtures affected by new contexts. If canonical signed policy semantics change, reassess/re-sign the policy and its identity digest; do not assume unchanged release authorization covers changed policy bytes. |
| P0.10 crypto recipe and vectors | Supersede bilateral commitments, source/destination IKM, PRK/MSK expansion and dependent confirmation values. Replace the exact 799-byte session recipe or explicitly version its revised inputs. Keep a locally reconstructed operation/session context even without HKDF: it binds key delivery, accepted evidence, history, approvals, interpretation and outcomes. |
| P0.11 handoff generation | Replace seed-plus-HKDF output with direct CSPRNG random32. Retain the protected owner/sink, first-attempt/Prepared guards, same-secret retry discipline, single-slot serialization, metadata, planned/recovery separation, two-slot cleanup and shutdown/inventory gates. Version the recipe change; wire changes are not inherently required for an unchanged secret operand. |
| T4.10 platform-key disposition | Remains empty/unavailable: neither random32 candidate requires MSG_KEY_REQ. |
| T4.11 typed installer | MSK32/history64/role/algorithm and correlated errors remain compatible. Update authorization/session fixtures and recipe documentation; the installer must not acquire key-generation responsibility. |
| T4.12 host/binding interfaces | Preserve secret-free host framing, pre-proof tombstones, durable authorization and terminal/reconciliation rules; binding-manager secret operands remain32. Revise install-entry and success receipts if confirmations change. Existing acceptance is not evidence that the revised sequence passed. |
| T4.13 peer boundary | Preserve purpose-separated owners, actual current TH1/evidence/policy promotion, bounded I/O, deadline and cleanup. Amend contribution-specific frames/validators/shared registry and session-reference assumptions. Planned local random32 fits its existing typed secret transfer; actual local wire support remains unqualified. |
| T4.14 onward / Tasks 7-11 | Update RNG/secret inventory and generation timing; Task 7 no longer precommits two secrets, Task 8 retains authorization, Task 10 becomes authorized MSK delivery with the approved receipt/confirmation, Task 11 retains actual role-correct effects. T4.17-20 revalidate/audit/freeze the changed surfaces. |
| Phase 4 / Phase 5 and production ledger | Keep planned/recovery/stateful-emulator and hardware obligations. Amend recipe-specific PA-007-PEER-04 and related references after approval; do not close kernel, policy, slot-cleanup, erasure or durability actions because generation is simpler. |

### 12.5 Concrete source, fixture and documentation footprint

The following inventory distinguishes direct logic changes from dependent
fixture changes. It is not a claim that every file needs wholesale replacement.

| Files / symbols | Change or retained use |
|---|---|
| [key_contribution.rs](../../src/pal/src/snp/key_contribution.rs), [contribution_exchange.rs](../../src/pal/src/snp/contribution_exchange.rs) | Replace active contribution codec/state/pair semantics; no reinterpretation of contribution bytes as the final MSK. Retain useful zeroizing ownership/error patterns. |
| [tenant_authorization.rs](../../src/pal/src/snp/tenant_authorization.rs:67) | Replace contribution-specific proof prerequisites and the two commitment inputs to authorization; preserve verified provenance and private capability constructors. Replay receipts must reflect the new accepted context. |
| [report_data_context.rs](../../src/pal/src/snp/report_data_context.rs), [purpose_binding.rs](../../src/pal/src/snp/purpose_binding.rs) | Review exact evidence-purpose/domain/binding definitions; keep local/recovery and history preimages unless the approved scope explicitly changes them. |
| [confirmation.rs](../../src/pal/src/snp/confirmation.rs:312), [control_exchange.rs](../../src/pal/src/snp/control_exchange.rs:276), [host_control.rs](../../src/pal/src/snp/host_control.rs:708) | Existing verifier contract is specifically P0.10 HMAC; install-entry requires its private verified receipt. Choose and implement replacement authority/order, never a fake verifier or fabricated receipt. |
| [peer_channel.rs](../../src/pal/src/snp/peer_channel.rs:496), [spdm_vdm.rs](../../src/migtd/src/spdm/spdm_vdm.rs), [snp_vdm.rs](../../src/migtd/src/spdm/snp_vdm.rs), [evidence_header.rs](../../src/pal/src/snp/evidence_header.rs), [limits.rs](../../src/pal/src/snp/limits.rs) | Review allocation/version strategy and coherent parser/length/type dispatch. Shared registry lookup must change together with new codecs/tests; old opcodes/tags remain reserved with their old meaning unless explicitly amended. |
| [local_handoff.rs](../../src/pal/src/snp/local_handoff.rs:816), [local_handoff_tests.rs](../../src/pal/src/snp/local_handoff_tests.rs:1035) | Replace HKDF generation and its exact vector with direct-random pass-through/error tests; preserve lifecycle and sink/cleanup checks. RNG interface naming may change from seed to secret output without changing firmware operands. |
| [migration_install.rs](../../src/pal/src/snp/migration_install.rs:70), [binding_manager.rs](../../src/pal/src/snp/binding_manager.rs:120), [tenant_replay.rs](../../src/pal/src/tenant_replay.rs) | Core operand/effect/ownership interfaces reusable. Revalidate new authorization/session constructors, durable compatibility and no-repeat-effects behavior. |
| [crypto_vectors.rs](../../src/pal/src/snp/crypto_vectors.rs), [p010_vectors.py](../../sh_script/test/p010_vectors.py), [vector corpus](../../src/pal/src/snp/test_data/p010_vectors.txt) | Preserve original deterministic evidence; produce a separately versioned corpus/reference for the selected replacement. Keep independent identity/policy/history/verification coverage, not just delete tests that mention contributions. |
| [ma_policy_tests.rs](../../src/pal/src/snp/ma_policy_tests.rs), [ordered_collateral_tests.rs](../../src/pal/src/snp/ordered_collateral_tests.rs), [property_tests.rs](../../src/pal/src/snp/property_tests.rs), [golden_vectors.rs](../../src/pal/src/snp/golden_vectors.rs), [migration_install_tests.rs](../../src/pal/src/snp/migration_install_tests.rs), [peer tests](../../src/pal/src/snp/peer_channel/tests.rs), [host tests](../../src/pal/src/snp/host_control/tests.rs), [tenant-source tests](../../src/pal/src/snp/tenant_source/tests.rs), [control tests](../../src/pal/src/snp/control_exchange/tests.rs) | Adapt affected contexts/builders/vectors/admission assertions. Evidence/authorization record unit fixtures also need review in their own modules. Re-sign generated test evidence if signed bytes change; never edit a captured AMD report and call it authentic. |
| [wire addendum](task4/p0.5-contribution-wire-addendum.md), [canonical plan](../q162-revised-master-execution-plan.md), [Task 4 architecture](task4/README.md), [production ledger](../snp-production-readiness.md), this note and [central log](../implementation_record.log) | Add an explicit supersession/mapping, update active consumers and future task gates, preserve earlier approval and validation history. No need to invent a new top-level milestone or renumber the37-entry sequence. |

The traced bilateral reference calculations are test-only
([test module](../../src/pal/src/snp/ma_policy.rs:858) and its nested
[reference tests](../../src/pal/src/snp/ma_policy_tests.rs:24)).
T4.12/T4.13 have bounded interfaces/controllers, not a production-activated
replacement migration protocol. The legacy
[write_msk path](../../src/migtd/src/migration/session.rs:1297) still has
TDX-shaped/mock behavior. Therefore this is contract/code/test rework before
new-protocol runtime activation, NOT rollback of a qualified deployed protocol.
Passing legacy Stage A/B cannot validate the new key-delivery design.

### 12.6 Replacement decisions required before implementation

1. **Entropy authority:** approve source-only MSK generation and outgoing-only
   independent random32 handoff generation; explicitly relinquish bilateral
   entropy/precommitment and derivation-level handoff context binding.
2. **Evidence and context:** specify replacement purpose1 binding, exact
   authorization/session preimages and authenticated protocol discrimination.
   Retain tenant/history/approval association without a hash cycle. No zeros
   in old commitment fields as an implicit downgrade.
3. **Receipt/confirmation:** choose explicit application key confirmation with
   a new reviewed separated-key recipe, or protected receipt with its narrower
   claim. Freeze installation ordering and typed negative/unknown outcomes.
4. **Wire compatibility:** specify new version/profile/records and allocation
   policy, requester/responder agreement and rejection of old/new mismatches.
   No automatic fallback to whichever protocol a peer requests. Exact numbers
   and bytes must be reviewed, not assigned by this impact review.
5. **Timing and retries:** recommend generating/delivering MSK only after
   tenant/peer/policy/history and durable authorization are accepted. Bind
   receipt to exact current session/context. Freeze duplicates, timeouts,
   session loss, partial installation and retained-secret ownership; never
   generate a replacement key to make an uncertain operation look fresh.
6. **Amendment scope:** approve superseding the identified parts of accepted
   contracts and their test evidence, while retaining unrelated accepted work
   and the current purpose3 deferral. Handoff and migration amendments can be
   approved independently; one does not authorize the other.

The first decision is not implied by asking for this review. There is no
selected new profile, byte layout, confirmation recipe or runtime activation.

### 12.7 Required implementation sequence and acceptance evidence

After explicit replacement approval:

1. Capture the full dirty-worktree baseline; append supersession authority
   and exact old-to-new contract mapping. Do not reset prior work or delete
   approval history.
2. Amend evidence/context and wire definitions first; keep old definitions
   historical/isolated and incompatible runtime messages fail-closed.
3. Implement source-generated key delivery and separately the approved handoff
   random32 change with existing private authorization/secret-owner patterns.
4. Reconcile confirmation/receipt controllers, T4.12 install/success admission,
   T4.13 validators and all dependent replay/session/evidence fixtures together.
5. Validate independent new vectors and both directions; malformed/version/
   role/session/tenant/history substitutions; unauthorized/early key delivery;
   duplicate/out-of-order/timeout/cancel/restart; RNG failure; key replacement;
   first-attempt handoff, same-slot retry and partial/unknown effects; redaction,
   ownership/cleanup and absence of deterministic production RNG selection.
6. Run targeted PAL default/TAV/Azure, emulator and serial MigTD tests, affected
   compile-fail tests, formatting/Clippy, TDX compatibility and rebuilt sequential
   legacy Stage A/B. New protocol execution needs its own real composition
   tests; legacy success is only preservation. Retain full CI/pre-push and
   actual production/hardware gates.
7. Record results and separate acceptance; only then resume T4.14 against
   the amended contracts. Do not claim cryptographic/provider/hardware
   qualification from codec or state-machine tests.

This review itself changes documentation only; no source tests were rerun
and no new behavior was validated. Preservation checks cover all source/test
files, prior central-log prefix, canonical sequence and Git HEAD.

## 13. T4.14-PRE direct-random supersession, 2026-11-04

**Recorded direction:** replace source/destination contributions and derived
MSK with one fresh source random32; replace outgoing handoff seed/HKDF with
independent direct random32. **Separately selected:** protected delivery
acceptance, removing application HMAC confirmations. This supersedes the
generation/confirmation recommendations in sections4/6/12, not historical
approval or validation facts.

The simpler design trusts source randomness/key selection and gives up
bilateral entropy/precommitment and explicit application key-possession
assurance. Context remains authenticated by actual encrypted SPDM and fresh
MA evidence. A receipt acknowledges key/context acceptance, not retention,
firmware success or attested persistence. Both role-specific firmware outcomes,
policy, exact history, tenant/source-MA association, durable replay and
partial/unknown-effect reconciliation remain necessary.

The [replacement contract](task4/t4.14-pre-direct-random.md) specifies purpose6/7,
commitment-free325-byte authorization,703-byte nonsecret session recipe,
distinct0x30-0x35 scheduling and private channel-minted receipts. These are
application choices, not AMD-required labels or a claim that TDX uses a single
software-generated shared migration key. Old allocations cannot be reused or
zero-filled as the new meaning.

Historical V1 controllers/codecs and original independent corpus remain
test-only evidence; active compilation selects V2 infrastructure. The
append-only central log records authorization, implementation/test outcomes and
later acceptance separately. Active documentation is updated in place;
historical sections are explicitly labeled superseded. There is no destructive
Git rollback or retroactive claim that prior tests validated V2.

This amendment is a named **pre-step** within canonical entry13, not an
additional numbered milestone. Bounded V2 infrastructure and relevant
regressions are implemented/passing; closure is blocked on baseline dependency
advisories, unchanged strict-lint failures and outstanding full CI. No
completion acceptance is recorded; T4.14 itself is not started.
Production RNG/peer/state/effect adapters,
raw Version6 layout resolution, actual runtime composition and hardware remain
separate gates.

## 14. Compatible TAV/RustCrypto upgrade, 2026-11-04

The user separately directed upgrading the compatible TAV/RustCrypto
dependency stack. This authorizes dependency remediation, not an advisory
waiver, cryptographic backend change, T4.14 implementation or completion
acceptance of the preceding amendment.

PAL and the emulator's test dependency now select `tav-1.0.7`, commit
`7fb2c2535180b73e56cc25a46a88cf679b5b8239`, with defaults disabled and
`crypto_pure_rust` selected explicitly. TAV 1.0.8
[removed that backend](https://github.com/microsoft/TEE-Attestation-Verification/blob/tav-1.0.8/CHANGELOG.md);
using it would require a separately considered backend change. Selecting the
last release containing pure-Rust support does not assert ongoing upstream
maintenance or production qualification.

The [lockfile](../../Cargo.lock) now resolves:

| Dependency | Previous | Selected |
|---|---|---|
| TAV library/crypto | 1.0.2 | 1.0.7 |
| `crypto-bigint` | 0.5.5 | 0.7.10 |
| `elliptic-curve` | 0.13.8 | 0.14.3 |
| `ecdsa` | 0.16.9 | 0.17.0 |
| `p256` / `p384` / `p521` | 0.13.x | 0.14.0 |
| Shared `subtle` / `hybrid-array` | 2.5.0 / 0.4.10 | 2.6.1 / 0.4.15 |

This is a compatible dependency-family migration, not a forced replacement of
`crypto-bigint` beneath consumers expecting 0.5.x. The existing Rust 1.90
compiler builds the selected stack; no toolchain change was made.

One compatibility constraint is deliberate: `pkcs1 0.8.0-rc.4`, matching
[TAV 1.0.7's release lockfile](https://github.com/microsoft/TEE-Attestation-Verification/blob/tav-1.0.7/Cargo.lock).
Stable `pkcs1 0.8.0` changes `RsaPssParams` from a lifetime-based type to a
generic type and fails to compile the upstream parser. The committed lockfile
and `--locked` builds retain the tested dependency; no cached upstream source
was patched and no unused direct dependency was added to force resolution.
Future updates must revalidate this parser/API boundary.

The checked advisory gate no longer reports `RUSTSEC-2026-0387`.
It still fails with eight baseline advisory errors: RSA, four rustls issues,
rustls-webpki, Tokio and webpki-roots. Their selected versions remain unchanged.
In particular, `rsa 0.9.10` remains; upgrading the integer/elliptic-curve stack
does not fix the separate Marvin/padding issue. The two unchanged strict-lint
errors and outstanding full CI remain separate blockers. No ignore entry or
success-shaped fallback was introduced.

Independent P0.10/V2 references, PAL default/TAV/Azure suites, emulator and
serial MigTD SNP tests, relevant Clippy and the TDX SPDM/policy_v2 check pass.
The standard gauntlet's format/check/CI-Clippy stages pass and it stops at
advisories as required; its later firmware and TDX EMU matrices are not claimed
as run. Separate rebuilt legacy regressions and their exact results are
recorded in the [central log](../implementation_record.log), with evidence in
`target/tav-rustcrypto-upgrade/20261104T222209Z/`.

The selected verifier/trust profiles, evidence encodings, policy/history
rules, direct-random protocol, firmware semantics and no-production-
qualification disposition are unchanged.

## 15. Remaining advisory remediation and approved RSA patch, 2026-11-04

The user directed fixing the remaining eight advisory errors. Seven paths
have released fixes; direct requirements now establish patched rustls/Tokio
minimums, and the lockfile selects:

| Dependency | Previous | Selected | Advisory errors removed |
|---|---|---|---|
| `rustls` | 0.23.45 | 0.23.46 | 4 |
| `rustls-webpki` | 0.103.15 | 0.103.16 | 1 |
| `tokio` | 1.52.1 | 1.53.3 | 1 |
| `webpki-roots` | 1.0.4 | 1.0.10 | 1 |

RSA has no advisory-free released upgrade. The user separately approved
**a narrow maintained TAV crypto patch using existing ring RSA verification**,
after being told that ring includes native code/assembly and that this is not
strictly pure Rust. It is not approval for OpenSSL, a different verifier/trust
profile, a waiver, or T4.14 completion.

The [local crypto crate](../../deps/tav-crypto/README.md) copies only TAV's
crypto package from `tav-1.0.7`, commit
`7fb2c2535180b73e56cc25a46a88cf679b5b8239`, with its MIT license retained.
The workspace patches that package's Git source, not the TAV report verifier.
The affected `rsa` dependency and its SHA-2 compatibility adapter are removed.
RSA is neither renamed nor hidden behind an advisory ignore.

The old feature name `crypto_pure_rust` remains as a compatibility selector.
ECDSA, X.509 parsing, signature-parameter validation and certificate-path
policy remain upstream code. Only RSA public-key parsing/verification is
adapted to existing patched ring. The local package defaults to that selected
feature, preventing its workspace membership from implicitly enabling the
upstream OpenSSL defaults. PAL and emulator still disable dependency defaults.
Other optional upstream platform backends are retained but are not selected.

All six RSA algorithms remain: PKCS#1 v1.5 and PSS with SHA-256/384/512.
SPKI must use `rsaEncryption` with NULL parameters, an octet-aligned BIT
STRING and strict PKCS#1 DER. The 4096-bit upper bound is preserved; a
2048-bit minimum intentionally rejects weaker keys unsupported by the chosen
ring algorithms. Modulus/exponent shape checks are explicit and bounded;
ring enforces signature/key length, padding, hash and PSS salt/MGF1 rules.
There is no permissive or alternate-backend fallback.

The upstream crypto suite and five added RSA regression tests pass: 75 unit
tests in total. Added coverage exercises all six algorithms, changed message/
key/signature/hash/padding, malformed lengths and DER, invalid OID/parameters/
BIT STRING, modulus/exponent boundaries and independently generated PSS
signatures with wrong salt length or MGF1 hash. Existing Milan/Genoa chain
tests pass. `cargo xtask lib-test` now includes the local crate so these are
not one-off unregistered tests. The selected native Linux path is tested;
other platforms and production/hardware remain unqualified.

The exact advisory check passes with zero errors and no exceptions.
The earlier sections' nine/eight-advisory results remain historical execution
facts. The current checked graph contains no affected `rsa` package.
The two unchanged baseline strict-Clippy errors and broader CI disposition
remain separate from advisory remediation. Full feature/build/runtime results
and preservation are appended to the [central log](../implementation_record.log);
evidence is under `target/remaining-advisories/20261104T223831Z/`.
No direct-random protocol, firmware ABI, authorization, history or production
qualification gate is changed by this dependency maintenance.

Final bounded validation passes: PAL default/TAV/Azure (27/402/403 unit
tests plus 5/20/20 doctests), emulator (7), serial MigTD SNP (67), registered
library suites (including the 75 crypto tests), relevant Clippy, and rebuilt
musl legacy Stage A/B. One existing collateral-generator test remains ignored,
not passed. Independent P0.10/direct-random vectors also pass.

The full gauntlet passes format/check/CI-Clippy, all advisory/source/bans
checks and all 32 firmware builds. Its EMU stage stops at the explicit
release build with `test_disable_ra_and_accept_all`: the unchanged
[release guard](../../src/migtd/src/lib.rs) deliberately rejects that
test-only feature. Neither the guard nor the workflow/runner was weakened.
Separate permitted debug TLS skip-RA, SPDM skip-RA and policy-v2 mock-report
handshakes pass; these do not constitute the full 14-scenario CI EMU matrix.
The two previously recorded strict-Clippy errors remain unchanged and were
not remediated by this advisory work. Full CI and T4.14-PRE closure therefore
remain blocked; no acceptance or T4.14 start is recorded.

## 16. Explicit mutex-guard lifetimes, 2026-11-04

The user authorized the two previously reported strict-Clippy corrections.
[rust_std_stub](../../src/std-support/rust-std-stub/src/lib.rs) now returns
`spin::MutexGuard<'_, T>` from both `try_lock` and `lock`. This explicitly
spells the existing borrow relationship to `&self`; locking behavior,
error handling and feature selection are unchanged.

Formatting and the crate's strict-Clippy check with `--all-targets` and
`-D warnings` pass. Library-test compilation passes (zero enabled unit
tests). The broader workspace strict-Clippy command remains blocked by
four newly exposed diagnostics in unchanged source: hidden lifetimes in
`crypto/src/lib.rs:139` and `crypto/src/x509.rs:156`, and manual
`is_multiple_of` implementations in `devices/pci/src/config.rs:223,257`.
The crate's full test command also reports 27 failing copied I/O doctests
(five pass); no doctest repair or unrelated lint changes were made.

All other sources matched the preceding validation manifest before this
documentation append. Evidence is under
`target/strict-clippy-lifetimes/20261104T232548Z/` and in the
[central log](../implementation_record.log). This clears the two named
mutex-guard diagnostics, not the overall strict-Clippy or full-CI gates.
T4.14-PRE remains unaccepted; T4.14 is not started. No commit or push.

## 17. Workspace strict-Clippy remediation, 2026-11-04

The user selected **fix workspace strict-Clippy until it passes**, excluding
the copied I/O doctest repair. As the check reached upstream SPDM test targets,
the user separately selected **exclude upstream SPDM from the MigTD workspace,
retaining it as a dependency**. The root workspace now excludes `deps/spdm-rs`,
like the other upstream submodules; its linked libraries and source revision
are retained. Metadata confirms no SPDM workspace members and a live `spdmlib`
dependency. No upstream SPDM source was patched or test failure claimed fixed.
Offline lockfile regeneration prunes only `pcidoe_transport`; no package
identity/version is added or upgraded.

The exact check passes with the final selected workspace boundary:

```bash
AS=nasm AR=llvm-ar CC=clang cargo clippy --offline --locked \
  --workspace --all-targets \
  --features main,vmcall-raw,stack-guard,vmcall-interrupt,oneshot-apic,spdm_attestation,igvm-attest,policy_v2 \
  -- -D warnings
```

Non-workspace dependency warnings remain visible under Cargo's normal lint
capping; this is a successful strict workspace check, not a claim that every
dependency is warning-free. No new lint allowances or warning suppression
were added.

Changes are explicit lifetimes, equivalent alignment/division/iterator
operations, removal of an unused private policy duplicate and redundant
casts/borrows, and error-log observers changed to `inspect_err` without
changing their errors or messages. TLS-only helpers/imports and test-only
builders now follow their callers' actual configuration. Two private
argument groups name existing peer-attestation fields and fixture trace-site
metadata; verification inputs, log fields and wire formats are unchanged.
The local TAV patch also has documented mechanical lint changes, not new
certificate-policy or ECDSA decisions.

Logging tests retain global-state serialization using an async-aware Tokio
mutex, with blocking acquisition only in the synchronous test. The existing
compile-time frozen-size assertions remain; duplicate constant runtime
assertions were removed without removing the boundary/value tests.
The existing fixture-only PAL guard is now declared and checked at crate
scope: fixture-only without `snp-emu` is rejected, and the paired features
compile. This is necessary because the SNP module itself is feature-gated.

Bare-metal/emulator entry points no longer collide with the existing test
entry point. The TDX-specific guest test binary explicitly requires `tdx`
and uses its custom guest harness, not host unit/bench harnesses. Its normal
build script already supplies `main,tdx`; an explicit bare-metal `tdx` binary
check passes. These target declarations do not claim a hardware test run.
The hash tool now requires a complete configuration-volume read instead of
silently accepting an unchecked short read; read errors propagate normally.

Registered library suites, affected tool/serial tests, PAL default/TAV/Azure,
SNP emulator and serial MigTD SNP suites, independent references and the
fixture guard's positive/negative checks pass. Zero-test targets and the
existing ignored collateral-generator test are not behavioral coverage.
Copied I/O doctests remain failed historical evidence and were not repaired
or claimed passed.

Exact final build/runtime results and preservation are recorded in the
[central log](../implementation_record.log), with evidence under
`target/workspace-strict-clippy/20261104T233000Z/`. The release/accept-all
guard remains in force. No phase acceptance, T4.14 start, production/hardware
qualification, commit or push is authorized by this lint maintenance.

Final validation completed 2026-11-05 UTC: the exact strict workspace command,
formatting and advisory checks pass after regressions. All 32 firmware
matrix builds and source/bans checks pass. Rebuilt legacy SNP Stage A/B and
four separate debug EMU handshakes (TLS/SPDM skip-RA and TLS/SPDM policy-v2
mock-report) pass. PCI/virtio fuzz alignment paths compile.
Full CI still stops at its explicit release-plus-accept-all build, rejected
by the unchanged security guard; the separate debug runs do not claim the
full CI EMU matrix. T4.14-PRE remains blocked and unaccepted.

## 18. CI harness alignment and full local parity, 2026-11-05

The user authorized the proposed closure steps: **"Fix using the steps
above."** This is CI maintenance and validation authority, not T4.14-PRE
completion acceptance or permission to start T4.14.

The previous release/accept-all failure came from a stale
[local gauntlet](../../.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh).
The [GitHub workflow](../../.github/workflows/integration-emu.yml) already
uses debug skip-RA prebuilds and `--debug` runner commands. The gauntlet now
matches all four prebuilds and all 14 scenario commands/timeouts exactly.
Skip-RA scenarios have 300-second timeouts; the other scenarios have
900-second timeouts. Mock-report scenarios retain the workflow's release
profile; `test_mock_report` is not the guarded `use-mock-quote` feature.

Fixture preparation now always invokes the existing mock policy builder,
as CI does, instead of checking only whether the base policy exists. It
generates matching base, policy-leaf, policy/mapping-leaf and all-three-leaf
rotation policies and issuer chains. Six tool builds present in
[main CI](../../.github/workflows/main.yml), but missing from the old
gauntlet, are now included: json-signer, migtd-collateral-generator,
migtd-hash, migtd-policy-generator, migtd-policy-verifier and
servtd-collateral-generator.

No GitHub workflow, Rust source, dependency manifest, lockfile or security
guard was changed. No release debug-assertion override or attestation waiver
was introduced. A separate release accept-all check fails with the exact
expected security diagnostic.

Validation uses the declared CI Rust toolchain, not the repository's local
Rust 1.90 override:

```bash
export AS=nasm AR=llvm-ar CC=clang
export RUSTUP_TOOLCHAIN=1.88.0 CARGO_NET_OFFLINE=true
export PATH="$PWD/target/t4.14-pre-random32/20261104T213506Z/tools/bin:$PATH"
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --from emu
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only format
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only deny
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only main
```

The existing cargo-deny installation and prepared submodules were reused;
no toolchain/dependency installation or submodule update was needed.

| Local workflow-command coverage | Result |
|---|---|
| Format, cargo check, CI feature-set Clippy | PASS |
| Advisory, source and bans checks | PASS; no waiver or ignored source failure |
| Firmware device/policy/protocol/profile matrix | 32/32 PASS |
| Main-workflow tool builds | 6/6 PASS |
| EMU migration, rebind, retry and rotation matrix | 14/14 PASS; 28/28 process exits zero |
| Forbidden release accept-all build | Expected security rejection PASS |

Evidence is under `target/ci-closure/20261105T000918Z/`: per-stage summaries
and logs, exact command/timeout comparisons, compiler/environment identities,
both process exits for every EMU scenario, tested public fixtures, and final
preservation/validation manifest. Generated config files were restored to
their exact pre-run bytes; owned newly generated outputs were removed.
Before documentation, all 508 non-harness baseline files were unchanged.
Historical log entries and earlier manifests retain their original meaning.

This closes the full local workflow-command parity gap. It does not claim
execution of GitHub-hosted actions, SARIF upload or a published CI run.
The previously excluded upstream SPDM tests and copied I/O doctests are not
repaired, rerun or claimed passed; neither is run by these four workflows.
No production-readiness row or hardware gate is qualified.
T4.14-PRE now awaits explicit completion acceptance; T4.14 remains NOT STARTED.
No commit or push was performed.

## 19. T4.14-PRE bounded completion acceptance, 2026-11-05

At 2026-11-05T02:22:07.036Z the user explicitly stated:

> Accept and freeze T4.14-PRE within its documented bounded scope and exclusions. Conditions: None.

Disposition: DONE - ACCEPTED AND FROZEN.
Freeze identifier: `T4.14-PRE-DirectRandomV2-2026-11-05`.
The append-only [central acceptance record](../implementation_record.log)
records the exact decision, bounded scope, evidence and exclusions.
The [amendment](task4/t4.14-pre-direct-random.md), canonical plan and current
readiness index are reconciled; earlier pending/blocked records remain
historical and are not rewritten.

Acceptance covers the implemented/tested V2 direct-random infrastructure,
authorization and protected delivery/acceptance/completion contracts,
preserved policy/history/replay/cleanup and uncertain-effect safeguards,
current documentation, and recorded bounded regression/local CI command
parity. The final CI manifest is preserved with SHA256
`f82fb8a1b6569818f81aa60d39f38ac17004d129d4ee7d2d7a4b5fc44dabd1ec`.
No code or dependency change and no new build/test claim accompany this
documentation-only acceptance; source still matches the validated state.

All exclusions remain. Production RNG/providers, effectful runtime,
hardware operation and deployment qualification are downstream gates.
GitHub-hosted CI/SARIF execution and excluded upstream SPDM/copied I/O tests
are not claimed. No production-readiness row or broader phase gate is closed.
T4.14 is READY for a separately recorded start and remains NOT STARTED.
No commit or push is authorized or performed.

## 20. T4.14 randomness and secret services, 2026-11-05

The user authorized **"Implement T4.14"** at 2026-11-05T02:23:45.866Z.
Prerequisite T4.14-PRE is accepted/frozen; its scope and exclusions are retained.
Completion identifier: `T4.14-RandomSecretServices-2026-11-05`.
Disposition: IMPLEMENTED, bounded validation PASS, completion acceptance pending.

The shared [random module](../../src/pal/src/random.rs) defines `RandomSource`,
explicit unavailable behavior and `SystemRandomSource`, using the existing
patched ring. On Linux, including musl, ring obtains randomness from the
operating-system CSPRNG. PAL's `system-random` capability enables that service
without enabling the SNP module, TAV, OpenSSL or Azure attestation dependencies.
The existing `snp-emu` composition selects the capability; future production
composition/provider selection remains T4.15 and downstream qualification.
No package/version or lockfile change accompanies this feature split.

Random output is published only after a complete successful fill into an
owned zeroizing staging buffer. Every tested partial failure, including a
full32-byte write followed by error, returns failure and leaves output zero.
Backend unwind cannot publish partial output. The finite scripted provider
exists only under `cfg(test)`, with compile-fail consumer-isolation coverage;
there is no runtime seed, fallback or configurable cryptographic recipe.

[MigrationKeyV2](../../src/pal/src/snp/direct_key.rs) and
[HandoffSecretV1](../../src/pal/src/snp/local_handoff.rs) reuse the service
through typed error adapters, including trait-object callers. Each generator
performs a separate direct32-byte draw. Source-only and Prepared/first-attempt/
no-results guards remain. An invalid admission consumes no randomness.
Existing V2 preimages, purposes, wire sizes and independent corpora are unchanged.
Generators do not establish durable once-only generation, restart or retry
authority, nor substitute for runtime appraisal of the outgoing handoff MA.

Both owners now share private non-Clone/non-Copy `Secret32` storage, with no
formatter or public extraction API. Drop calls volatile zeroization through
the existing zeroize crate. Existing outer diagnostics remain redacted.
Consuming `clear` methods cover explicit completion/error/cancel/timeout
retirement; compile-fail tests reject subsequent owner use and handoff cloning.
An authorized retry keeps the same owner instead of retiring/regenerating it.
Existing zeroizing transport payloads and decoder input wiping remain intact.

Handoff installation consumes its local owner. Normal errors clear both
provider slots exactly once and propagate cleanup failure with explicit logging.
A guard also attempts cleanup on unwind; it never blindly repeats failed
cleanup. Success intentionally leaves installed slots for the handoff protocol.
Finalization/abort and acknowledged firmware-slot cleanup remain runtime/
authority duties. Cleanup providers must not panic. Panic-abort, SIGKILL,
crash/restart, firmware persistence and internal compiler/register/transport
copies are not made safe by Drop; they retain reconciliation/qualification gates.

The standalone capability exposed an existing unused QvlResult import.
It now follows the same cfg as its QvlLibrary consumer; no lint allowance
was added. An initial Azure-SNP test using Rust1.88 was rejected by existing
Azure SDK/TPM Rust1.90 MSRVs. That failed attempt remains evidence; no package
downgrade or toolchain configuration change was made. Azure-SNP tests use
their previously validated Rust1.90 toolchain; CI commands retain Rust1.88.

| Final validation | Result |
|---|---|
| PAL default | 33 unit tests, 6 doctests PASS |
| Standalone system-random capability | 34 unit tests, 6 doctests PASS; no attestation dependency activation |
| PAL SNP | 413 unit tests, 24 doctests PASS |
| PAL SNP + Azure | 414 unit tests, 24 doctests PASS |
| SNP emulator / serial MigTD SNP library | 7 / 67 tests PASS |
| Registered library suites | PASS; existing ignored test not executed |
| Independent direct-random V2 / P0.10 references | PASS; corpora unchanged |
| Selected strict workspace / standalone RNG Clippy | PASS, Rust1.90 / Rust1.88 respectively |
| Full local CI command parity | Format/check/CI-Clippy, advisories/sources/bans, 32 firmware builds, 6 tools and 14 EMU scenarios PASS |
| Release accept-all guard | Expected rejection PASS; guard source unchanged |
| Rebuilt musl legacy Stage A/B | PASS; existing musl CC and dangerous-implicit-autorefs workaround retained |

Tests verify exact independent32-byte values, all33 partial-write failure
prefixes, no replacement draw during retained-owner serialization, rejected
admission before drawing, compile-time ownership, and one cleanup attempt
after a partial-installation panic even when cleanup reports failure.
Byte-level zeroization is tested through the same cleanup routine used by Drop;
no unsafe inspection of freed memory or claim about every compiler copy is made.

Evidence: `target/t4.14-secret-services/20261105T022345Z/`, including final
logs, exact commands/toolchains, tested-state/preservation manifest and legacy
ELF/controller identities. CI-generated public fixtures are archived and
pre-run config state restored. Historical central records and prior manifests
remain unchanged. Copied I/O doctests/upstream SPDM tests remain excluded,
not repaired or claimed passed. No hardware or production-readiness row is
qualified; the new V2 effectful runtime is not activated.
No T4.14 completion acceptance, T4.15 start, commit or push is recorded.

## 21. T4.14 bounded completion acceptance, 2026-11-05

The user explicitly accepted:

> I accept T4.14 within its documented bounded scope,

Acceptance timestamp: `2026-11-05T03:02:37.597Z`.
Accepted completion identifier: `T4.14-RandomSecretServices-2026-11-05`.
Disposition: DONE - ACCEPTED within the documented bounded scope and exclusions.
No additional conditions were specified.

Acceptance covers the shared random32 service, OS-backed ring adapter,
independent MSK/handoff draws, owned/redacted/zeroizing secrets, consuming
retirement, bounded error/unwind cleanup and the validation described in
section20. The accepted evidence manifest is
`target/t4.14-secret-services/20261105T022345Z/validation-manifest.json`,
SHA256 `9c4db1967188b57bb7e0a72e5e49b24986021457e0ae3f29139cc295d66f41a4`.
Its tested source and historical evidence are unchanged by this recording.

Existing exclusions remain: no production provider/RNG qualification,
effectful V2 runtime activation, durable once-only/restart/retry authority,
independent outgoing-role appraisal, crash/abort/persistent-slot cleanup
qualification, hardware operation or deployment approval. No production-
readiness row is qualified. No GitHub-hosted CI/SARIF execution or excluded
upstream SPDM/copied I/O doctest pass is claimed.

The central ACCEPTANCE event is appended to
[implementation_record.log](../implementation_record.log).
T4.15 explicit provider sets is READY for a separately authorized start;
this acceptance does not start it. No broader phase acceptance, commit or push.

## 22. T4.15 explicit provider sets, 2026-11-05

The user authorized **"Implement T4.15"** at 2026-11-05T13:08:46.245Z.
T4.9-T4.14 bounded completions are accepted. Completion identifier:
`T4.15-ExplicitProviderSets-2026-11-05`.
Disposition: IMPLEMENTED, bounded validation PASS, completion acceptance pending.

### Composition and ownership

The new [composition module](../../src/pal/src/composition.rs) defines:

| Composition | Mode | Provider family / trust | Randomness |
|---|---|---|---|
| TDX hardware | no_std | Existing TDX hardware | Existing TDX SystemRandom path, unchanged |
| AzCVMEmu | std | Existing TDX emulator | Existing TDX SystemRandom path, unchanged |
| SnpEmuAzure | std | SNP emulator / fixture profile | Existing Linux OS-backed SystemRandomSource |
| SnpHardware | std | SNP production / AMD profile, layout blocked | Same existing SystemRandomSource, not production-qualified |

These specifications are configuration contracts, not authenticated claims
or runtime dispatch. The actual TDX entry points, transports and feature
graph are untouched. No new cryptographic recipe, kernel RNG initialization
service, firmware opcode or transport protocol is introduced.

Sealed SNP markers select privately owned `SnpProviderSet` instances. Shared
orchestration borrows `SnpServiceRefs` containing the existing typed MA evidence,
collateral, common verifier, peer factory/clock, host transport/context,
replay/current firmware state, disabled platform-key, migration installer,
binding manager, handoff authority/protected-secret and randomness interfaces.
Peer factories are borrowed through their trait with the associated session
type retained, not exposed as replaceable concrete objects.

`SnpEmuAzure::compose` accepts explicit trusted service inputs; host requests
cannot supply them. `SnpHardware::compose` accepts no emulator service input.
The production aggregate has a distinct sealed type and selects unavailable
production interfaces plus the existing OS RNG. Private ownership and
compile-fail tests reject emulator-to-production conversion, emulator injection
into production and replacement of the owned random service.
The aggregate `composition::snp::SnpHardwareProvider` is distinct from the
older report-only `snp::hardware::SnpHardwareProvider`.

No operational or qualification result follows from construction. The common
verifier is still `UnavailableSnpReportVerifier`: neither composition can
produce authenticated AAS claims. Hardware evidence/collateral, trusted clock,
state/effects and transport remain explicitly unavailable. Existing typed
unavailable implementations retain their error domains; no dummy success,
zero-key fallback, TAV verifier fallback or emulated production effect is added.

### RNG scope and attribution

Both Linux SNP compositions use the existing ring-backed OS CSPRNG, with no
seed parameter or runtime deterministic/random toggle. The previously listed
`snp-test-randomness` deployable emulator capability is reconciled with accepted
T4.14: scripted randomness remains `cfg(test)` only. The T4.16 composition
example and R4.2 RNG entry now reflect that same rule.

TDX supplies the feature/entry-point/transport-selection precedent, not this
exact SNP bundle. AMD constrains host/guest/peer separation and legal firmware
effects, not the Rust composition names or OS RNG adapter. The provider
architecture and AAS/fixture selection are accepted project choices.

The prior discussion of tracing kernel entropy provenance was a proposed
production assurance approach, not an approved new prerequisite or mandatory
implementation framework. Linux handles its own CSPRNG initialization.
Production evidence scope still requires explicit downstream review;
selection of SystemRandomSource does not qualify it for deployment.

### Separately authorized advisory remediation

The first full CI attempt stopped on newly reported RUSTSEC-2026-0441:
existing `pin-utils` was unmaintained, with no safe direct upgrade.
The user then authorized:

> Authorize narrowly scoped pin-utils dependency remediation and required revalidation

Compatible lockfile updates select futures-util0.3.32, futures-macro0.3.32,
supporting futures channel/core/io/sink/task0.3.34, and hyper1.9.0.
`pin-utils` is removed. Recorded metadata shows all updated MSRVs are at most
Rust1.71, compatible with CI Rust1.88. Dependency ranges, ring/TAV/AAS versions
and toolchain configuration are unchanged. No advisory waiver is added.
Cargo also re-resolved existing Windows-target `windows-sys` dependency edges
for dirs-sys, nu-ansi-term and socket2; those package versions are unchanged.
These automatic edge changes are captured in the manifest, not hidden as
byte-identical lockfile preservation or Windows qualification.
The final lockfile is revalidated; earlier manifests remain immutable.

### Validation and limits

| Final validation | Result |
|---|---|
| PAL default / standalone system-random | 34/6 and 35/6 unit/doctests PASS |
| PAL SNP / SNP + Azure | 418/27 and 419/27 PASS |
| SNP emulator / serial MigTD SNP library | 7 / 67 tests PASS |
| Registered libraries / unchanged V2 and P0.10 oracles | PASS; existing ignored test not executed |
| PAL strict, dependency-excluded / selected strict workspace | PASS with Rust1.90 |
| Standalone system-random strict check | PASS with Rust1.88 |
| Full local CI, final lockfile | Format/check/CI-Clippy, advisories/sources/bans, 32 firmware builds, six tools, 14 EMU scenarios PASS |
| Independent EMU process-exit check | 28/28 source/destination exits zero |
| Release accept-all guard | Expected rejection; source unchanged |
| Rebuilt musl legacy Stage A/B | PASS; original controller and existing build workaround retained |

Supplemental Rust1.88 strict SNP checks encountered pre-existing
uninlined-format lints: ten in the unchanged TAV crypto workspace member,
then one in unchanged peer logging when dependency linting was excluded.
Those failed attempts are retained, not suppressed, repaired or claimed
passed. Established strict checks use the previously validated Rust1.90;
full CI keeps its Rust1.88 configuration.

Evidence: `target/t4.15-provider-sets/20261105T130846Z/`, including exact
commands/toolchains, final manifest, dependency/MSRV changes, failed attempts,
raw CI logs, independent counts and legacy ELF/controller identities.
Eight generated policy/chain fixtures were archived and restored to exact
pre-test bytes. No live regression listener remains.

T4.16 still owns feature/dependency/image isolation; the shared SNP module
retains its historical `snp-emu` gate here. T4.18 owns caller routing, and later
tasks own complete V2 runtime activation and production qualification.
No production-readiness row, physical Version 6 parser, AAS adapter, effectful
hardware operation, GitHub-hosted CI/SARIF or excluded upstream SPDM/copied I/O
doctest pass is claimed. T4.15 acceptance remains pending; T4.16 is not started.
No commit or push.

## 23. T4.15 bounded completion acceptance, 2026-11-05

The user explicitly accepted:

> I accept T4.15 within its documented bounded scope and exclusions.

Acceptance timestamp: `2026-11-05T13:51:09.902Z`.
Accepted completion identifier: `T4.15-ExplicitProviderSets-2026-11-05`.
Disposition: DONE - ACCEPTED within the documented bounded scope and exclusions.
No additional conditions were specified.

Acceptance covers the four composition specifications, shared typed SNP
provider sets, separate emulator/production construction, selected existing
SystemRandomSource with scripted randomness test-only, explicit unavailable
boundaries, and the validation and separately authorized dependency remediation
documented in section22. The accepted manifest is
`target/t4.15-provider-sets/20261105T130846Z/validation-manifest.json`,
SHA256 `03b8ec998acf3be778ffc5db15186d804da817f1b34a44df98d411549dfa975f`.
Its source, lockfile and evidence hashes match the pre-acceptance state.

The exclusions remain unchanged: no completed T4.16 feature/image isolation
or T4.18 caller integration, operational production AAS/physical Version 6
parser, effectful V2 runtime activation, production RNG qualification, hardware
operation or deployment approval. No production-readiness row is qualified.
Recorded supplemental Rust1.88 strict failures and excluded upstream
SPDM/copied I/O tests are not retroactively passed; no GitHub-hosted CI/SARIF
execution is claimed. The proposed kernel entropy-provenance checklist remains
outside the accepted implementation mandate.

The central ACCEPTANCE event is appended to
[implementation_record.log](../implementation_record.log).
T4.16 feature selection is READY for a separately authorized start; this
acceptance does not start it or accept a broader phase. Source and lockfiles
are unchanged by this documentation-only recording. No commit or push.

## 24. T4.16 feature selection implementation and validation

Authorization: "Implement T4.16" at `2026-11-05T15:12:07.400Z`.
Prerequisite: the bounded T4.15 completion accepted in section23.
Validation timestamp: `2026-11-05T16:05:02.185Z`.
Completion identifier: `T4.16-FeatureSelection-2026-11-05`.
Disposition: IMPLEMENTED; bounded validation PASS; completion acceptance PENDING.
Earlier records and their exclusions remain historical and unchanged.

### Implemented selection and isolation

- PAL `snp-core` exposes shared SNP contracts independently of `snp-emu`;
  `snp-fixture` and `snp-linux-hardware` gate their own providers.
  State/mock capabilities are explicit; production/fixture/TDX combinations
  are compile-rejected at the PAL and MigTD boundaries.
- MigTD `std` is explicit. Legacy TDX modules/dependencies are behind
  `tdx-platform`; the binary has a separate `entry` capability and production
  SNP entry point. The legacy binary body is re-homed without changing its
  TDX/AzCVMEmu workflow. Binary harnesses contain no tests in that body;
  it is not compiled under `cfg(test)`, without suppressing lints.
- `SnpUnderhillRuntime` supplies shared configuration/PID1 behavior without
  fixture, TCP, synthetic-root or TDX providers. `SnpUnderhill` now aliases
  that runtime-only capability; `SnpEmuAzure` explicitly adds `SnpEmu`.
- MigTD roots select closed production or fixture-root typed sets once.
  Shared logic cannot select a fallback from a runtime flag. Both Linux
  sets retain existing `SystemRandomSource`; scripted randomness is test-only.
  The legacy unactivated V2 bundle is not presented as caller integration.
- Local AAS is the sole selected SNP verification capability. The legacy
  captured-fixture verifier rejects live report requests with a typed
  unavailable error. Common V6 claims verification remains unavailable until
  AAS1A-M; no physical layout is guessed and no remote authorization service
  is introduced. Parsing fields alone does not establish authentication or
  provenance; the legacy policy adapter labels its output `unverified`.
- TAV and its crypto patch are removed from final dependencies, backend
  selection, traces and registered test targets. Historical patch files are
  retained outside the workspace. Fifty-two lockfile packages are pruned;
  no package version/source is added or upgraded. Remaining record changes
  are removed feature edges and dependency-name disambiguation.
- Frozen P0.10 certificate-vector assertions use the repository X.509 parser
  and ring, including canonical DER, signatures, validity, purpose, CA/path
  constraints and usages. The corpus is unchanged. Legacy field-parser
  regressions cover every TCB component, reserved bytes, little-endian SVN
  floors and exact report length.

### Validation and repaired regressions

All commands use `AS=nasm AR=llvm-ar CC=clang` unless explicitly cross-building.
Preparation remains valid; no submodule update or preparation mutation occurred.

| Validation | Result |
|---|---|
| Persistent feature selection/dependency checks, including independent std/runtime/hardware, AzCVMEmu compatibility and expected compile exclusions | 40 PASS |
| PAL default / system-random unit + doctests | 34/6 and 35/6 PASS |
| PAL shared core / fixture-only / production unit + doctests | 415/26, 415/26 and 415/27 PASS |
| PAL emulator unit + doctests | 422/26 PASS |
| SNP emulator / serial MigTD SNP library tests | 7 and 67 PASS |
| Registered library runner and unchanged P0.10/direct-random Python references | PASS |
| Scoped PAL core/emulator, SnpHardware and workspace strict Clippy, Rust1.90 | PASS; no lint suppression |
| Rust1.88 format/check/CI-Clippy, advisory/source/ban stages, firmware/tool builds | PASS; 32 images and six tools |
| Rust1.88 EMU matrix | 14 PASS; all 28 source/destination exits zero |
| Rebuilt musl release SNP Stage A/B with frozen historical host controller | PASS |
| Production binary startup / forbidden release accept-all | Explicit exit2 / expected compile rejection |

The full command-parity run exposed the image-hash consumer's missing explicit
TDX capability. Its fix deliberately does not enable attestation: an initial
over-selection produced a native `__ImageBase` link failure and was corrected.
Moving the binary body also exposed private-module dead code in empty test
harnesses and the AzCVMEmu child's old crate-root import. The former is gated
out only for the empty harness; the latter now uses its actual parent module.
Strict checks and the isolated hash-tool build pass; all firmware/tool commands
pass and the repaired EMU stage was resumed and passed. Failed attempts remain
in the evidence directory; they are not described as successful runs.
Initial feature/parser/compiler failures were also corrected before validation.

Evidence root: `target/t4.16-feature-selection/20261105T151207Z/`.
Its final manifest records source/lockfile hashes, feature matrices, raw logs,
toolchains, failed attempts, fixture restoration and preservation checks.
The eight regenerated Azure policy/chain files were archived and restored
byte-for-byte. The canonical 37-step sequence, prior central-log prefix,
technical-note sections1-23, frozen corpora, submodule revisions and unrelated
worktree changes remain preserved. No task listeners remain.

### Bounded exclusions

Production startup refuses unavailable services before evidence acquisition,
secret generation, transport startup or firmware effects. Compiling the legacy
Linux `/dev/sev-guest` provider independently is not activation or qualification
of a production Version 6 provider. AAS capability selection does not complete
the common claims/layout adapter. Production transport, persistence, trusted
clock and effect providers remain unavailable. No fixture fallback is enabled.

No effectful V2 runtime, T4.18 broad caller integration, production RNG/hardware
qualification, deployment approval, readiness-row qualification or
GitHub-hosted CI/SARIF is claimed. Excluded upstream SPDM/copied-I/O tests are
not newly claimed passed. No new kernel entropy-provenance prerequisite is
invented. T4.17 remains NOT STARTED pending separately recorded T4.16 bounded
acceptance and authorization. No commit or push.

## 25. T4.16 bounded completion acceptance

The user explicitly accepted:

> I accept T4.16 within its documented bounded scope and exclusions.

Acceptance timestamp: `2026-11-05T16:11:10.268Z`.
Accepted completion identifier: `T4.16-FeatureSelection-2026-11-05`.
Disposition: DONE - ACCEPTED within the documented bounded scope and exclusions.
No additional conditions were specified; existing exclusions remain in force.

Acceptance covers the capability/feature isolation, explicit std and
runtime-only Underhill split, independent fixture/Linux-hardware gates,
root-owned provider selection, production mixed-feature rejection, local
AAS-only backend selection, TAV removal and bounded validation in section24.
The accepted manifest is
`target/t4.16-feature-selection/20261105T151207Z/validation-manifest.json`,
SHA256 `043836f044f2880275926b5b7dc93c2da6886cb254d3e74c49d7683e58cf234d`.
Its recorded source and lockfile hashes match the pre-acceptance state.
The repaired failures and resumed CI stages remain recorded as such; acceptance
does not convert failed attempts, ignored tests or excluded tests into passes.

The exclusions remain unchanged: no operational common AAS Version 6/layout
adapter or production transport/state/clock/effect providers, effectful V2
activation, T4.18 broad caller integration, production RNG/hardware
qualification, deployment approval, readiness-row qualification or
GitHub-hosted CI/SARIF. Production startup remains intentionally fail-closed.
No new kernel entropy-provenance prerequisite is introduced.

The central ACCEPTANCE event is appended to
[implementation_record.log](../implementation_record.log).
T4.17 is READY for separately authorized implementation and remains NOT STARTED.
This acceptance does not start it or accept a broader phase. Recording changes
documentation only; source, lockfile, prior technical-note sections and accepted
evidence remain unchanged. No commit or push.

## 26. T4.17 interface and provider conformance

Authorization: `Implement T4.17`, recorded at `2026-11-05T16:22:33.174Z`.
Prerequisite: accepted `T4.16-FeatureSelection-2026-11-05` and the earlier
accepted contracts; no broader acceptance is inferred.
Bounded validation timestamp: `2026-11-05T17:21:34.964Z`.
Completion identifier: `T4.17-InterfaceConformance-2026-11-05`.
Disposition: IMPLEMENTED; bounded architectural/interface validation PASS;
completion acceptance PENDING. T4.18 remains NOT STARTED.

### Changes and narrow production-code repairs

The existing conformance suites and frozen corpora are reused, not replaced.
Five tenant-source tests add exact host-package round trips/truncation checks,
all-byte ETCB consistency across claims/supplement/base report, digest and
profile consistency, supplement reserved/migration-data checks, and common
typed policy identity projection. The negative consistency cases check the
exact error, absence of a receipt, zero replay loads/commits and zero current
firmware calls. All 30 verifier errors receive the same no-effect checks.
Inline and base-report-reference host packages both retain explicit verifier
unavailability after decoding: decoding confers no authentication.

Both real composition sets are checked across two evidence formats, two
trust domains and three request kinds: 24 common-verifier failures, all
explicit `ProviderUnavailable`, with no authenticated result or fallback.
Selected unavailable services additionally reject peer establishment,
host responses and pre-proof finalization, not just startup/input acquisition.
These are real selected provider sets, not replacement test compositions.

The feature checker grows from 40 to 55 checks. In addition to existing
mixed-feature/dependency checks, it builds the complete emulator without an
attestation bypass, checks the TDX graph's no-std selection, builds standalone
production/fixture PAL artifacts, and compiles actual external consumers.
Positive constructor controls pass; prohibited fixture/hardware exports,
constructor injection, replacement of owned randomness, deterministic test
randomness, receipt forgery and an externally implemented composition marker
are rejected with the expected diagnostics. This avoids relying on unit-test
exports or on arbitrary compilation failures.

The external fixture consumer exposed missing explicit `zeroize/alloc`
selection, masked by other dependencies in earlier feature combinations.
PAL now declares the allocation support required by its existing
`Zeroizing<Vec<u8>>` owners. No package identity/version/source or lockfile
changes, new dependency, lint waiver or secret-cleanup weakening is involved.

`MaPolicyIdentityInputV1::from_authenticated_claims` projects common typed
claims into the existing 280-byte identity, with the existing Version 6 guard.
Its encoding and identity hash use the unchanged frozen codecs. The same
projection is tested for all three provenance profiles and both trust domains
without emulator branches. This helper does not authenticate a claim, check
policy admission, resolve an evidence layout or grant a production receipt.
The legacy fixture policy-appraisal path is unchanged. Full common-verifier
caller wiring remains T4.18; actual authenticated claims and their composed
admission conformance remain AAS1A-M, not an achievement of this projection.

### Executed requirement coverage register

The evidence manifest records exact executed passing test names for these
obligations. Representative selectors below refer to existing or expanded
tests; controlled verifier outputs are interface inputs, never signed
attestation or migration-qualification evidence.

| T4.17 obligation | Executed coverage | Boundary/authority |
|---|---|---|
| Provider conformance and selection | `composition::snp::tests::both_compositions_share_typed_fail_closed_services`; feature checker | Real selected sets; production services deliberately unavailable |
| Hardware fail closed/no fixture fallback | `hardware_rejects_fixture_guest_binding_and_unqualified_raw_layout`; `unavailable_common_verifier_has_no_legacy_backend_fallback`; startup exit2 | No fixture acceptance or alternate backend |
| Shared verifier contract | `no_composition_has_an_authenticated_aas_adapter_yet` | 24 request/profile/trust/set combinations; no accepted claims |
| Emulator/host codecs | `host_package_codecs_are_exact_for_both_profiles_but_do_not_authenticate`; existing header/frame codec suites | Exact sizes, reserved fields, profiles, all truncations and trailing bytes |
| Supplement signature and provenance | `supplement_signatures_full_report_binding_and_all_bytes_are_checked`; P0.10 independent oracle | Real fixture P-384 signatures and complete report/supplement binding; not AAS |
| Report/supplement digest and ETCB consistency | `every_etcb_byte_is_consistent_across_claims_supplement_and_base_report`; `every_digest_byte_and_profile_is_checked_after_the_controlled_verifier` | Controlled typed verifier outputs; exact errors and zero downstream effects |
| Supplement versions/reserved/migration data | `supplement_reserved_and_migration_data_bytes_cannot_mint_receipts`; existing signed inconsistent-supplement vectors | All flag values, reserved fields and all 64 migration-data bytes |
| Typed policy/common claims | `typed_policy_identity_consumes_common_claims_without_provider_branches`; `every_identity_input_byte_is_checked_against_selected_identity` | Common semantic identity projection and existing frozen identity binding; not full production admission |
| Unsupported/conflicting layouts and typed errors | `every_backend_failure_is_explicit_and_never_cached_as_success`; hardware raw-layout rejection | All 30 errors propagate, including `UnsupportedVersion6Layout`/`ConflictingAbiLayout`; no guessed physical layout |
| Production fixture/provider/state/TCP/mock/test-RNG isolation | Mixed-feature negatives and external-consumer API checks | Compile-time exclusions and sealed/private ownership, not hardware qualification |
| No TAV and Underhill runtime independence | Dependency trees/lockfile checks and runtime-only/alias positive builds | Existing independent gates retained; no dependency fallback |
| Hardware provider reachability | Production-root positive and fixture-root/Linux-module negative external consumers | Production capability gates, not an operational device claim |
| Host/peer/firmware-plane separation | `host_responses_are_correlated_typed_and_not_valid_as_requests`; `application_cannot_be_sent_during_bootstrap`; `protected_acceptance_is_not_firmware_success_and_source_waits_for_destination` | Host status, protected peer records and firmware results remain distinct |
| Tenant binding classification | `guest_binding_uses_independent_full_expectation_and_never_enters_active_v1_authorization`; hardware rejection | Guest-requested expectations are not host-pushed zero REPORT_DATA; all 64 binding bytes matter |
| Venice installer validation | `both_roles_borrow_exact_key_history_and_existing_proofs`; operation-field and history-reserved-byte tests | Role-specific REPORT_ID and correlated local outcomes; no real firmware installation |
| Handoff-secret non-exposure | `handoff_secret_is_exact_direct_random32_and_never_uses_host_codec`; redaction/protected transfer tests | Accepted direct-random V2, no application HMAC or derived-key activation |
| Binding-manager state ordering | `t412_binding_boundary_retains_frozen_contract_gates_and_never_fakes_effects`; planned/recovery gate suites | Existing authoritative ordering and current proofs; no host-flag authority |
| Secret cleanup and failure outcomes | `failed_secret_install_attempts_cleanup_and_propagates_cleanup_failure`; `handoff_install_unwind_attempts_slot_cleanup_once`; direct-exchange partial/unknown outcome tests | No success after partial/unknown effects; owned secrets remain wiped/redacted |

TDX supplies architectural software precedent for capability separation,
provider ownership and fail-closed interfaces. It does not specify these SNP
wire types, Rust features or AMD command semantics. The accepted
[Firmware ABI 1.59 / ARG v1.20 addendum](task4/q162-arg-v120-command-addendum.md#current-p02-addendum-2026-11-02)
remains the AMD authority for REPORT_ID/VMPL/REPORT_DATA, Venice history and
firmware outcome handling. The removed `MSG_VERIFY_REPORT` is not restored.
The V6 migration-data/ETCB overlap remains unresolved; controlled fixture
consistency checks do not resolve it or authenticate a production report.
The original PDFs were not reinterpreted or modified for this test step.

### Validation and preserved evidence

Evidence: `target/t4.17-interface-conformance/20261105T162233Z/`.
The final `validation-manifest.json` binds source/document hashes, logs,
exact executed coverage selectors, prior evidence and preservation assertions.
The central log refers to its path; explicit completion acceptance, if later
given, must record its SHA256 without rewriting this validation history.

| Gate | Final result |
|---|---|
| Feature/dependency/external-consumer checks | 55 PASS |
| PAL default / system-random units and doctests | 34/6 and 35/6 PASS |
| PAL snp-core / snp-fixture | 420/26 each PASS |
| PAL snp-emu / snp-production | 427/26 and 420/27 PASS |
| MigTD serial SNP library / standalone SNP emulator | 67 and 7 PASS |
| Registered libraries | PASS; existing ignored test remains ignored |
| P0.10 / direct-random V2 independent references | 137 exact P0.10 entries and unchanged V2 corpus PASS |
| Strict workspace and scoped PAL/hardware Clippy | PASS; no lint suppression |
| Rust1.88 local CI command parity | Format/check/CI-Clippy, all deny checks, 32 firmware images, six tools, 14 EMU scenarios PASS; all 28 process exits zero |
| Rebuilt musl legacy SNP Stage A/B | PASS with frozen historical host controller |
| Production binary/startup and release bypass | Build PASS; startup deliberately exits2 with unavailable-provider diagnostic; release bypass deliberately rejected |

Scoped SNP/strict checks use Rust1.90. Preparation was already valid; no
submodule update or dependency installation was needed. The initial peer-error
conversion test failed compilation, the external fixture build exposed the
allocation-feature bug, and an expanded test temporarily shadowed helper
names. Each was repaired and its affected gate rerun; original failed logs
are retained and are not represented as passes.

The eight generated Azure policy/chain fixtures were archived and restored
byte-for-byte. No task listener remains. The lockfile, both frozen corpora,
prior accepted manifests, HEAD/submodule revisions, 37-step canonical order,
old central-log prefix and technical-note sections1-25 are preserved.

### Deferred qualification and downstream obligations

AAS1A-M must supply the actual approved V6 layout/base-report authentication,
authenticated supplement composition and full common-claims admission
conformance after Task6/AAS1A, then rerun the relevant T4.17-T4.19 gates.
Production transport, trusted time/state/persistence, installation/rebind
effects and hardware/deployment/RNG qualification remain unprovided.
No new kernel entropy-provenance prerequisite is invented by these tests.
No effectful V2 caller, Task3 runtime exchange, production/readiness-row
qualification or GitHub-hosted CI/SARIF is claimed. Historical ignored/excluded
upstream tests are not newly claimed passed. No completion acceptance,
T4.18 start, broader phase approval, commit or push.

## 27. T4.17 bounded completion acceptance

The user explicitly accepted:

> I accept T4.17 within its documented bounded scope and exclusions.

Acceptance timestamp: `2026-11-05T17:27:38.397Z`.
Accepted completion identifier: `T4.17-InterfaceConformance-2026-11-05`.
Disposition: DONE - ACCEPTED within the documented bounded scope and exclusions.
No additional conditions were specified; existing exclusions remain in force.

Acceptance covers the bounded interface/provider conformance, exact rejection
and no-effect checks, common-claims identity projection, deployed-consumer
feature/API isolation checks, explicit allocation-feature repair and validation
recorded in section26. It does not convert controlled interface outputs into
authenticated attestation, identity projection into full policy admission,
or failed/ignored/excluded tests into passes.

The accepted manifest is
`target/t4.17-interface-conformance/20261105T162233Z/validation-manifest.json`,
SHA256 `e8d96297d73c4d364a9cbbe794f772194ce83447dcf881048f082c9e3eb7cc3d`.
Its recorded source/document hashes matched the pre-acceptance state.
The immutable manifest and validation history are not rewritten.

Existing exclusions remain: no operational AAS V6/layout adapter, production
providers, full common-claims admission, effectful V2/Task3 runtime activation,
RNG/hardware/deployment/readiness qualification or GitHub-hosted CI/SARIF.
AAS1A-M must complete actual authentication/composition after Task6/AAS1A and
rerun the relevant T4.17-T4.19 gates. No physical layout is guessed and no new
kernel entropy-provenance prerequisite is introduced.

The central ACCEPTANCE event is appended to
[implementation_record.log](../implementation_record.log).
T4.18 is READY for separately authorized implementation and remains NOT STARTED.
This acceptance does not start it or approve a broader phase.
Recording changes documentation only; source, lockfile, prior technical-note
sections1-26, central-log history and accepted evidence remain unchanged.
No commit or push.

## 28. SDK 8774be3 update and regression

The user requested build/test reruns after the SDK checkout advanced nine
commits, then supplied old `046690a` and new `8774be3` on clean `main`.
Request timestamp: `2026-11-05T17:30:20.359Z`.
Validation timestamp: `2026-11-05T18:01:29.016Z`.
Disposition: PASS for the configurations and invocations below; separate
maintenance validation, not another phase acceptance or T4.18 authorization.

### Dependency and backend selection

MigTD was still pinned to the old revision, so rerunning without changing the
pin would not have exercised the updated SDK. The exact dependency moved from
`046690a1f247f2b524bd02b71eb302745d06cfc6` to
`8774be30f452060c56372d34ccbe34c3d3f3c577`.
The SDK and its azure-tpm dependency both advance from 0.1.0 to 0.2.0.
Only those two Cargo.lock package records change; unrelated versions,
sources and dependency edges are retained.

Previously, SDK `verify` implicitly selected `native`. SDK 0.2.0 separates
backend selection, so MigTD now explicitly selects `native,verify` with
default features still disabled. This preserves existing Linux native
verification instead of switching to SymCrypt or RustCrypto. The persistent
feature checker also requires these SDK features and rejects either alternate
backend in the production graph. Bare-metal TDX remains independent of this
Linux/std dependency. The common AAS V6/layout adapter is still unavailable;
this is not its implementation or activation.

### Final validation

Evidence: `target/sdk-8774be3-regression/20261105T173020Z/`.
The final `validation-manifest.json` binds all final command results,
dependency/source hashes, failed attempts, restoration and preservation checks.

| Gate | Final result |
|---|---|
| PAL default / system-random units and doctests | 34/6 and 35/6 PASS |
| PAL snp-core / snp-fixture | 420/26 each PASS |
| PAL snp-emu / snp-production | 427/26 and 420/27 PASS |
| MigTD serial SNP library / standalone SNP emulator | 67 and 7 PASS |
| Registered libraries | Complete suite PASS with `RUST_TEST_THREADS=1`; existing ignored test remains ignored |
| Feature/dependency/external-consumer checks | 55 PASS, including explicit native backend selection |
| Frozen P0.10 / direct-random V2 independent references | PASS; corpora unchanged |
| Workspace/scoped strict Clippy | PASS |
| Rust1.88 local CI command parity | Format/check/CI-Clippy, all deny checks, 32 firmware builds, six tools, 14 EMU scenarios PASS; all 28 process exits zero |
| Rebuilt musl SNP Stage A/B | PASS with the frozen historical host controller |
| Production binary and negative boundaries | Build PASS; designed unavailable startup exit2 and release-bypass compile rejection confirmed |
| Upstream SDK native,verify suite | 291 unit tests and 11 doctests PASS; one existing live-THIM test ignored |
| Upstream azure-tpm native suite | 141 unit tests and 2 doctests PASS |
| Upstream SDK/TPM native strict Clippy | PASS |

MigTD SNP/strict and upstream SDK checks use Rust1.90; local CI parity uses
Rust1.88. Already-valid preparation was retained; MigTD submodule revisions
did not change. The external SDK checkout remains clean at the requested
commit, including its own unchanged lockfile.

### Failed attempts and the serial host-test boundary

The initial offline upstream SDK test could not resolve a missing
`ms-tpm-20-ref` git submodule source. A locked online invocation restored the
required test source and completed successfully. No upstream source patch or
dependency-version workaround was needed; the failed attempt is retained.

The first default-parallel `cargo xtask lib-test` run failed the existing
`migration::logging::test::test_log_info` request-ID assertion. Logging tests
observe process-global buffers and an installed global logger; their own
`TEST_LOCK` does not prevent other module tests from emitting log records.
The observed configuration was `main,policy_v2,vmcall-raw`, without the SDK.
No new SDK execution or production concurrency defect is inferred.

The complete registered suite, without dropping or weakening assertions, was
rerun successfully with:

```bash
RUST_TEST_THREADS=1 cargo xtask lib-test
```

Serial execution is the validated invocation. Production/test logging source
was not changed, so this is not a claim that the default parallel runner has
been made race-free. The initial assertion failure remains in the evidence.
Existing ignored library tests and SDK
`tee_report::fmspc_resolver::tests::thim_live_tdx_lookup` remain excluded,
not claimed passed. No live THIM, Windows, SymCrypt or reference-vTPM
qualification is implied by the selected native tests.

### Preservation and scope

The eight regenerated Azure policy/chain fixtures were archived and restored
byte-for-byte, and no task listener remains. HEAD, MigTD submodules, the
37-step canonical order, both frozen corpora, the prior central-log prefix
and technical-note sections1-27 are unchanged. The T4.17 validation manifest
SHA256 remains
`e8d96297d73c4d364a9cbbe794f772194ce83447dcf881048f082c9e3eb7cc3d`;
its bounded acceptance recording SHA256 remains
`4adde8bbcd60f93519634d443665b4a59cb1a22dfeb6f25d3ed908cc2f1e712c`.
Those artifacts and their preserved evidence were not rewritten.

No phase order, accepted contract, frozen encoding or direct-random V2
semantics change. Production AAS/layout/transport/state/effect providers remain
explicitly unavailable. No readiness-row, hardware/RNG/deployment or hosted-CI
qualification is claimed. T4.18 remains READY for separate authorization and
NOT STARTED. No commit or push.

## 29. T4.18 caller integration

Authorized by `Implement T4.18` at `2026-11-05T18:20:16.530Z`.
Bounded validation recorded at `2026-11-05T18:58:22.061Z`.
Completion identifier: `T4.18-CallerIntegration-2026-11-05`.
Completion acceptance is **PENDING**; this is not a user acceptance record.
T4.19 remains NOT STARTED.

### Caller ownership and compatibility register

| Caller/surface | Implemented routing and boundary |
|---|---|
| SNP executable entry | Direct SNP entry module, separate from the unused TDX dispatcher; one root after configuration/platform-mode validation |
| WFR GetTDReport and SPDM requester/responder evidence | Explicitly shared root; selected `MaEvidenceProvider` and `SnpCollateralProvider`; no direct fixture construction in these callers |
| Legacy blob construction | One fixture-only encoder, unchanged raw report + two length-prefixed DER certificates; cannot relabel requested/live evidence or VLEK as a captured VCEK fixture |
| Legacy local SDK verification | Root-owned, explicitly named captured-fixture compatibility; real SDK signature/chain checks retained, not live TH1 binding or common V6 claims |
| Common report verification | Frozen selected verifier remains `ProviderUnavailable`; successful legacy verification cannot enable it or supply an alternate fallback |
| Legacy key-only installation | Explicit root-owned mock, passed through session and both SPDM roles; temporary key bytes still zeroized; no invented tenant/session/history inputs for V2 installation |
| Linux MA acquisition | Existing `/dev/sev-guest` adapter explicitly selected in the closed hardware set; no hardware execution, ABI qualification or fresh-report verification claimed |
| Production bootstrap | Consumes selected logical host transport; reports `HostControl(ProviderUnavailable)` and exits2 before any report ioctl or host operation |
| V2 peer/host transports, context authority, replay/current-firmware state, installation, binding/handoff | Existing frozen selected seams retain explicit unavailable implementations; no legacy transport/mock is silently promoted |
| Randomness/platform keys | Existing privately owned `SystemRandomSource` retained; no RNG provenance/quality qualification or platform-derived-key prerequisite added |
| TDX/AzCVMEmu | Existing behavior and wire remain unchanged; inherited SNP transport/proof placeholders are explicitly legacy until Task5 |

The root is owned once per emulator process and shared with explicit `Rc`
handles, not a provider registry, per-call reconstruction or hidden global
selector. Selected mutable borrows end before awaits. Shared SNP contracts do
not inspect backend features. Remaining TDX-shaped compatibility guards are
not a new V2 selector or an activation of Task3.

All valid legacy blob bytes remain unchanged. The refactored parser additionally
rejects every truncation, invalid certificate length and trailing data before
SDK verification. Signature/report-data tampering still fails cryptographic
verification. WFR GetTDReport now preserves a failed acknowledgement's transport
status and stops rather than silently continuing.

The authority remains Firmware ABI1.59 / ARGv1.20 and the accepted addenda.
MA acquisition is not authentication, tenant evidence or policy approval.
No Version6 migration-data/ETCB overlap is guessed, no `MSG_VERIFY_REPORT` or
platform-derived key is introduced, and no TAV fallback exists. SDK/azure-tpm
0.2.0 remains pinned to `8774be30f452060c56372d34ccbe34c3d3f3c577`, with the
unchanged explicit native verification backend and byte-identical lockfile.

### Executed validation register

Evidence directory:
`target/t4.18-caller-integration/20261105T182016Z/`.
The generated [manifest](../../target/t4.18-caller-integration/20261105T182016Z/validation-manifest.json)
records final commands, failed attempts, source/evidence hashes and preservation.

| Gate | Final result |
|---|---|
| PAL default / system-random | 34/6 and35/6 unit/doctest passes |
| PAL SNP core / fixture / emulator / production | 420/26,422/26,429/26,420/27 unit/doctest passes |
| Standalone SNP emulator crate | 7 unit tests pass |
| MigTD SNP / hardware library | 72 and12 tests pass; includes selected caller/failure and real bootstrap-boundary checks |
| Registered library runner | Complete suite passes with `RUST_TEST_THREADS=1 cargo xtask lib-test`; existing ignored test remains excluded |
| Feature/dependency/external-consumer matrix | 57 checks pass, including legacy `SnpEmu` alias and production exclusion of the fixture encoder |
| Independent P0.10/direct-random references | Pass; frozen corpora unchanged |
| Strict checks | Workspace, PAL core/emulator and hardware scoped `-D warnings` commands pass |
| Additional legacy SNP Clippy | Command passes with existing inherited warnings; not a warning-free claim |
| Local Rust1.88 CI command parity | Repository formatter/check/CI-Clippy, all deny checks,32 firmware builds,six tools,14 EMU scenarios pass; all28 process exits zero |
| Native production artifact | Build and fixture-byte/forbidden-symbol isolation checks pass; designed startup exit2 and release-bypass compile rejection confirmed |
| Rebuilt musl legacy Stage A/B | Pass against the frozen historical host controller; rebuilt controller also compiles |

Eight new tests cover two encoder boundaries, four selected-root paths,
the terminal WFR acknowledgement failure and production bootstrap's typed
unavailable result. Root tests prove actual selected evidence/collateral
call-through, no fallback after either provider fails, exact captured segments,
all truncations/trailing/oversized cases, tampering and separation of successful
legacy services from unavailable common verification/state/effects.
They supplement, rather than replace or rewrite, the frozen conformance corpus.

### Retained failed attempts and existing limitations

The first feature matrix exposed a binary-only compile failure: an unused TDX
dispatcher was still compiled under SNP and referenced the old exchange
signature. The SNP entry module was separated from that dispatcher instead of
adding a dummy provider or fallback. The failed matrix/log is archived under
`feature-matrix-attempt1`; all57 final checks and rebuilt binaries pass.

An additional, non-CI `cargo fmt --all -- --check` reported existing formatting
in the patched ring and TDX emulator dependency trees. Those files are unchanged;
no vendor-wide formatting churn or waiver of the actual CI gate was made.
The exact repository command `cargo fmt -- --check` passes, as does the full
CI formatter. Both attempts remain in the evidence.

The documented global-logging interference still requires serial registered
host tests. Existing ignored tests, inherited legacy SNP lint warnings, common
AAS/layout execution, real hardware acquisition/effects, RNG/deployment and
hosted-CI qualification are not represented as fixed or passed. Local SDK
compatibility is not the future AAS1A-M common-claims adapter.

### Preservation and disposition

The eight generated Azure policy/chain fixtures were archived and restored
byte-for-byte. The64 CI log files are independently archived; no task listener
remains. HEAD, submodule revisions, the SDK pin/lockfile, both frozen corpora,
prior accepted manifests/evidence, the37-step canonical order and the full
previous central-log/technical-note prefixes are preserved. Sections1-28 above
are historical and unchanged.

No phase order or accepted wire/identity/policy/direct-random V2 contract changes.
No complete Task3 exchange, production/readiness-row qualification, completion
acceptance or T4.19 start is implied. No commit or push.

## 30. T4.18 bounded completion acceptance

At `2026-11-05T19:04:48.267Z`, the user stated:

> I accept T4.18 within its documented bounded scope and exclusions.

This accepts `T4.18-CallerIntegration-2026-11-05` within the scope and exclusions
recorded in section29. No additional conditions were specified; all existing
limitations and deferred obligations remain in force. Section29 is the
unchanged historical implementation/validation record; this section records
the subsequent explicit acceptance.

The accepted validation manifest remains:
`target/t4.18-caller-integration/20261105T182016Z/validation-manifest.json`.
Its SHA256 is
`e46ddb5cca6fa05394e2414a95e5cff42f75d916a4f7155bcaf115a5b1ffde97`.
Its source/evidence inventory and1064 historical evidence files were verified
before recording acceptance. The manifest, logs, binaries and prior evidence
are not rewritten or reclassified as new test results.

Only the central log and current plan/readiness/README dispositions change,
with this append-only technical note. Source, lockfile, both frozen corpora,
HEAD/submodules, the37-step canonical order and earlier log/note prefixes are
preserved. Documentation-only acceptance recording requires no new build or
test run. Recording verification is preserved under
`target/t4.18-acceptance/20261105T190448Z/`.

The accepted limitations still include unavailable common V6/AAS/layout and
production transport/state/effect providers; unqualified and unexercised Linux
MA acquisition; legacy SDK/mock compatibility that is not common claims or V2
installation; serial registered tests, existing ignored tests and inherited
lint/vendor-formatting limitations. No full Task3 activation, readiness-row,
hardware/RNG/deployment or hosted-CI qualification is implied.

T4.19 is READY for separate implementation authorization and remains NOT
STARTED. This acceptance does not start it or accept any later phase.
No commit or push.

## 31. T4.19 Task 4 regression

Authorized by **"Implement T4.19"** at `2026-11-05T19:45:40.638Z`.
Bounded validation recorded at `2026-11-05T20:12:53.102Z`.
Completion identifier: `T4.19-Task4Regression-2026-11-05`.
Status: **VALIDATED; explicit bounded completion acceptance PENDING**.
T4.18 acceptance and its exclusions remain unchanged.

### Implementation and coverage boundaries

This step adds regression coverage and reproducible provisional image
inventories, not a new protocol, provider implementation or runtime activation.

| Surface | Executed coverage | Boundary |
|---|---|---|
| PAL/provider interfaces | Default/system RNG, core, fixture, emulator and production suites; existing available verifier/conformance cases | Controlled verifiers and legacy SDK crypto are not the unavailable common V6 adapter |
| `InterNodeTwoProcessMigration` composition | Valid source/destination requests in both provider-set compositions return the exact unavailable peer-provider error | Constructor/provider composition; not full Task 3 activation |
| `LocalMaHandoffTwoProcess` composition | Valid outgoing/incoming requests in both compositions return the same typed unavailable error | No local two-process handoff or firmware-state emulator is executed; R4.2 remains later work |
| Feature/API isolation | All 57 positive/negative/dependency/external-consumer checks | Missing providers fail closed; no TAV or fixture fallback |
| Provisional inventory tool | Seven unit controls plus both actual release builds, with defaults disabled and explicit target | Fresh output directory; no overwriting accepted inventories |
| Production isolation | Byte scans for captured report/VCEK/ASK and both P0.10 synthetic root DER values; named fixture/mock/test/TDX symbol/string checks | Named-assets and surviving-symbol evidence, not proof of runtime capability |
| Emulator positive control | All three captured report/certificate assets are present in its rebuilt ELF | Captured fixture trust, not fresh REPORT_DATA/TH1 evidence |
| Production startup | Selected host-control error is `HostControl(ProviderUnavailable)`, exit 2, no emulator fallback | Before report ioctl or host operation; Linux MA acquisition remains unexercised/unqualified |
| TDX/AzCVMEmu preservation | Full firmware/tool/EMU CI command parity and strict checks | Local validation only, not hosted CI or physical hardware |
| Legacy SNP compatibility | Rebuilt musl Stage A/B with frozen historical host controller | Existing legacy SDK and key-only mock path; not common claims or V2 installation |

The new Rust test uses canonical purpose-specific contexts: inter-node
source/destination and local planned outgoing/incoming. The local context
retains `LocalHandoffSecretV1`, version 1 and zero tenant binding. All eight
composition/role cases reach the selected unavailable peer provider rather
than succeeding or failing an unrelated codec guard. No real device call is
introduced into host tests.

The new inventory tool is
[`snp_task4_inventory.py`](../../sh_script/test/snp_task4_inventory.py), with
[`test_snp_task4_inventory.py`](../../sh_script/test/test_snp_task4_inventory.py)
positive/negative controls. Both `SnpEmuAzure` and `SnpHardware` builds explicitly
use `--release --no-default-features --target x86_64-unknown-linux-gnu`,
`--offline --locked`, Rust 1.90 and `AS=nasm AR=llvm-ar CC=clang`.
Each ELF is copied before the other build, with its own immutable manifest,
source snapshot hashes, target, environment and normal/build dependency-feature
inventory. Command and symbol logs are retained alongside the manifests.
Cargo diagnostic stderr is archived but not parsed as dependency data.

These are **provisional ELF-only image-content inventories**, not P2.2
versioned/qualified bundles; kernel/initramfs and deployment qualification are
not included. A genuine public AMD ARK is not a synthetic root or a forbidden
captured-report fixture. The production linker may eliminate the unreachable
source-selected Linux acquisition adapter; neither its absence nor its presence
qualifies hardware acquisition or report freshness.

### Validation and retained attempts

Evidence: `target/t4.19-task4-regression/20261105T194540Z/`.
The validation manifest is `validation-manifest.json` in that directory.

| Gate | Final result |
|---|---|
| Final distinct local command gates | 26 PASS, including expected negative exits |
| Inventory-tool unit controls | 7 PASS |
| PAL default / system-random units and doctests | 34/6 and 35/6 PASS |
| PAL core / fixture | 421/26 and 423/26 PASS |
| PAL emulator / production | 430/26 and 421/27 PASS |
| Standalone SNP emulator / MigTD emulator / hardware libraries | 7 / 72 / 12 PASS |
| Registered library suites | Complete serial run PASS; one existing ignored test remains ignored |
| Feature/dependency/external API checks | 57 PASS |
| Independent P0.10 / direct-random V2 references | PASS; both frozen corpora unchanged |
| Workspace and scoped strict Clippy | PASS; no lint suppression |
| Legacy SNP Clippy | PASS with inherited warnings, not warning-free qualification |
| Rust 1.88 local CI command parity | Format/check/CI-Clippy, all three deny checks, 32 firmware images and six tools PASS |
| AzCVMEmu integration matrix | 14 scenarios, all 28 MA process exits zero; policy generation and four prebuilds also PASS |
| Explicit emulator/production release inventories | PASS; production isolation scan empty and expected startup exit 2 |
| Release hardware plus bypass | Deliberate compile rejection with the required diagnostic |
| Rebuilt musl Stage A/B | PASS; both MA exits zero in each stage, both Stage B controller exits zero |

All 64 current CI logs are archived. The summary distinguishes the 14 actual
EMU scenarios from policy generation and four build steps; process exits are
read from the exact source/destination exit-code markers, not inferred from a
top-level success. The SDK remains pinned to
`8774be30f452060c56372d34ccbe34c3d3f3c577` with explicit `native,verify`;
no dependency/lockfile/submodule change or preparation rerun was needed.
The validated registered invocation remains
`RUST_TEST_THREADS=1 cargo xtask lib-test`.

Failed attempts are retained, not counted as passes:

- The first new local-composition test used an inter-node algorithm/tenant
  binding in a local context and was correctly rejected by the frozen codec.
  Correcting only the test context made all eight intended cases reach the
  unavailable provider. Production contracts were not weakened.
- The first inventory run attempted to parse Cargo stderr warnings as tree
  data. Separating stdout from archived diagnostics repaired the tool; its
  unit controls and both complete inventories were rerun successfully.
- The session-local CI archive counter initially treated all EMU stage steps
  as scenarios and used an incorrect exit-label pattern. The completed
  gauntlet itself passed. The corrected archive audit independently verifies
  32 images, six tools, 14 scenarios and all 28 zero exits. No scenario was
  dropped or rerun to conceal a failure.

Separate inventories within the evidence directory:

| Composition | Manifest | ELF SHA256 |
|---|---|---|
| Emulator | `image-inventories/SnpEmuAzure/manifest.json` | `fcb1710527bdc4f9ae0be8c236a22840e7fa3f8643244cce0d82b1e3e57633c1` |
| Production | `image-inventories/SnpHardware/manifest.json` | `ba5cc3594058d4c42921dc6ce29751abc36cf2714f0b9a0c9e587694aae767ea` |

The inventories preserve build-time source/document hashes; the final
validation manifest separately binds the subsequent completion documentation.
Neither is rewritten to accommodate future acceptance or bundle work.

### Deferred executable verifier obligations

The following are **DEFERRED / NOT EXECUTED**, not passing tests. AAS1A-M owns
closure after Task 6/AAS1A with the accepted actual adapter and signed fixtures,
and must rerun the relevant T4.17-T4.19 gates before Task 7:

| Obligation | Required later execution |
|---|---|
| Approved V6 layout and base-report authentication | Exercise the actual backend, exact authenticated fields and explicit unsupported/conflicting-layout failures without guessed offsets or partial/default claims |
| Authenticated report/supplement composition | Run the actual adapter over the signed emulator profile, report/signature association, all claims/digests/ETCB consistency and production rejection of fixture trust |
| Common-claims policy admission and provider conformance | Replace controlled verifier outcomes with actual authenticated claims, validate complete admission rather than identity projection alone, and rerun the recorded deferred composition/conformance cases |

TDX remains architectural precedent, not authority for SNP command or layout
semantics. The accepted Firmware ABI 1.59 / ARG v1.20 addendum remains unchanged;
the V6 migration-data/ETCB overlap is not resolved by these regressions.
No `MSG_VERIFY_REPORT`, TAV fallback or new platform-derived-key prerequisite
is introduced.

### Preservation and disposition

The fresh 512-file baseline matches accepted T4.18 source; only its five
subsequent acceptance documents differ from the implementation snapshot.
All 1286 prior owned evidence files were verified and remain unchanged.
Eight generated Azure policy/chain fixtures were restored byte-for-byte;
all 13 Azure configuration files, lockfile, both frozen corpora, HEAD/submodules,
37-step order, old central-log prefix and technical-note sections 1-30 are
preserved. No task TCP listener remains.

Common AAS V6/layout, production transport/state/authority/effect providers,
Linux hardware acquisition, replay persistence, local handoff and deployment/
RNG qualification remain unprovided or unqualified as previously documented.
Existing serial-test, ignored-test, inherited legacy lint and vendor-wide
formatting limitations are not claimed fixed. The exact repository/CI formatter
passes; the extra non-CI vendor-wide check was not reclassified or rerun here.
No readiness row, full Task 3/V2 activation, hardware or hosted-CI/SARIF
qualification is claimed. Completion acceptance is PENDING.
T4.20 is not authorized or started. No commit or push.

## 32. T4.19 bounded completion acceptance

At `2026-11-05T23:49:26.373Z`, the user stated:

> I accept T4.19 within its documented bounded scope and exclusions.

This accepts `T4.19-Task4Regression-2026-11-05` within the scope and exclusions
recorded in section 31. No additional conditions were specified; all existing
limitations and deferred obligations remain in force. Section 31 remains the
unchanged historical implementation/validation record.

The accepted validation manifest remains:
`target/t4.19-task4-regression/20261105T194540Z/validation-manifest.json`.
Its SHA256 is
`07711bd07565e91373f58ed639dec576649fb8c10de80316938acd19d5a07d44`.
The 514-file source/document inventory and 1514 prior/current owned evidence
files were verified before recording acceptance. The validation manifest,
separate provisional image inventories, archived logs, binaries and earlier
evidence are not rewritten or reclassified as new test results.

Only the central log and current plan/readiness/README dispositions change,
with this append-only technical note. Source, lockfile, both frozen corpora,
HEAD/submodules, the 37-step canonical order and earlier log/note prefixes
remain preserved. Documentation-only acceptance recording requires no new
build or test run. Recording verification is preserved under
`target/t4.19-acceptance/20261105T234926Z/`.

The accepted exclusions still include unavailable common AAS V6/layout and
actual composed-claims verification; unqualified production transport/state/
authority/effect providers and Linux MA acquisition; local-handoff composition
tests that are not a two-process runtime; legacy SDK/mock compatibility that
is not fresh TH1 evidence, common claims or V2 installation; and provisional
ELF inventories that are not P2.2 bundles. Existing serial/ignored-test,
inherited lint and vendor-wide formatting limitations remain explicit.
No full Task 3 activation, readiness-row, hardware/RNG/deployment or hosted-CI
qualification is implied.

T4.20 is READY for separate implementation authorization and remains NOT
STARTED. This acceptance does not start it or accept any later phase.
No broader acceptance, commit or push.

## 33. T4.20 Task 4 freeze

Status: implemented and validated within bounded scope; explicit user acceptance
pending. Authorization: `2026-11-05T23:50:40.311Z`.
Freeze identifier: `T4.20-Task4Freeze-2026-11-05`.

The user explicitly selected a documentation-only freeze commit, leaving the
audited implementation uncommitted and identified by hashes. No source, Cargo
files, scripts, fixtures, submodules or unrelated worktree changes are included.
Some existing freeze documents were untracked: their first commit contains
their historical contents as well as T4.20 changes. The documentation commit is
not a reproducible committed implementation tree. No push is authorized.

Deliverables:

- [Audit and freeze record](task4/task4-freeze.md), including exact present
  availability, accepted policy/profile authority and qualification exclusions.
- [Consumer-readiness matrix](task4/consumer-readiness-matrix.md), covering
  AAS1A/AAS1A-M, every Task5-14, R4.1-R4.7, P2.1/P2.2 and H5.0-H5.7.
- Four corrected [ownership](task4/rust-type-provider-diagram.md),
  [composition](task4/provider-set-diagram.md),
  [feature](task4/feature-selection-diagram.md) and
  [sequence](task4/sequence-diagrams.md) diagrams.
- [Freeze inventory](task4/freeze-inventory.json):470 audited non-document
  input hashes and submodule revisions, all57 accepted feature/API gate results,
  all three inherited deferred-verifier rows and separate
  [emulator](task4/image-content/SnpEmuAzure.json) /
  [production](task4/image-content/SnpHardware.json) accepted ELF manifests,
  including complete resolved normal/build dependency inventories.

The audit reconciles active stale V1 handoffs with the already accepted
direct-random V2 amendment; no source, frozen bytes or protocol semantics change.
Actual provider ownership is boxed/generic with borrowed service refs; tenant
source is operation-local. No invented operational verifier, state store,
injected tenant slot, `Arc` provider framework or Underhill peer is asserted.

Both selected common V6 verifiers remain unavailable and yield no claims.
The captured-v5 SDK/key-only emulator bridge remains isolated compatibility,
not the signed V6 supplement profile. Production startup fails at unavailable
host control before report acquisition; the named raw V6 layout blocker is a
deferred common-adapter obligation, not the observed startup error.
Task6/AAS1A-M must close inherited T4.17-T4.19 executable authentication,
profile/layout/error and purpose6/7 handoff tests before Task7. Production
state, effects, trust/time/revocation, transport, RNG, shutdown inventory,
deployment and actual hardware remain unqualified. No PA row advances.
Task12/purpose3 remains separately deferred and is not a current readiness gate.

Fresh T4.20 verification checks source/evidence correspondence, exact accepted
ELF bytes and copied manifests, matrix coverage/source symbols, relative links,
diagram structure, append-only historical prefixes, the unchanged37-step order
and explicit documentation-only commit scope. Accepted T4.19 26 command gates,
32 firmware builds and14 EMU scenarios are reused evidence, not rerun tests.
There is no source behavior change requiring a new runtime test execution.

Final fresh checks pass:470 unchanged audited inputs,1518 preserved historical
evidence files,505 untouched baseline files,64 relative links,29 downstream
consumer rows and30 actual producer symbols. The four Mermaid files were
checked for fences/diagram-kind structure, not rendered. Initial session-only
validator whitespace/schema assumptions were corrected; the source-symbol
check also corrected the new diagram/matrix clock label to `PeerClockV1`.
Attempts and corrections are retained in `validation-attempts.json`; none
required a source change or an alteration of canonical-order bytes.

Evidence: `target/t4.20-task4-freeze/20261105T235040Z/`.
The fresh `validation-manifest.json` records pre-commit verification;
`commit.json` records the actual documentation commit and post-commit checks
without a self-referential commit-hash claim. The central log records this
freeze and its limits. T4.19 acceptance is preserved. T4.20 acceptance and
Phase1 closure remain pending; P2.1/P2.2 remain NOT STARTED.

## 34. T4.20 bounded completion acceptance

Status: DONE - ACCEPTED AND FROZEN within the documented bounded scope and
exclusions at `2026-11-06T00:32:02.025Z`; conditions: None.
Freeze identifier: `T4.20-Task4Freeze-2026-11-05`.

The user explicitly stated:

> I accept T4.20 within its documented bounded scope and exclusions.

This accepts the [Task4 audit/freeze](task4/task4-freeze.md), corrected diagrams,
consumer-readiness/feature matrices, source-hash record and separate accepted
ELF/dependency inventories within section33's exact bounds. The existing
documentation-only freeze commit is
`ab91f5f9194152cd4e5440ec050c447de5de8f0d`. The audited implementation remains
uncommitted and hash-identified; that commit alone is not a reproducible source
tree. Acceptance does not authorize an implementation commit or push.

The Phase1 gate is satisfied at the documented interface level only.
P2.1 is READY for separate implementation authorization, NOT STARTED.
P2.2 remains NOT STARTED pending P2.1 completion and separate authorization.
No later task is started by this acceptance.

All existing exclusions remain: unavailable common V6/AAS and final providers;
Task6/AAS1A-M's inherited executable-verifier obligations before Task7; no full
Task3/V2 runtime, production transport/state/effects/trust/time/revocation/RNG,
deployment, authoritative shutdown or hardware/end-to-end migration
qualification. No PA row advances. Task12/purpose3 remains separately deferred
and is not a current readiness gate.

Recording evidence: `target/t4.20-acceptance/20261106T003202Z/`.
Before editing,519 existing files,470 audited non-document inputs and1535
prior evidence files were verified and captured. Fresh recording verification
checks the exact six-document change scope, all other file hashes, full
historical log/note prefixes, accepted evidence and the unchanged37-step
canonical order. Section33 and the original freeze inventory/validation/commit
receipts remain unchanged historical snapshots; their acceptance-pending
fields are superseded by this explicit record, not silently rewritten.

This is documentation-only acceptance recording. No tests/builds are rerun,
no fresh runtime or production result is claimed, and no new commit or push is
made. Exact recording checks and hashes are in `recording-verification.json`.

## 35. P2.1 descriptive migration scenario terminology

Status: implemented and validated within bounded scope; explicit user acceptance
pending. Authorization: `2026-11-06T00:34:35.144Z`.
Completion identifier: `P2.1-ScenarioTerminology-2026-11-06`.
Separate naming-only commit:
`1dbb3e6bf8e9f3666d9a5ead2dbb6e66b6d15481`.

The user explicitly selected: commit only P2.1 naming changes; leave
prerequisite changes uncommitted. The tested working scripts retain accepted
uncommitted MSG_KEY_REQ rejection assertions. Their staged counterparts are
exact naming transforms of the parent commit's scripts, not a covert commit
of those prerequisite behavior changes. The accepted assertion delta remains
intact at the canonical paths. Prerequisite acceptance-record updates also
remain uncommitted. The rename-only commit is not a reproducible snapshot of
the accepted working implementation.

Implemented current names:

| Canonical scenario | Current runner / disposition |
|---|---|
| `SingleProcessMigration` | `run_snp_single_process_migration.sh`; existing autostart source/destination workflow |
| `InterNodeTwoProcessMigration` | `run_snp_inter_node_two_process_migration.sh`; existing WFR/controller and two-MA workflow |
| `LocalMaHandoffTwoProcess` | Reserved Phase4 local old/new-MA workflow; no current executable runner to rename or activate |

The [scenario guide](../snp-migration-scenarios.md) documents exact canonical
environment variables, output/evidence names and aliases. The old script paths
are thin executable delegates and old environment variables remain fallbacks;
nonempty canonical values win. Positional arguments, role/start-mode flags,
ports/timeouts, explicit evidence paths, manifest fields, process topology,
protocol and trust are unchanged. The single-process label does not merge
the legacy runner's source/destination OS processes.

An active-reference audit found no stage-letter Rust/CLI symbols or CI
commands requiring a rename. Active guide/README and the live T4.10 test
instruction now use canonical names. Historical validation summaries, frozen
addenda, hashes, commits, inventory manifests and prior log/note bytes retain
their original terminology. Old-name occurrences in active runners/tests are
explicit compatibility aliases, not primary scenario names.

Fresh validation:

- Bash syntax and ShellCheck pass for both canonical runners and both aliases.
- Eight naming/compatibility tests pass on the working tree and again on an
  isolated eight-file rename-only index snapshot. Deliberately failing
  processes exercise naming, defaults, alias forwarding, environment priority/
  empty-value fallback, address rejection and exit status; no successful
  attestation/migration doubles are claimed.
- Both canonical runners and both old-path/old-env aliases pass sequentially
  using the same frozen accepted musl MigTD and controller:12 zero MA/controller
  exits. The scenario ports have no remaining listeners.
- MigTD SHA256:
  `2a1933640374ed55a3becc377c989314039ede0b5ef9e0baea50d35109da91d5`.
  Controller SHA256:
  `166ec9302efcd9f655ba243b25756153a32beadf5b30afa3cc2bba67dbc7c2a9`.
- Mechanical equivalence proves each working runner is only a naming transform
  of the accepted input, and each staged runner is only that transform of its
  parent-commit input. All eight committed bytes match the isolated tested
  index; prior implementation and acceptance changes were excluded.

No Rust source, dependency, lockfile, fixture or firmware behavior changes.
The unchanged Rust/full-CI suites are not rerun or relabeled as fresh results;
accepted earlier evidence is preserved. These are legacy captured-fixture
scenario regressions, not common V6/AAS, active V2, local-handoff, production
or actual page migration/resume qualification. No PA row advances.

Evidence: `target/p2.1-terminology/20261106T003435Z/`.
Baseline:519 files,1540 prior evidence files and two frozen executables.
`rename-equivalence.json`, `validation-manifest.json`, `scenario-results.json`
and `commit.json` record exact source/index equivalence, checks, executions and
persisted commit scope. Final `recording-verification.json` verifies the
expected seven existing/four new working files,512 untouched baseline files,
all prior evidence, historical log/note prefixes and the37-step canonical order.
No push. Bounded P2.1 acceptance is pending; P2.2 remains NOT STARTED pending
that acceptance and separate implementation authorization.

## 36. P2.1 bounded completion acceptance

Status: DONE - ACCEPTED AND FROZEN within the documented bounded scope and
exclusions at `2026-11-06T00:47:34.984Z`; conditions: None.
Accepted completion identifier: `P2.1-ScenarioTerminology-2026-11-06`.

The user explicitly stated:

> I accept P2.1 within its documented bounded scope and exclusions.

This accepts section35's exact naming-only implementation and validation:
canonical runner/environment/evidence/diagnostic names, explicit old-name
compatibility aliases, current usage documentation and the reserved
`LocalMaHandoffTwoProcess` name. It does not activate that local runtime or
change process topology, protocol, trust, firmware operations or manifest
semantics. Historical records retain their original terminology and bytes.

The accepted naming-only commit remains
`1dbb3e6bf8e9f3666d9a5ead2dbb6e66b6d15481`. Prior implementation and acceptance
changes remain intact and uncommitted; that commit alone is not a reproducible
snapshot of the accepted working implementation. No implementation commit,
amendment or push is authorized by this acceptance.

All documented exclusions remain: legacy captured-fixture scenarios only;
no common V6/AAS or active V2 qualification, local handoff, production
state/effects/trust/time/revocation/RNG/deployment/shutdown/hardware or actual
page migration/resume qualification. No PA row advances. Task12/purpose3
remains separately deferred and is not a current readiness gate.

P2.2 is READY for separate implementation authorization, NOT STARTED.
This acceptance does not start P2.2, accept Phase2 as a whole or waive any
downstream prerequisites. T4.20 and the bounded Phase1 disposition are unchanged.

Recording evidence: `target/p2.1-acceptance/20261106T004734Z/`.
Before editing,523 existing files and1600 prior evidence files were verified
and captured. Final recording verification covers the exact five-document
change scope,518 untouched baseline files, unchanged code/scripts/tests,
historical log/note prefixes, accepted evidence, HEAD/index/submodule revisions
and all37 canonical execution-order steps.

Section35 and the original naming/validation/commit receipts remain unchanged
historical snapshots; their acceptance-pending fields are superseded by this
explicit record, not silently rewritten. No tests/builds are rerun, no fresh
runtime result claimed and no new commit or push made. Exact checks and hashes
are recorded in `recording-verification.json`.

## 37. P2.2 atomic artifact producer and bundle consumer

Status: **IMPLEMENTED AND VALIDATED; PENDING EXPLICIT USER ACCEPTANCE**.
Authorization: `2026-11-06T00:49:32.416Z`, following bounded P2.1 acceptance.
The user separately approved the prerequisite commit, consumer conversion,
documented obsolete-assertion deviation and intact nested-source relocation.
This record grants neither P2.2 acceptance nor Phase2 closure.

### Ownership, contract and publication

MigTD now owns the [v1 bundle schema](../../schemas/snp-ma-bundle-manifest-v1.json),
fixed-composition builders, static musl MA/controller packaging, deterministic
minimal initramfs, image rules, checksums, source/lock/AAS provenance,
Rust/native inventory, CycloneDX SBOM and standalone validation. Both builders
require explicit kernel/QEMU/OVMF identities and expected hashes. Neither needs
a VM-harness checkout or accepts arbitrary feature/composition overrides.
Private staging is validated before atomic Linux no-clobber publication;
failed construction cannot publish partial output or replace an existing root.
The [bundle guide](../snp-bundles.md) records usage, ownership and limits.

The external harness consumes the validated manifest and retains only VM
topology/lifecycle, platform launch configuration, host orchestration and
results/log collection. It does not compile MigTD or select verifier/provider
composition. The frozen MigTD-owned consumer contract rejects corrupt,
unsupported and contradictory bundles before launch and retains failure
records. The formerly active15 files have an explicit ownership disposition.
Nested MigTD source was moved intact to the approved session archive; all413
tracked hashes and the original Git objects remain preserved. No source/cache
contents were deleted. No active nested MigTD gitlink/declaration remains.

### Commits and genuine fresh-source proof

- Separately authorized accepted prerequisites:
  `5d6a4ad302d2c5b17a8a80d11286657559ad126d`. All523 pre-P2.2 baseline regular
  file hashes were verified in its staged tree; P2.2 changes were excluded.
- MigTD tooling:
  `8cd88edcf4eafa7ed8eb9ede7fec7777d61c51ce`.
- Frozen-input correction and exact fresh tested source:
  `bb1a2fccb2e42062378d4ef454718b6a1b5eadd5`.
- External consumer:
  `700e22aae1bcf09aff7d591cffc5ea6a39b4169c`, followed by
  `efb0d48614d5a386a263058a9a8b1e3788a01ac3`.

A genuine fresh MigTD clone initialized declared submodules from their
configured remote URLs and passed nondestructive SNP preparation. Its first
emulator attempt exposed an undeclared generated input: the old image oracle
read an ignored P0.10 corpus. That attempt failed without publication. The
existing74107-byte **PUBLIC TEST ONLY** corpus passed its committed independent
oracle:137 exact entries and cryptographic negatives. It is now tracked
unchanged, with a specific ignore exception, rather than silently borrowed or
regenerated from the original workspace. All five existing forbidden asset
fingerprints and their frozen policy digest are unchanged.

At the correction commit, both fresh-checkout compositions build and validate
using only declared tooling, ordinary Cargo caches and explicit external
artifact inputs. Final roots are `validated-emulator/` and
`validated-production/` under the evidence directory. Each has a separate
manifest, checksums, build/dependency/SBOM records and classification.
The production-shaped MA actually exits2 with
`HostControl(ProviderUnavailable)` and no emulator fallback.

### Tests, actual VM parity and approved deviation

- Fresh checkout:24 targeted unit tests pass (9 schema/archive/publication,
  7 inherited inventory,8 runner compatibility).
- Fresh real bundles:19 integration methods pass, including every artifact
  corruption, all five resealed fixture/root injections, malformed JSON,
  contradictory provider/schema/SBOM/provenance records, non-ELF controller,
  composition-override attempts and consumer rejection/failure reporting.
- ShellCheck passes for changed shell surfaces; `cargo fmt -- --check` passes.
  No new Rust runtime logic changed. Full Rust/TDX CI is not rerun or relabeled;
  the preceding accepted T4.19 evidence remains inherited.

The preserved old harness and new consumer used the **same initial bundle**.
Both booted both guests, returned both successful compatibility StartMigration
ACKs and reached both PID1 resident-completion markers. The old harness then
exited1 solely at its obsolete `MSG_VERIFY_REPORT` prerequisite; the new
manifest-driven consumer exited0. The stale `MSG_KEY_REQ` expectation is also
retired. The user explicitly approved this disclosed assertion deviation:
final exit statuses are not claimed identical, and no common V6/V2 protocol
was substituted or falsely treated as implemented.

Additionally, the final **fresh-source emulator bundle** completed the actual
two-VM compatibility workflow with the new consumer. Both controller ACKs and
both guest completions were observed; all four owned processes exited0 at
cleanup. No topology listeners or task-owned processes remain. This is a real
VM run, not `--validate-only` or a mock successful migration.

### Evidence, preservation and exclusions

Evidence: `target/p2.2-artifact-production/20261106T004932Z/`.
`commands.json` retains exact commands, environment overrides, times, exits and
log hashes, including failed attempts. `parity.json` compares the initial
old/new runs and approved deviation. `validation.json` identifies both final
bundle manifests and the fresh VM result. `recording-verification.json` covers
the untouched baseline, all1604 historical evidence files,413 relocated nested
tracked files, exact37-step sequence and historical note/log prefixes.
Initial draft bundles remain historical snapshots with their own embedded
contract; final claims use the fresh validated bundles, not those drafts.
Existing generated submodule changes/native outputs are preserved, not reset
or included in the commits. A documentation-only completion commit follows
the exact tested source without changing tooling, schema, runtime sources or
declared external inputs. Bundle provenance retains the exact tested commit.

Classification remains **Build-validated/migration-unqualified**. The common
V6 verifiers, live TH1/V2 path, local handoff and unavailable production
effects remain excluded. System randomness is selected, not qualified.
The native inventory is explicitly not a hermetic compiler/CRT/system closure;
external kernel/QEMU/OVMF hashes identify rather than requalify those inputs.
Integrity hashes are not authenticity. No Task14, firmware/persistence,
production/RNG/deployment/hardware/page-migration/resume qualification or PA
advancement is claimed. Task12/purpose3 stays deferred; Task5 has not started.
No push is made. P2.2 awaits explicit bounded acceptance.

## 38. P2.2 bounded acceptance and Phase2 closure

Status: **DONE - ACCEPTED AND FROZEN within the documented scope and exclusions**.
Explicit acceptance was received at `2026-11-06T15:39:00.609Z`; conditions: None.
The user requested:

> I accept P2.2 as implemented and validated within its documented scope and exclusions.
> Commit the remaining harness relocation changes in both repositories and record
> P2.2 acceptance and Phase 2 closure. Do not push or start Task 5.

Core implementation and fresh-source evidence remain recorded in section37:
prerequisite commit `5d6a4ad302d2c5b17a8a80d11286657559ad126d`, tooling commit
`8cd88edcf4eafa7ed8eb9ede7fec7777d61c51ce`, frozen-input/tested-source correction
`bb1a2fccb2e42062378d4ef454718b6a1b5eadd5` and completion documentation
`6fe345b3683d72a65068ff19671eed52f35ce6d3`.
The remaining harness relocation is now persisted in:

- Harness: `4a10dafd9125457616d09589f618cef1d3ff9e68`.
- MigTD: `af17a246a2ec6117e0872b63e7d750e7dbe71165`.

The independent private repository is `mvasantarao/snp-ma-vm-harness`.
Its confirmed platform repositories and preserved/rebuilt binaries remain
ignored local dependencies, not vendored source. Final relocation validation
passed24 existing SNP controls,21 real-bundle methods and3 harness tests.
Actual two-VM workflows passed with explicit relocated tools/ROMs, including
relative runtime paths; all four processes exited0 and topology listeners were
absent after cleanup. QEMU, OVMF and both kernel images rebuilt in separate
outputs without replacing validated inputs. The local relocation receipt is
`/home/murthy/repos/snp-ma-vm-harness/.local/relocation/receipt.json`.
Acceptance recording itself does not relabel those prior checks as new runs.

P2.1 was already accepted and committed as
`1dbb3e6bf8e9f3666d9a5ead2dbb6e66b6d15481`. With P2.2's explicit bounded
acceptance, committed implementation/relocation and this persistent record,
**Phase2 is closed within its documented scope**.
Earlier authorized IGVM requirements and the working-tree execution-order
cleanup remain deliberately uncommitted, as separately requested; they are
not implementation or qualification evidence.

Classification remains **Build-validated/migration-unqualified**. Acceptance
does not activate common V6/V2, qualify IGVM/ADO, production effects, randomness,
hardware migration or resume, advance PA rows, or reactivate Task12.
Historical evidence and section37 retain their original snapshot status.
Task5 is next pending, **NOT STARTED**, requiring separate authorization.
No push is authorized or performed.
