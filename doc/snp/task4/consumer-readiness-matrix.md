# T4.20 frozen consumer-readiness matrix

Part of [the Task4 freeze](task4-freeze.md). Rows assign implementation and
qualification obligations, not authorization to start them. The canonical
37-step order and separate acceptance gates still govern. No row below marks
a downstream task implemented.

## Reading the contracts

- **C**: implemented/frozen typed contract and bounded conformance evidence.
- **U**: selected final service is unavailable; an explicit error is required.
- **L**: preserved isolated legacy compatibility, not the final SNP path.
- **D**: deferred future work, not a current readiness gate.
- **Q**: external authority, deployment implementation or qualification open.

Producer names refer to the [source index](task4-freeze.md#audit-disposition)
and [machine inventory](freeze-inventory.json). `AuthenticatedSnpClaims`,
`TenantEvidence`, policy collateral, replay authorization, protected-I/O
receipts and firmware completion are distinct authorities. Constructing a
nonsecret context or decoding persistence never manufactures another receipt.

The accepted [V2 amendment](t4.14-pre-direct-random.md) governs every active
inter-node row: purposes6/7, authorization325 and session703, no contribution,
HKDF or application HMAC. Old V1 records are historical, not fallback.

## Interface producer/consumer map

| Frozen producer seam | Immediate or later consumer | Contract invariant and present boundary |
|---|---|---|
| `SnpProviderSet::services` / `SnpServiceRefs` | Explicit WFR/SPDM process root; downstream operation owners | Borrow selected services; no verifier/RNG replacement. C; final common services U |
| `MaEvidenceProvider` / `SnpCollateralProvider` | MA report generation and complete package construction | Separate acquisition/collateral, all64 expected bytes, calling-MA scope. C; captured bridge L; Linux adapter Q |
| `SnpReportVerifier::verify` | `HostPushedTenantEvidenceSource` and common claims consumers | Authenticated kind/VMPL/binding/provenance only; unavailable yields no claims. C/U; AAS1A-M |
| `HostPushedTenantEvidenceSource::evidence` / `TenantEvidence` | `SnpHostOperationV1`, tenant delivery/authorization | Exact retained package and private receipt; no guest-binding promotion to host-zero active authorization. C/U |
| `HostControlTransport` / `HostControlContextAuthorityV1` | Host operation and restart reconciliation | Bounded untrusted intent/evidence/control, durable pre-proof reservation, no secrets. C/U |
| `DurableTenantReplayStoreV1` / `CurrentTenantFirmwareStateV1` | Tenant journal, authorization and terminal/restart logic | Authenticated rollback-anchored atomic CAS/current authority; never empty fallback. C/U/Q |
| `VerifiedLmPolicyV1` / `VerifiedMaPolicyCollateral` | Peer promotion, fixed/ordered pair admission and history appraisal | Policy signatures/time/signer/store separate from report authentication; no fixed-to-ordered inference. C; deployment Q |
| `TenantAuthorizationContextV2` / `VerifiedSessionMaV2` | Both-role purpose7, replay journal, authorization result | Complete tenant digest, source REPORT_ID_MA, actualTH1, exact325 and matching identities. C; raw compatibility bridge is not final common V6 authentication |
| `MigrationDataV1` | Session context, installation, handoff/recovery and later relying party | Exact64, full Venice fields, immutable INIT_MA_REPORT_ID; no zero-history success fallback. C |
| `PeerTransportFactory` / `PeerSession` / `PeerClockV1` | Inter-node and local peer promotion / protected APIs | Distinct kinds, actual session binding, policy rechecks, deadlines/close/abort. C/U |
| `MigrationSessionContextV2` / `MigrationKeyV2` | Protected delivery, acceptance and installer | Independently admitted session703; source final random32 once per operation, zeroization, no retry regeneration. C; runtime authority U |
| `InstallExchangeSequenceV2` | Both-role install/completion scheduling | Protected acceptance is not key-possession/persistence; destination completion precedes source install; correlated outcomes/ack. C/U |
| `SnpMigrationKeyInstaller` / `MigrationInstallRequestV1` | Stateful emulator and production firmware adapter | Borrow key32/history64, role0 tenant REPORT_ID versus role1 zeros, same session/authorization; explicit partial/unknown effects. C/U |
| `MaBindingManagerV1` / binding requests | Planned/recovery command owner and cleanup | Exact scoped ready contract, tenant membership and secret-slot set/clear; no host secret. C/U |
| `LocalHandoffAuthorityV1` | Planned/recovery prepare, result and shutdown logic | Roles, epoch, attempt, tenant set, current binding/history and operation authority; no inferred coordinator principal. C/U |
| `ProtectedHandoffSecretProviderV1` / `HandoffSecretV1` | Planned outgoing/incoming MAs only | Independent outgoing random32 on promoted local channel; clear slots and reconcile before shutdown. C/U |
| `PlatformKeyProvider` | No active migration consumer | Disabled compatibility always unavailable; no MSG_KEY_REQ prerequisite. C; any new use requires approval |

## Canonical downstream consumers

| ID / consumer | Frozen producer inputs | Required implementation / acceptance before its claimed outcome | Current disposition / owner |
|---|---|---|---|
| C-AAS1A / base verification | `SnpReportVerifier`, request-kind/trust/collateral/error types | Integrate qualified AAS base authentication without TAV/TDX fallback; base success alone is not composite LM or policy approval | C/U/Q; AAS1A, H5.2/H5.6 |
| C-AAS1AM / common V6 adapter | Common verifier, `AuthenticatedSnpClaims`, tenant source, exact supplement contract | Authenticate base+supplement+signature+collateral/provenance; close all three inherited T4.17-T4.19 executable-verifier rows; fixture/production negatives and purpose6/7 receipt handoff before Task7 | C/U; Task6 plus AAS1A-M; PA-009 physical blocker remains |
| C-T05 / Task5 | SNP types, explicit composition root and L-only bridge | Remove active inherited TDX calls/fields/payload assumptions without changing TDX/AzCVMEmu; do not replace them with dormant V1 KDF/confirmation | C/L; Task5 |
| C-T06 / Task6 | Evidence header, exact220 supplement, P384 signature, fixed policy/collateral codecs | Produce complete signed V6 MA/tenant fixtures and negative corpus, fixture PKI/allowlists and matched ETCB; no captured-report mutation or invented overlapping layout | C; Task6, then AAS1A-M |
| C-T07 / Task7 | Tenant source, common verifier, host operation, peer and verified policy/collateral | Verify same complete host tenant independently first; actualTH1 and fresh purpose6 both roles; fixed-policy pair admission; no secret generation at this stage | C/U; Task7 after common adapter |
| C-T08 / Task8 | Tenant delivery, `TenantAuthorizationContextV2`, replay/current state | Verify exact source REPORT_ID_MA/identities and purpose7 both roles; exact325 digest; reserve/authorize durable anchored state; no fabricated receipts | C/U; Task8 |
| C-T09 / Task9 | Verified fixed pair, Venice history, ordered contracts kept distinct | Compute/reconstruct identical history64 and admit absolute/lifetime floors, mitigation containment and immutable initial MA ID; fixed milestone does not activate ordered production | C; Task9; production history H5.2/H5.6 |
| C-T10 / Task10 | Session703, `MigrationKeyV2`, promoted protected APIs, V2 exchange | Source random32 only after admission; opcodes30/31, destination32/33 then source34/35; same key/history and no blind retry or persistence claim | C/U; Task10 |
| C-T11 / Task11 | `SnpMigrationKeyInstaller`, borrowed request, correlated effect/error | Implement stateful emulator; exact key32/history64 and role operands; partial/unknown/retry/cancel/cleanup; no success-shaped unavailable or key-only mock substitute | C/U; Task11; production H5.3 |
| C-T12 / Task12 | Dormant purpose3 and persisted-state contracts only | Separate approval and authenticated actual persisted-state source are needed to reactivate; preserve dormant formats without making this a present dependency | D; NOT a current Task13/14 or milestone prerequisite |
| C-T13 / Task13 | Bounded host/VDM codecs, peer types, deadline/error/outcome contracts | Replace both requester/responder together; full framing, exact lengths/roles/order, duplicate/reorder/mismatch/timeout/session-loss handling and no secret in host/logs | C/U; Task13; Task12 not required |
| C-T14 / Task14 | Host operation, replay, V2 receipts/effects and close/abort | Integrate complete runtime flow, both-role regressions, cleanup/reconciliation and bounded readiness claim; distinguish key/history readiness from actual VM migration/resume | C/U; Task14; Task12 not required |
| C-R41 / R4.1 | Binding/rebind and history contracts | Independent authoritative state owner models lifecycle, slots, attempts, atomic per-tenant binding and exact history64 | C/U; R4.1 |
| C-R42 / R4.2 | Local peer kind, metadata, handoff authority and secret APIs | Implement actual two-Rust-MA workflow and independent firmware-state owner; logical contracts are not current TCP/Underhill wire qualification | C/U; R4.2 |
| C-R43 / R4.3 | Purpose4, fixed pair, local secret/binding/result contracts | Same-release planned handoff, scoped tenant set/epoch/attempt, protected random32, both slots, authoritative result, confirmation/finalize/clear and no-old-bindings shutdown | C/U; R4.3 |
| C-R44 / R4.4 | Planned contracts and explicit no/partial/unknown effects | Qualify mismatched identity/secrets/set, crashes, partial tenants, retries, terminal duplicates, cleanup and preserved full history; prove split ownership | C/U; R4.4 |
| C-R45 / R4.5 | Incoming-only purpose5 and recovery/binding/history contracts | Authoritative launch/identity/binding checks; no old/new SPDM or handoff secret; confirm/finalize/reconcile and preserve exact history64 | C/U; R4.5 |
| C-R46 / R4.6 | Distinct local/inter-node sessions and transferable metadata | Abort old inter-node session, retain only authenticated transferable state, reattest new MA and restart unless qualified exact resume authority exists | C/U; R4.6 |
| C-R47 / R4.7 | R4.1-R4.6 complete evidence | Two-process same-release planned/recovery emulator qualification only; no cross-release, real firmware/GCTX/RMP, production BASE or atomicity claim | C/U; R4.7 |
| C-P21 / P2.1 | Frozen names/contracts, four corrected diagrams and this matrix | Separately authorized terminology audit, preserving runtime behavior and exact protocol/profile meaning | NOT STARTED; requires T4.20 acceptance and authorization |
| C-P22 / P2.2 | Source hash snapshot and provisional separate ELF/dependency inventories | Versioned manifest/schema, atomic binary/kernel/initramfs/config/collateral bundle, reproducible provenance and positive/negative contents/shutdown gates | NOT STARTED; no P2.2 schema is invented here |
| C-H50 / H5.0 | Common claims/layout errors, P0.9 ordered/fixed and PA-009 | Obtain authoritative V6 physical layout, kernel/firmware and deployment contracts before parser/provider activation; no partial guessed fields | C/U/Q; H5.0, AMD/Microsoft authority |
| C-H51 / H5.1 | Host framing/context authority, separate tenant push versus MA acquisition | Qualified BASE/kernel/GHCB routing, handles, correlation/restart and report/cert acquisition; calling-MA ioctl is not tenant acquisition | C/U/Q; H5.1 and PA-007 |
| C-H52 / H5.2 | Common verifier, fixed/ordered collateral, signer/time/store/history services | Real PKI/roots, VCEK/VLEK selection, KDS/THIM/offline/expiry/revocation/time/state and deployment approval; no missing mapping => zero/fixed fallback | C/U/Q; H5.2 and PA ledger |
| C-H53 / H5.3 | Typed installer, firmware correlation, effect/errors and V2 outcomes | Real supplied-MSK/history command path, exact operands, transport/firmware status, persistence/effects-once/reconciliation and secret cleanup | C/U/Q; H5.3 |
| C-H54 / H5.4 | Anchored replay journal, current-state and pre-proof host authority | Real authenticated durable atomic CAS, rollback/freshness/time policy, terminal retry/restart/rollback and no empty or live-session replacement fallback | C/U/Q; H5.4 and PA-008 |
| C-H55 / H5.5 | Local authority/protected secret, binding manager and current-state inventory | Qualified production transport/commands, slot serialization/clear, planned/recovery result/retry, partial ownership, active inter-node handling and authoritative shutdown | C/U/Q; H5.5 |
| C-H56 / H5.6 | Complete evidence/provenance, initial authorization/history, common claims | Qualified original-evidence retrieval and composite relying-party representation/verification; base AAS or signed history alone is insufficient | C/U/Q; H5.6, P0.12B |
| C-H57 / H5.7 | All production providers and reproducible deployment evidence | Actual AMD hardware/RNG/firmware, both-role migration and handoff/recovery, shutdown/cleanup and full end-to-end migration/resume qualification | Q; H5.7, no current claim |

Tracking owner and external technical authorities remain the dispositions in
the [PA ledger](../../snp-production-readiness.md). A row naming a downstream
task assigns work to that milestone, not an invented person, private work item
or approval. Accepted Task4 conformance/release ELF evidence does not close any
of these production requirements.
