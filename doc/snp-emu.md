## AMD SEV-SNP Emulation (SnpEmu)

For development and testing of MigTD live migration logic on AMD SEV-SNP platforms, MigTD can be
built with SNP emulation support (`snp-emu` feature). This mode runs the PAL attestation stack
using real AMD SEV-SNP hardware attestation (PSP-generated reports, VCEK/ASK certificate chain,
TAV-based verification) without the Intel TDX UEFI shim. It is the AMD SEV-SNP counterpart of
the Intel AzCVMEmu feature.

The SnpEmu feature is developed in phases on the `murthy/integration-policyv2-sync` branch of
the MigTD fork at `mvasantarao/MigTD`.

---

## Phase 1 — TAV Integration and SnpEmu Scaffolding

**Status:** Complete (branch: `murthy/integration-policyv2-sync`)

**Key milestones:**

| Area | Change | Commit |
|---|---|---|
| TAV integration | `src/pal/src/snp/qvl/verify.rs`: replaced ring-based SNP cert chain verification (`verify_snp_cert_chain_der`, `verify_snp_report_sig`, `rsa_pss_sha384_verify`) with `tee-attestation-verification-lib` (TAV) `sync::verify_attestation()` | e02b486 |
| Certificate re-export | `src/pal/src/snp/certs.rs`: re-exports `tee_attestation_verification_lib::Certificate` | 5e70536 |
| PAL trait update | `QvlLibrary::verify()` updated to accept `AttestationVerificationParams`; `get_report()` returns `AttestationBundle` instead of `Vec<u8>` | 7ba48b3 |
| Fixture blob | `src/snp_emu/src/report_emu.rs`: `build_fixture_blob()` assembles `report \|\| vcek_len \|\| vcek \|\| ask_len \|\| ask \|\| ark_len \|\| ark` (~5,867 bytes) for Phase 1 E2E testing | — |
| Validate stub | `src/pal/src/snp/qvl/validate.rs`: `validate()` returns `Ok(())` unconditionally; `AttestationVerificationParams` constructed via `phase1()` with all `Option` fields `None` | — |
| E2E test | `./snpemu.sh`: source and destination SnpEmu handshake passes with TAV chain verification | — |

**Wire blob format (Phase 1):**
```
report[1184B] || vcek_len[4LE] || vcek[1351B] || ask_len[4LE] || ask[1677B] || ark_len[4LE] || ark[1639B]
Total: ~5,867 bytes
```

**TAV version:** `tee-attestation-verification-lib` v1.0.2 (tag `tav-1.0.2`),
`ChainVerification::WithProvidedArk { ask, ark }` — all three certs on wire.

---

## Phase 2 — TCB Floor Check, WithPinnedArk, SnpMigPolicy

**Status:** In progress (branch: `snp-emu-phase2`, merges into `murthy/integration-policyv2-sync`)

**Key milestones:**

| Task | Area | Change |
|---|---|---|
| **P2-11** | `validate.rs`, `spdm/mod.rs` | Rename `phase1()` → `crypto_only()` constructor in `AttestationVerificationParams` |
| **P2-12** | `verify.rs`, `report_emu.rs`, `spdm/mod.rs` | Switch from `WithProvidedArk{ask, ark}` to `WithPinnedArk{ask}` — ARK removed from wire; TAV uses its pinned AMD Milan ARK internally |
| **P2-01** | `validate.rs` | Implement `validate()` with `tcb_ge()` helper — TCB floor check (`report.reported_tcb.as_milan_genoa() >= min_tcb`) and guest SVN floor (`report.guest_svn.get() >= min_guest_svn`) |
| **P2-07** | `types.rs`, `verify.rs` | Add `platform_tcb: Option<[u8; 8]>` to `QvlResult` — exposes attested platform TCB to callers |
| **P2-03** | `snp/policy.rs`, `spdm_req.rs`, `spdm_rsp.rs` | Define `SnpMigPolicy` struct (zerocopy 0.8, 64 bytes, zero-value); replace `SHA384(&[])` stub with `SHA384(SnpMigPolicy::new_zeroed().as_bytes())` |
| **P2-04** | `snp/identity.rs`, `snp/mod.rs` | Define `SnpIdentityInfo` (512 bytes, zero-value) as SNP equivalent of TDX `TDINFO_STRUCT` for wire compatibility |
| **P2-02** | `spdm_req.rs`, `spdm_rsp.rs` | Accept zero-length EventLog for SNP peers (AMD SNP has no RTMR/CCEL) |
| **P2-05** | `pal/src/tdx/` | Add `TdxAttestationProvider` stub behind `tdx` feature gate (parallel to SNP work) |

**Wire blob format (Phase 2, after P2-12):**
```
report[1184B] || vcek_len[4LE] || vcek[1351B] || ask_len[4LE] || ask[1677B]
Total: ~4,220 bytes
```
ARK is no longer transmitted. TAV validates the chain against its pinned AMD Milan ARK internally.

**TAV API notes (confirmed from tav-1.0.2 source):**
- `AttestationReport::reported_tcb` — public field, type `TcbVersionRaw`; call `.as_milan_genoa()` for comparison
- `AttestationReport::guest_svn` — public field, type `le::U32` (byteorder); call `.get()` for native `u32`
- `TcbVersionMilanGenoa` implements `PartialOrd` (field-by-field: `boot_loader`, `tee`, `snp`, `microcode`; reserved bytes excluded)
- TAV uses zerocopy **0.8** (`IntoBytes`, `FromBytes`, `KnownLayout`, `Immutable`)

---

## Build and Test (SnpEmu)

```bash
# Unit tests (no hardware required)
cargo test -p pal --features snp-emu

# snp_emu crate tests
cargo test -p snp_emu

# Full SnpEmu binary
cargo build -p migtd --features SnpEmu

# End-to-end handshake (source + destination)
./snpemu.sh
```

---

## Phase Roadmap

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | TAV integration, scaffold PAL traits, E2E SnpEmu handshake | Complete |
| Phase 2 | WithPinnedArk (ARK off wire), validate() TCB floor, SnpMigPolicy, SnpIdentityInfo, TDX PAL | In progress |
| Phase 3 | maReportID/MSG_VERIFY_REPORT trust boundary, source_tcb, migration_data policy fields | Planned |
| Phase 4 | Production policy enforcement, VCEK OID parsing, real platform TCB in QvlResult | Planned |

---

*References: AMD SEV-SNP Firmware ABI Rev 1.58; AMD ARG ABI (2026); Venice Live Migration Rev 0.52;
TEE Attestation Verification Library tav-1.0.2 (`microsoft/TEE-Attestation-Verification`)*
