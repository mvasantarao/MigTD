# Execute the SNP MigTD Migration Agent

## Current execution guide

Use the accepted Task 5 SNP-separated implementation, with an emulator bundle
built as `SnpEmuAzure`. Follow [bundle preparation and construction](snp-bundles.md)
first, or consume an approved, already validated bundle. Run the commands below
from the MigTD repository root.

The renamed items are **scenario runners, not different MA binaries**. Both
standalone scenarios use the same frozen `bin/migtd` executable. The WFR scenario
also uses the bundle's matching `bin/host_wfr_test` controller.

| Execution mechanism | Current entry point | Processes and trigger |
|---|---|---|
| `SingleProcessMigration` | `run_snp_single_process_migration.sh` | Two standalone MA processes, source and destination; local autostart, no host controller |
| `InterNodeTwoProcessMigration` | `run_snp_inter_node_two_process_migration.sh` | Two standalone MA processes plus two host-controller processes; external WFR requests |
| Two-VM execution | External harness `run-emulator-e2e.sh --bundle DIR` | One MA as PID1 in each VM plus two host controllers; external WFR requests |
| `LocalMaHandoffTwoProcess` | Not implemented | Reserved for the Phase 4 old/new-MA handoff; not inter-node migration |

### Standalone autostart and WFR/controller execution

```bash
BUNDLE="$PWD/target/bundles/emulator"
RUN_ROOT="$PWD/target/snp-execution/$(date -u +%Y%m%dT%H%M%SZ)"

tools/snp/validate-bundle.sh --bundle "$BUNDLE"
"$BUNDLE/bin/migtd" --help

bash sh_script/test/run_snp_single_process_migration.sh \
  "$BUNDLE/bin/migtd" \
  "$RUN_ROOT/single-process-migration"

bash sh_script/test/run_snp_inter_node_two_process_migration.sh \
  "$BUNDLE/bin/migtd" \
  "$BUNDLE/bin/host_wfr_test" \
  "$RUN_ROOT/inter-node-two-process-migration"
```

Run sequentially against the same frozen executables. These runners do not
build MigTD or change its feature selection. Neither `MIGTD_POLICY_FILE` nor
`MIGTD_ROOT_CA_FILE` is required or loaded. Do not mix SNP features with the
TDX-owned `main`, `spdm_attestation`, `policy_v2`, `vmcall-raw`,
`test_disable_ra_and_accept_all` or `test_mock_report` features.

Each evidence directory contains `manifest.txt`, `source.log` and
`destination.log`; the WFR scenario additionally retains
`source-controller.log` and `destination-controller.log`. A successful
standalone run requires both MA exits to be zero; WFR also requires both
controller exits to be zero. The runners check workflow/verification markers
and executable hashes, not just exit status. See
[scenario names, addresses and timeouts](snp-migration-scenarios.md).

### Two-VM PID1/WFR execution

Use the independent VM harness with the same validated emulator bundle.
Install its declared Python dependencies and provide its required KVM/SNP
platform and noninteractive `sudo` access as described in the
[bundle consumer instructions](snp-bundles.md#consumers-and-qualification-limits).
Set `HARNESS` to the actual independent checkout. The paths below match its
documented local platform layout; relocated QEMU/OVMF bytes must match the
bundle's approved hashes.

```bash
HARNESS=/home/murthy/repos/snp-ma-vm-harness
"$HARNESS/run-emulator-e2e.sh" --bundle "$BUNDLE" \
  --qemu "$HARNESS/.local/platform/qemu-9.2/build/qemu-system-x86_64" \
  --ovmf "$HARNESS/.local/platform/edk2-amdsev/Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd" \
  --qemu-data "$HARNESS/.local/platform/qemu-9.2/pc-bios" \
  --log-root "$RUN_ROOT/two-vm"
```

This harness boots the bundle's kernel/initramfs, orchestrates both WFR
controllers and retains `result.json` plus logs in a fresh run directory.
Successful PID1 MAs remain resident; the harness checks completion markers and
controller ACKs before cleaning up its processes. Do not expect the guest MA
to exit zero as in a standalone run. This is direct kernel/initramfs execution,
not an IGVM boot or Task 14 qualification.

### What current success establishes

All three runnable mechanisms exercise **captured-fixture legacy compatibility**:
captured-v5 SNP report/certificate verification and a key-only mock installer.
They do not establish fresh V6/TH1 evidence, admitted V2 authorization/keys,
real installation, local handoff or production migration qualification.
Bundles remain **Build-validated/migration-unqualified**. `SnpHardware` is not
an alternative working emulator: its current production startup fails explicitly
with exit status 2 because required providers remain unavailable.

## Feature selection and historical development reference

**Command-contract update (2026-11-02; original correction 2026-10-24):** the
[Q162 current Firmware ABI 1.59 / ARG v1.20 addendum (removed)](master-execution-plan.md#removed-task4-documentation)
supersedes removed-command assumptions in older Venice/Technical Notes flows.
`MSG_VERIFY_REPORT` is not a current hardware operation. The phase records
below retain their historical context; current verification is software
validation, and installation retains `MSG_SET_MIGRATION_INFO`.

**Current feature selection (T4.16, 2026-11-05):** shared PAL SNP code uses
`snp-core`, independently of fixtures. `SnpEmuAzure` selects explicit fixture,
state-emulator, TCP and mock capabilities; `SnpHardware` rejects them at
compile time and contains no TDX shim/transport providers. Both select existing
`SystemRandomSource` and the local AAS verification capability, without a remote
service dependency for peer authorization. TAV and its crypto patch are no
longer workspace dependencies or registered test targets; historical patch
files and the phase records below are retained only as prior evidence.
Historical certificate-vector tests now use the repository X.509 parser and
ring; their frozen corpus is unchanged.

`SnpUnderhillRuntime` (also named by compatibility alias `SnpUnderhill`) supplies
Linux/PID1 support without implying `SnpEmu`. Existing emulator runs should
select `SnpEmuAzure`, or explicitly combine `SnpEmu,SnpUnderhillRuntime`.
Explicit `std` does not select an emulator. TDX firmware remains `no_std`;
AzCVMEmu retains its existing provider path.

```bash
AS=nasm AR=llvm-ar CC=clang \
  cargo build --locked -p migtd --no-default-features --features SnpHardware
AS=nasm AR=llvm-ar CC=clang \
  python3 sh_script/test/snp_feature_conformance.py
```

The production binary deliberately exits with status 2 and a startup diagnostic:
production services and the common AAS Version 6 claims/layout adapter remain
unavailable. The working AAS captured-fixture verifier is not that adapter and
cannot authenticate live Version 6 requests. This is feature isolation, not
production activation or hardware/RNG qualification. No automatic emulator
fallback is permitted.

**Historical TAV dependency (2026-11-04; superseded by T4.16):** PAL and the emulator's test dependency
use `tav-1.0.7` with `default-features = false` and `crypto_pure_rust`.
TAV 1.0.8 removed that backend, so it is not a compatible replacement.
The [local crypto patch](../../deps/tav-crypto/README.md) retains that legacy
feature name but replaces RSA public signature verification with the existing
patched ring, including native code/assembly. It is not strictly pure Rust.
X.509/path policy and RustCrypto ECDSA remain unchanged; the affected `rsa`
crate is removed rather than waived. The user explicitly approved this
maintained patch. Its tests are included in `cargo xtask lib-test`.
The [workspace lockfile](../../Cargo.lock) selects `crypto-bigint 0.7.10`,
`elliptic-curve 0.14.3`, `ecdsa 0.17.0`, and `p256`/`p384`/`p521 0.14.0`.
The shared helpers are `subtle 2.6.1` and `hybrid-array 0.4.15`.
Use `--locked` for reproducible builds: `pkcs1 0.8.0-rc.4` matches TAV
1.0.7's own release lockfile; stable `pkcs1 0.8.0` has an incompatible
`RsaPssParams` API. Do not blanket-update that dependency without validating
the upstream parser. The earlier RustCrypto-only upgrade did not fix RSA;
the separately approved local patch removes that dependency entirely.
The seven other advisory paths now use `rustls 0.23.46`,
`rustls-webpki 0.103.16`, `tokio 1.53.3` and `webpki-roots 1.0.10`.
The advisory check passes without exceptions. Earlier phase/version records
below remain historical; production qualification is not implied.

The following phase descriptions are historical. For the original development
and testing of MigTD live migration logic on AMD SEV-SNP platforms, MigTD could be
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

**Historical Phase 1 TAV version:** `tee-attestation-verification-lib` v1.0.2 (tag `tav-1.0.2`),
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

## Historical build and test commands (do not use for current execution)

These commands predate the bundle interface and SNP/TDX separation. They are
retained as development history, not current execution instructions. Use the
bundle-based guide above instead.

```bash
# Unit tests (no hardware required)
cargo test --locked -p pal --features snp-emu

# snp_emu crate tests
cargo test --locked -p snp_emu

# Full SnpEmu binary
cargo build --locked -p migtd --features SnpEmu

# End-to-end handshake (source + destination)
./snpemu.sh
```

---

## Historical phase roadmap

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | TAV integration, scaffold PAL traits, E2E SnpEmu handshake | Complete |
| Phase 2 | WithPinnedArk (ARK off wire), validate() TCB floor, SnpMigPolicy, SnpIdentityInfo, TDX PAL | In progress |
| Phase 3 | Software report verification and tenant-to-MA binding, source_tcb, migration_data policy fields; governed by the ARG v1.20 addendum | Planned |
| Phase 4 | Production policy enforcement, VCEK OID parsing, real platform TCB in QvlResult | Planned |

---

*References: AMD SEV-SNP Firmware ABI Rev 1.58; AMD ARG ABI (2026); Venice Live Migration Rev 0.52;
TEE Attestation Verification Library tav-1.0.2 (`microsoft/TEE-Attestation-Verification`)*
