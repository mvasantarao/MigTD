# Copilot Instructions for MigTD

MigTD is a bare-metal Rust firmware (no_std) implementing Intel TDX Migration TD — a security enclave that performs mutual SPDM attestation between two platforms before allowing a confidential VM to migrate. It also has emulator modes (`AzCVMEmu`, `SnpEmu`) that run as standard userspace Rust binaries for development and testing.

## Build and Test Commands

### Prerequisites (must run once per clone or after `deps/` changes)
```bash
bash sh_script/preparation.sh   # patches ring, pre-builds spdm-rs; REQUIRED before any cargo build
```

Required environment variables for all builds:
```bash
export AS=nasm
export AR=llvm-ar
export CC=clang
```

### Primary Build Commands

```bash
# Bare-metal TDX firmware (default, production)
cargo image

# Bare-metal with SPDM attestation enabled
cargo image --features spdm_attestation

# AzCVMEmu — Azure TDX CVM userspace (requires Azure TDX CVM + TPM2-TSS at runtime)
cargo build --no-default-features --features AzCVMEmu

# AzCVMEmu with mock TD reports (full attestation flow, any Linux machine)
cargo build --no-default-features --features AzCVMEmu,test_mock_report

# AzCVMEmu with IGVM attestation (uses servtd_get_quote)
cargo build --no-default-features --features AzCVMEmu,igvm-attest

# AzCVMEmu — skip remote attestation (development/testing, any Linux machine)
cargo build --no-default-features --features AzCVMEmu,test_disable_ra_and_accept_all

# SNP emulator (captured-fixture compatibility; migration-unqualified)
cargo check -p migtd --no-default-features --features SnpEmuAzure
cargo build -p migtd --no-default-features --features SnpEmuAzure
```

> **Note:** `AzCVMEmu` implicitly enables `main` and `vmcall-raw`; you do not need to add them explicitly.

### Lint and Format

```bash
# ALWAYS run preparation.sh before these if ring/spdm-rs haven't been patched yet
cargo fmt -- --check
cargo clippy --features stack-guard,virtio-vsock,virtio-serial,vmcall-interrupt
```

### Unit Tests

```bash
# Run all library crate test suites (runs migtd, crypto, attestation, pci, virtio, vsock, policy)
cargo xtask lib-test

# Individual crate targets (mirrors what lib-test does internally)
cargo test -p migtd     --features test_disable_ra_and_accept_all
cargo test -p migtd     --features policy_v2
cargo test -p policy
cargo test -p policy    --features policy_v2
cargo test -p crypto
cargo test -p attestation --features test
cargo test -p virtio
cargo test -p vsock

# Unit test coverage report (output: unit_test_coverage/)
bash sh_script/unit_test_coverage.sh
```

### Integration Tests (emulation)

Recommended via `migtdemu.sh` — see the **Running AzCVMEmu** section below:

```bash
# Simplest e2e test (no TDX/TPM required):
./migtdemu.sh --skip-ra --both

# Full attestation with mock data (no TDX/TPM required):
./migtdemu.sh --mock-report --both

# Policy v2 with mock report:
./migtdemu.sh --policy-v2 \
  --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
  --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
  --mock-report --both

# SPDM attestation + skip RA:
./migtdemu.sh --skip-ra --features spdm_attestation --both

# Python integration test suite (requires running pair of MigTD instances):
cd sh_script/test && python -m pytest integration_test.py
```

### Utility Tools

```bash
cargo build -p migtd-hash                   # compute SERVTD_INFO_HASH from image
cargo build -p migtd-policy-generator       # generate policy JSON from template
cargo build -p migtd-policy-verifier        # verify policy signatures
cargo build -p json-signer                  # sign policy JSON files
cargo build -p servtd-collateral-generator  # generate collateral bundles
cargo hash --image /path/to/migtd.bin       # print SERVTD_INFO_HASH
```

---

## Architecture

### Crate Structure

```
src/
  migtd/            # Main binary — entry points + migration orchestration
    src/bin/migtd/
      main.rs       # Bare-metal entry point (#[no_std] #[no_main])
      cvmemu.rs     # AzCVMEmu entry (std userspace, Azure TDX CVM)
      snpemu.rs     # SnpEmu entry (std userspace, AMD SNP)
    src/spdm/       # SPDM protocol — VDM message exchange (req/rsp/vdm)
    src/migration/  # Session orchestration, MSK delivery, rebinding, ServtdExt
    src/ratls/      # RA-TLS certificate generation
    src/event_log/  # Event log collection (RTMR)
    src/mig_policy/ # Policy parsing and enforcement
  attestation/      # Quote generation and verification (wraps Intel DCAP / mock)
  policy/           # Migration policy schema, signing, and verification
  crypto/           # Primitives: ring, rustls, custom x509.rs, ECDSA P-384
  pal/              # Platform Abstraction Layer — SNP report/cert types (in progress)
  devices/
    vmcall_raw/     # Primary transport for emulator modes (TCP sockets)
    vsock/          # Virtio-vsock transport (production)
    virtio_serial/  # Virtio-serial transport (experimental)
deps/
  td-shim/          # Bare-metal TDX shim; patched ring lives here
  td-shim-AzCVMEmu/ # Emulator shim — tdx-tdcall-emu, az-tdx-vtpm
  spdm-rs/          # SPDM protocol library (pre-built by preparation.sh)
```

### Migration Session Flow

The core inter-MigTD communication lifecycle (source ↔ destination) is orchestrated in `src/migtd/src/migration/session.rs`:

1. **Query VMM** — `query()` checks VMM migration support
2. **Wait for request** — `wait_for_request()` blocks until VMM signals
3. **Setup transport** — `setup_transport()` connects vsock / vmcall-raw / virtio-serial
4. **Pre-session exchange** — policy file and issuer chain exchanged before TLS
5. **Secure channel** — TLS 1.3 (RA-TLS) or SPDM established
6. **Key exchange** — `exchange_msk()` → `migration_src_exchange_msk()` or `migration_dst_exchange_msk()`
7. **MSK delivery** — `write_msk()` stores Migration Session Key via TDX tdcall
8. **Shutdown** — `shutdown_transport()`, `report_status()` back to VMM

Transport abstraction (`transport.rs`):

| Feature flag      | Transport class            |
|-------------------|----------------------------|
| `vmcall-raw`      | `vmcall_raw::VmcallRaw`    |
| `virtio-serial`   | `virtio_serial::VirtioSerialPort` |
| (default)         | `vsock::VsockStream`       |

### VDM Wire Protocol (SPDM over VDM)

Source `spdm_req.rs` sends **5-element REQ**, receives **3-element RSP**.  
Destination `spdm_rsp.rs` parses REQ, sends RSP.

| Direction | Elements |
|-----------|----------|
| REQ (Src → Dst) | `QuoteMy` \| `EventLogMy` \| `MigPolicyMy` \| `SerVtdExt` \| `TdReportInit` |
| RSP (Dst → Src) | `QuoteMy` \| `EventLogMy` \| `MigPolicyMy` |

`spdm/mod.rs` is included for `spdm_attestation` or `SnpEmu`. Neutral handshake,
framing and signing are shared; TDX and SNP application functions are selected
separately. SNP compatibility lives in `runtime/snp/legacy.rs`.

### TDX Attestation Layers

| Layer | Name | Size | Location |
|-------|------|------|----------|
| 0 | `TdxReport` — CPU-MAC'd by TDX hardware | 1024 B | Local only; `TdInfo` (512 B) slice sent as `TdReportInit` VDM element |
| 1 | TDX Quote (`QuoteMy` on wire) | ~4–5 KB | `QuoteHeader(48) + TdQuoteBody(584) + ECDSA + PCK chain`; `report_data` binding at offset 520 in `verify_quote_integrity()` output |
| 2 | Intel PCS collateral | ~30–50 KB | External fetch: `TCBInfo`, `QEIdentity`, CRLs |

SNP attestation has only 2 layers: `AttestationReport` (1184 B) + VCEK→ASK→ARK cert chain; no QE, no PCK, no collateral fetch.

---

## Key Conventions

### Feature Flag Architecture

Three distinct build targets:

| Feature | Binary type | Notes |
|---------|-------------|-------|
| (default, bare-metal) | `no_std` firmware | Production TDX image |
| `AzCVMEmu` | `std` userspace | Azure TDX CVM; requires TPM2-TSS (unless `test_*`) |
| `SnpEmu` | `std` userspace | AMD SNP emulator — in active development |

**`no_std`/`no_main` guards in `main.rs`** — both `cfg_attr` lines gate on `not(any(feature = "AzCVMEmu", feature = "SnpEmu"))`. Any new emulator mode must be added to **both** guards and to the bare-metal `fn main()` guard, or the build will fail with duplicate `main` symbol errors.

**`spdm/mod.rs` file-level gate** is
`#![cfg(any(feature = "spdm_attestation", feature = "SnpEmu"))]`.
For TDX, `spdm_attestation` retains its existing `main` dependency.

**SNP feature isolation**: `SnpEmu` selects neutral SPDM directly, not TDX
`main`, `spdm_attestation`, `vmcall-raw` or emulator-shim dependencies.
`SnpEmuAzure` adds the existing Underhill runtime capability. Mixed SNP/TDX
platform compositions, including `test_disable_ra_and_accept_all`, are rejected.
Do not change TDX feature meanings to accommodate SNP.

### Cargo Patch Overrides

Two crates are redirected via `[patch.crates-io]` in the workspace root `Cargo.toml`:

| Crate | Redirected to |
|-------|--------------|
| `ring` | `deps/td-shim/library/ring` (no_std-compatible patch) |
| `sys_time` | `src/std-support/sys_time` |

**Do not replace the `ring` override with the upstream crates.io version** — the local patch is mandatory for bare-metal builds.

### SNP Attestation Verification

The SNP PAL uses Microsoft TEE Attestation Verification (TAV), pinned to tag `tav-1.0.2` with the `crypto_pure_rust` feature. The obsolete local `virtee/sev` gitlink and Cargo patch were removed; do not restore them.

### Commit Message Format

Per `CONTRIBUTING.md` — all three sections are required:

```
<type>(<crate/module>): <subject>

<body — explain what and why>

Signed-off-by: Name <email>
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

`<type>`: `fix`, `feat`, `docs`, `refactor`, `test`, `chore`  
`<crate/module>`: e.g., `migtd/spdm`, `vmcall_raw`, `pal/snp`  
Repository-wide changes: use `migtd` as the crate name.

---

## Running AzCVMEmu

Use `migtdemu.sh` (the recommended runner). It builds, sets env vars, manages TPM permissions, and can orchestrate both sides on localhost.

```bash
./migtdemu.sh --help                    # show all options

# Both sides on one machine (most common for dev)
./migtdemu.sh --skip-ra --both          # no attestation, any Linux
./migtdemu.sh --mock-report --both      # full attestation, mock data, any Linux
./migtdemu.sh --both                    # real attestation (Azure TDX CVM + TPM required)

# One side at a time
./migtdemu.sh --skip-ra --role destination
./migtdemu.sh --skip-ra --role source --dest-ip 127.0.0.1 --dest-port 8001

# Policy v2 + IGVM attestation
./migtdemu.sh --policy-v2 \
  --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
  --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
  --mock-report --igvm-attest --both

# Extra features (e.g., SPDM attestation)
./migtdemu.sh --skip-ra --features spdm_attestation --both

# Debug build
./migtdemu.sh --debug --skip-ra --both
```

Required env vars (set automatically by script, or manually):
```bash
export MIGTD_POLICY_FILE=/path/to/config/policy.json
export MIGTD_ROOT_CA_FILE=/path/to/config/Intel_SGX_Provisioning_Certification_RootCA.cer
```

TPM note: when `test_disable_ra_and_accept_all` or `test_mock_report` is used, TPM2-TSS is NOT required.

## Running SnpEmu

For development, build the MA and controller with Rust 1.90:
```bash
cargo +1.90.0 build -p migtd --no-default-features --features SnpEmuAzure
bash sh_script/test/run_snp_single_process_migration.sh target/debug/migtd
bash sh_script/test/run_snp_inter_node_two_process_migration.sh \
  target/debug/migtd target/debug/host_wfr_test
```

Run sequentially against the same frozen executables. For immutable VM inputs,
use the [bundle producer](../doc/snp-bundles.md); the harness does not build
MigTD. SNP requires neither `MIGTD_POLICY_FILE` nor `MIGTD_ROOT_CA_FILE`.
WFR and autostart use the same SNP host-request handler. Autostart is a testing
trigger, not authorization; successful PID1 completion remains resident.

---

## SNP legacy compatibility boundary

All SnpEmu-specific code is gated with `#[cfg(feature = "SnpEmu")]`.

SNP owns host request decoding, typed operation context, direct TCP transport,
legacy evidence/key exchange and zeroizing compatibility key buffers. It must
not import `migtd::migration` or call TDX ServTD, TDCS-version or key helpers.
The 48-byte controller frame ignores legacy TD identifier bytes and rejects
nonzero init-data/reserved fields.

The five/three-element legacy envelope carries captured-v5 evidence, an empty
event log, `SHA384([0; 64])` and inert zero placeholders. Captured signature/chain
verification stays enabled; it is not fresh V6/TH1 authentication. Two
directional legacy random32 keys and key-only mock effects are not admitted
`MigrationKeyV2` or production installation. Common V6/V2 activation and later
Tasks 6-11 remain deferred. Unavailable hardware providers fail explicitly,
without fixture fallback. See the [Task 5 record](../doc/snp/approval-decision-technical-note.md#39-task5-snp-tdx-separation-review-pending).

---

## Crypto Stack

All crypto is no_std-compatible. **No OpenSSL anywhere in the production path.**

| Library | Usage |
|---------|-------|
| `ring` (patched) | ECDSA P-384, SHA-384, key generation; patched for no_std |
| `rustls` + ring backend | TLS 1.3 session, SECP384R1 |
| `src/crypto/src/x509.rs` | Custom X.509 builder/parser; uses `der` crate, NOT `x509-cert` crate |
| `src/crypto/src/rustls_impl/ecdsa.rs` | ring-based ECDSA signing for RA-TLS certificates |
