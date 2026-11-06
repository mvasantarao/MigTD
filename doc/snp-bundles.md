# SNP MA bundles (P2.2)

MigTD builds, packages, inventories and validates its own artifacts. A VM
harness consumes a validated bundle; it neither builds MigTD nor selects
features, verifiers, fixtures or providers. No external harness checkout is
needed for either builder or validator.

## Prerequisites and declared inputs

Use Linux, Python 3.12, Rust 1.90 with `x86_64-unknown-linux-musl`, Git, binutils
(`readelf`, `nm`), NASM, LLVM ar, Clang, CMake/make and
`x86_64-linux-musl-gcc`. Cargo dependencies must be available for `--offline
--locked`; populate the ordinary Cargo cache from the committed lockfile first
if needed. Initialize the repository's declared submodules:

```bash
git submodule update --init --recursive
python3 -m venv target/snp-bundle-tools
target/snp-bundle-tools/bin/python -m pip install -r tools/snp/requirements.txt
export PATH="$PWD/target/snp-bundle-tools/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.90.0
bash sh_script/preparation.sh --snp-bundle
```

The SNP-specific preparation mode verifies the pinned, pre-patched ring
checkout without resetting/cleaning it or reapplying patches. It does not run
the legacy firmware preparation sequence. The builder repeats this check.
Do not replace the patched ring with crates.io ring.

Supply **all** kernel, QEMU and OVMF paths, human-readable version/build
identities and approved expected SHA-256 values explicitly. No home-directory,
previous-build or source-checkout defaults exist. Identity/hash recording does
not requalify those external artifacts.

```bash
tools/snp/build-emulator-bundle.sh --output target/bundles/emulator \
  --kernel "$KERNEL" --kernel-identity "$KERNEL_ID" --kernel-sha256 "$KERNEL_SHA256" \
  --qemu "$QEMU" --qemu-identity "$QEMU_ID" --qemu-sha256 "$QEMU_SHA256" \
  --ovmf "$OVMF" --ovmf-identity "$OVMF_ID" --ovmf-sha256 "$OVMF_SHA256"

tools/snp/build-production-bundle.sh --output target/bundles/production \
  --kernel "$KERNEL" --kernel-identity "$KERNEL_ID" --kernel-sha256 "$KERNEL_SHA256" \
  --qemu "$QEMU" --qemu-identity "$QEMU_ID" --qemu-sha256 "$QEMU_SHA256" \
  --ovmf "$OVMF" --ovmf-identity "$OVMF_ID" --ovmf-sha256 "$OVMF_SHA256"

tools/snp/validate-bundle.sh --bundle target/bundles/emulator
tools/snp/inspect-production-image.sh --bundle target/bundles/production
```

The compatibility entry point `sh_script/build_snp_azure_bundle.sh` delegates to
the emulator builder and now requires the same explicit arguments; its old
environment-only interface and implicit external paths are retired.

## Frozen v1 contract and publication

Both builders use [the same schema](../schemas/snp-ma-bundle-manifest-v1.json).
They select exactly `--no-default-features --features SnpEmuAzure` or
`--no-default-features --features SnpHardware`, respectively. Neither accepts
extra features or a composition override. Compiler-wrapper/bootstrap overrides
are rejected; owned build flags, toolchain/linker identity, environment and
commands are recorded. Each composition has a separately locked Cargo cache.

Only static x86-64 musl ELFs are supported by this minimal-rootfs contract.
The deterministic gzip/newc filesystem contains exactly `/init`, `/dev`,
`/proc`, `/sys`; `/init` must match the MA ELF byte for byte. Arbitrary external
root filesystems/dynamic-library packaging are not supported by this v1
producer. Kernel bytes are copied into the bundle. QEMU/OVMF remain external,
with required identity/hash records; explicit relocation overrides must match
the same hashes.

Each bundle contains the MA, kernel, initramfs, runtime configuration, provider
classification/availability, Cargo.lock, source/submodule/AAS provenance,
normal/build Rust dependency features, Cargo-declared native link inventory,
CycloneDX 1.5 SBOM, checksums and image inspection. Emulator bundles additionally
contain a freshly built host WFR controller; production bundles instead retain
the actual exit-2 unavailable-host startup record.

Construction happens in a private sibling staging directory. Validation must
pass before Linux `renameat2(RENAME_NOREPLACE)` publishes it. Existing outputs,
including empty directories, are never replaced. Failed staging is cleaned up;
there is no success-shaped partial output. Use different output roots for
emulator and production builds. Recorded source/submodule hashes and HEAD are
checked again before publication to detect concurrent source changes.

The validator rejects unknown schema versions/members, duplicate JSON members,
nonfinite constants, missing/corrupt/misclassified artifacts/providers, unsafe
paths, symlinks, extra files, checksum/ELF/initramfs mismatches and contradictory
provenance/SBOM records. Production checks share the Task 4 dependency/symbol
rules, scan all five captured/synthetic asset fingerprints, forbid emulator/TDX
features/dependencies and reject an apparently successful production startup.
The fingerprint policy is pinned by the trusted validator; a bundle cannot
replace it merely by recomputing its manifest hashes.

## Consumers and qualification limits

Install the MigTD-owned contract into a consumer without copying a build tree:

```bash
python3 tools/snp/export_consumer_contract.py \
  --destination /declared/consumer/bundle_contract
```

`--replace` is an explicit update of only those owned contract files. The
consumer's active interface is:

```bash
/declared/consumer/run-emulator-e2e.sh --bundle /declared/bundle
```

It reads identities, hashes, expected markers and unavailable providers from
the validated manifest, owns only topology/lifecycle/results, and retains
failures as well as successful legacy compatibility results. A standalone
bundle also carries its validator/schema; invoke its
`contract/validate_bundle.py --bundle DIR` with the declared Python dependencies,
Git-independent and outside a source checkout.

All current bundles are **Build-validated/migration-unqualified**. Both common
verifiers remain unavailable. Emulator compatibility verifies only captured-v5
signature/chain data with a separate SDK bridge and key-only mock installer.
It is not common V6 authentication, live TH1 binding, V2, firmware persistence,
production/RNG qualification or Task 14. Production MA acquisition is selected
but startup stops at the unavailable host boundary before an ioctl.

Source/AAS hashes and native inventories are provenance, not a hermetic compiler,
registry, system-library or implicit CRT closure. The native inventory explicitly
records that scope. SHA-256 integrity is not authenticity: distribute approved
manifest digests over a trusted channel and trust the producer/validator itself.
Neither build success nor matching failures grants migration qualification.

## Tests and transition ownership

```bash
python3 -m unittest discover -s tests/snp/feature-matrix -v
python3 -m unittest discover -s sh_script/test -p test_snp_task4_inventory.py -v
python3 tests/snp/integration/test_bundles.py \
  --emulator /declared/emulator --production /declared/production \
  --consumer /declared/consumer -v
```

The first tests are explicitly nonbuilt schema vectors. Integration tests use
real bundles, reseal deliberate corruptions to reach the intended deeper gates,
and never substitute a fake successful MA/attestation. SNP contract CI runs
schema/isolation controls; actual bundle and VM evidence require declared
external inputs. No existing MigTD CI job used the retired external build
workflow; existing TDX EMU CI remains unchanged.

The external transition inventories all 15 formerly active files:

| Files | Ownership/disposition |
|---|---|
| `build-initramfs.sh` | MigTD packaging; consumer stub now fails explicitly |
| `run-snp-unified-demo.sh`, `set-demo-env.sh` | Build/source defaults removed; bundle-only delegates |
| `generate-api-call-matrix.sh` | MigTD defines expected operations; consumer summarizes validated results |
| `run-emulator-e2e.sh`, `run-snp.sh`, `launch-nosnp.sh` | VM harness lifecycle/topology only |
| `README.md` | Manifest-driven consumer instructions |
| `.gitmodules` | Nested MigTD source declaration retired after explicit approval |
| `.gitignore`, `kernel-config/README.md`, `kernel-config/ohcl.config` | Harness/kernel-input ownership; no MigTD build authority |
| `demo-block-diagram.md`, `.svg`, `.txt` | Preserved historical illustrations; not active build instructions |

Old/new VM evidence and the approved stale-assertion deviation are retained in
the central execution record. The clean nested source was moved intact to its
explicitly approved session archive; historical Git objects and all 413 tracked
file hashes were preserved. No source or cache contents were deleted.
