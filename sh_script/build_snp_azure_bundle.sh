#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_ENCLAVE_REPO="${VM_ENCLAVE_REPO:-$HOME/nested_openvmm/vm_enclave}"
QUALIFIED_BUILD="${QUALIFIED_BUILD:-$HOME/snp-unified-ma-work/builds/snp-unified-wfr/20260910-023049}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-$HOME/snp-unified-ma-work/builds/snp-unified-wfr/azure-attestation}"
BUILD_ID="${BUILD_ID:-$(date -u +%Y%m%d-%H%M%S)}"
BUNDLE_DIR="$ARTIFACT_ROOT/$BUILD_ID"
QEMU_PATH="${QEMU_PATH:-$HOME/nested_openvmm/qemu-9.2/build/qemu-system-x86_64}"
OVMF_PATH="${OVMF_PATH:-$HOME/nested_openvmm/edk2-amdsev/Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd}"

mkdir -p "$BUNDLE_DIR"
unset MIGTD_EXPECTED_SHA256

export RUSTFLAGS="${RUSTFLAGS:--A dangerous-implicit-autorefs}"
export AS="${AS:-nasm}"
export AR="${AR:-llvm-ar}"
export CC="${CC:-x86_64-linux-musl-gcc}"

(cd "$ROOT" && cargo build \
    -p migtd --bin migtd --no-default-features \
    --features SnpEmuAzure \
    --target x86_64-unknown-linux-musl --release)

MIGTD_BIN="$ROOT/target/x86_64-unknown-linux-musl/release/migtd"
MIGTD_SHA256="$(sha256sum "$MIGTD_BIN" | awk '{print $1}')"

MIGTD_NO_BUILD=1 MIGTD_BIN_PATH="$MIGTD_BIN" \
    "$VM_ENCLAVE_REPO/build-initramfs.sh"

cp "$MIGTD_BIN" "$BUNDLE_DIR/migtd"
cp "$VM_ENCLAVE_REPO/initramfs.cpio.gz" "$BUNDLE_DIR/initramfs.cpio.gz"
cp "$QUALIFIED_BUILD/bzImage" "$BUNDLE_DIR/bzImage"
cp "$QUALIFIED_BUILD/host_wfr_test" "$BUNDLE_DIR/host_wfr_test"

INITRAMFS_SHA256="$(sha256sum "$BUNDLE_DIR/initramfs.cpio.gz" | awk '{print $1}')"
BZIMAGE_SHA256="$(sha256sum "$BUNDLE_DIR/bzImage" | awk '{print $1}')"
HOST_WFR_SHA256="$(sha256sum "$BUNDLE_DIR/host_wfr_test" | awk '{print $1}')"

cat > "$BUNDLE_DIR/use-build.sh" <<EOF
#!/usr/bin/env bash
export HOST_WFR_TEST="$BUNDLE_DIR/host_wfr_test"
export MIGTD_BIN_PATH="$BUNDLE_DIR/migtd"
export MIGTD_EXPECTED_SHA256="$MIGTD_SHA256"
export ATTESTATION_BACKEND="azure-attestation"
export ATTESTATION_EVIDENCE_MARKER="operation=AZURE_VERIFY_ATTESTATION"
export BZIMAGE="$BUNDLE_DIR/bzImage"
export INITRD="$BUNDLE_DIR/initramfs.cpio.gz"
export QEMU="$QEMU_PATH"
export OVMF="$OVMF_PATH"
export LOG_ROOT="$BUNDLE_DIR/runs/run-\$(date +%Y%m%d-%H%M%S)"
EOF
chmod +x "$BUNDLE_DIR/use-build.sh"

cat > "$BUNDLE_DIR/manifest.txt" <<EOF
backend=azure-attestation
migtd_repo=$ROOT
migtd_branch=$(git -C "$ROOT" branch --show-current)
migtd_commit=$(git -C "$ROOT" rev-parse HEAD)
azure_sdk_commit=23bf1d1b62d2a3fcbf3eed8f80c5a2bd54e5028b
rustc=$(cd "$ROOT" && rustc --version)
features=SnpEmuAzure
migtd_path=$BUNDLE_DIR/migtd
migtd_sha256=$MIGTD_SHA256
initramfs_path=$BUNDLE_DIR/initramfs.cpio.gz
initramfs_sha256=$INITRAMFS_SHA256
bzimage_path=$BUNDLE_DIR/bzImage
bzimage_sha256=$BZIMAGE_SHA256
host_wfr_test_path=$BUNDLE_DIR/host_wfr_test
host_wfr_test_sha256=$HOST_WFR_SHA256
EOF

printf 'Azure bundle created: %s\n' "$BUNDLE_DIR"
printf 'MA SHA-256: %s\n' "$MIGTD_SHA256"
