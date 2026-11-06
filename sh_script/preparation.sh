#!/bin/bash

if [[ "${1:-}" == "--snp-bundle" ]]; then
    set -euo pipefail
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    if [[ $# -ne 1 ]]; then
        echo "ERROR: --snp-bundle accepts no additional arguments" >&2
        exit 2
    fi
    ring="$root/deps/td-shim/library/ring"
    if [[ ! -f "$ring/Cargo.toml" ]]; then
        echo "ERROR: initialize declared Git submodules before SNP bundle preparation" >&2
        exit 2
    fi
    expected=$(git -C "$root/deps/td-shim" rev-parse HEAD:library/ring)
    actual=$(git -C "$ring" rev-parse HEAD)
    if [[ "$expected" != "$actual" ]] || ! git -C "$ring" diff --quiet HEAD --; then
        echo "ERROR: SNP bundles require the unmodified, pinned pre-patched ring checkout" >&2
        exit 2
    fi
    echo "SNP bundle preparation: pinned pre-patched ring; no reset, clean or duplicate patching"
    exit 0
fi

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    # Apply spdm-rs ring patches to td-shim's ring (used via [patch.crates-io])
    pushd deps/td-shim/library/ring
    git apply ../../../spdm-rs/external/patches/ring/0003-introduce-EphemeralPrivateKey-serialization.patch
    git apply ../../../spdm-rs/external/patches/ring/0004-Introduce-digest-de-serialization.patch
    popd

    pushd deps/spdm-rs
    bash sh_script/pre-build.sh
    popd
}

preparation
