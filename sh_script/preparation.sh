#!/bin/bash

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -gt 1 ]] || [[ $# -eq 1 && "$1" != "--snp-bundle" ]]; then
    echo "ERROR: usage: $0 [--snp-bundle]" >&2
    exit 2
fi

check_pinned_ring() {
    local ring="$root/deps/td-shim/library/ring"
    if [[ ! -f "$ring/Cargo.toml" ]]; then
        echo "ERROR: initialize declared Git submodules before preparation" >&2
        exit 2
    fi
    local expected actual
    expected=$(git -C "$root/deps/td-shim" rev-parse HEAD:library/ring)
    actual=$(git -C "$ring" rev-parse HEAD)
    if [[ "$expected" != "$actual" ]] || ! git -C "$ring" diff --quiet HEAD --; then
        echo "ERROR: preparation requires the unmodified, pinned pre-patched ring checkout" >&2
        exit 2
    fi

    # The fork pins a complete patch set; upstream preparation would reset it.
    local patch
    for patch in \
        "$root/deps/td-shim/library/patches/ring.diff" \
        "$root/deps/td-shim/library/patches/0002-Disable-checks-for-SSE-and-SSE2.patch" \
        "$root/deps/spdm-rs/external/patches/ring/0003-introduce-EphemeralPrivateKey-serialization.patch" \
        "$root/deps/spdm-rs/external/patches/ring/0004-Introduce-digest-de-serialization.patch"
    do
        if ! git -C "$ring" apply --reverse --check "$patch"; then
            echo "ERROR: pinned ring does not contain required patch: $patch" >&2
            exit 2
        fi
    done
}

check_pinned_ring
if [[ "${1:-}" == "--snp-bundle" ]]; then
    echo "SNP bundle preparation: pinned pre-patched ring; no reset, clean or duplicate patching"
    exit 0
fi

echo "Using the pinned, pre-patched td-shim ring"
for patch in "$root/deps/spdm-rs/external/patches/ring/"*.patch; do
    ring="$root/deps/spdm-rs/external/ring"
    if git -C "$ring" apply --reverse --check "$patch" >/dev/null 2>&1; then
        echo "Already applied: $(basename "$patch")"
    else
        git -C "$ring" apply --check "$patch"
        git -C "$ring" apply "$patch"
        echo "Applied: $(basename "$patch")"
    fi
done
