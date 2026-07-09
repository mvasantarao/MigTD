#!/bin/bash

preparation() {
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd

    # Relax zerocopy exact pin in td-shim submodule to allow TAV compatibility.
    # td-shim pins "=0.8.27" exactly; TAV (used by pal/snp-emu) needs "^0.8.31".
    # Relaxing to "0.8" lets cargo pick a single compatible version (>=0.8.31).
    for f in \
        deps/td-shim/td-shim-interface/Cargo.toml \
        deps/td-shim/td-shim/Cargo.toml \
        deps/td-shim/td-payload/Cargo.toml \
        deps/td-shim/cc-measurement/Cargo.toml; do
        sed -i 's/zerocopy = { version = "=0.8.27"/zerocopy = { version = "0.8"/' "$f"
    done

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
