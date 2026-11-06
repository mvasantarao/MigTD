// Copyright (c) 2022-2026 Intel Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

extern crate alloc;

#[cfg(all(feature = "tdx-platform", not(feature = "SnpEmu"), not(test)))]
mod legacy;

#[cfg(all(feature = "SnpEmu", not(test)))]
mod snpemu;

#[cfg(all(
    feature = "tdx-platform",
    feature = "std",
    not(feature = "SnpEmu"),
    not(test)
))]
fn main() {
    legacy::main();
}

#[cfg(all(feature = "SnpEmu", not(test)))]
fn main() {
    snpemu::main();
}

#[cfg(feature = "SnpHardware")]
fn main() {
    match migtd::snp_composition::start_selected_runtime(
        migtd::snp_composition::selected_provider_set(),
    ) {
        Ok(never) => match never {},
        Err(error) => eprintln!(
            "[MA] SnpHardware startup refused: production AAS Version 6 layout, \
             host/peer transport, state and effect providers are unavailable; \
             no emulator fallback; selected provider error={error:?}"
        ),
    }
    std::process::exit(2);
}

#[cfg(all(
    feature = "entry",
    feature = "std",
    not(any(feature = "AzCVMEmu", feature = "SnpEmu", feature = "SnpHardware"))
))]
compile_error!(
    "std entry requires an explicit AzCVMEmu, SnpEmuAzure/SnpEmu or SnpHardware composition"
);
