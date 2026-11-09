#!/usr/bin/env python3
"""Check isolated SNP feature graphs and compile-time composition exclusions."""

import argparse
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "target/snp-feature-conformance")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = []

    def run(name, arguments, expected_success=True, diagnostic=None):
        result = subprocess.run(
            ["cargo", *arguments, "--offline", "--locked"],
            cwd=ROOT, env=os.environ.copy(), text=True, capture_output=True,
        )
        text = result.stdout + result.stderr
        (args.output_dir / f"{name}.log").write_text(text)
        passed = (result.returncode == 0) == expected_success
        if diagnostic is not None:
            passed = passed and diagnostic in text
        results.append({"name": name, "exit_code": result.returncode, "passed": passed})
        if not passed:
            raise RuntimeError(f"{name} failed; see {args.output_dir / f'{name}.log'}\n{text}")
        return result.stdout

    try:
        for label, features in [
            ("core", "snp-core"), ("std", "std"),
            ("underhill-runtime", "SnpUnderhillRuntime"),
            ("underhill-alias", "SnpUnderhill"),
            ("linux-hardware", "snp-linux-hardware"),
            ("emulator-without-bypass", "SnpEmuAzure"),
            ("emulator-legacy-alias", "SnpEmu"),
            ("production", "SnpHardware"),
            ("azcvm-compatibility", "AzCVMEmu,test_disable_ra_and_accept_all"),
        ]:
            run(f"check-{label}", [
                "check", "-p", "migtd", "--no-default-features", "--features", features,
            ])

        for label, features in [
            ("core", "snp-core"), ("runtime", "SnpUnderhillRuntime"),
            ("production", "SnpHardware"), ("emulator", "SnpEmuAzure"),
        ]:
            tree = run(f"tree-{label}", [
                "tree", "-p", "migtd", "--no-default-features", "--features", features,
                "--edges", "normal,build", "--prefix", "none", "--format", "{p} features={f}",
            ])
            for line in tree.splitlines():
                package = line.split()[0]
                forbidden_package = (
                    package.startswith(("td-", "tdx-", "tee-attestation", "tav-"))
                    or package in {"vmcall_raw", "vsock", "attestation"}
                    or (label != "emulator" and package in {"snp_emu", "spdmlib"})
                )
                if forbidden_package:
                    raise AssertionError(f"{label} includes forbidden provider: {line}")
                if package == "azure-guest-attestation-sdk":
                    active = set(line.split("features=", 1)[1].split(","))
                    if not {"native", "verify"}.issubset(active) or {"rustcrypto", "symcrypt"}.intersection(active):
                        raise AssertionError(f"{label} changed the selected native AAS backend: {line}")
                if label != "emulator" and package in {"pal", "migtd"}:
                    forbidden_features = {
                        "snp-fixture", "snp-emu", "snp-state-emulator", "snp-tcp-transport",
                        "snp-mock-installation", "snp-mock-rebind", "snp_fixture_only",
                    }
                    active = line.split("features=", 1)[1].split(",")
                    if forbidden_features.intersection(active):
                        raise AssertionError(f"{label} includes emulator capability: {line}")

        tdx_tree = run("tree-tdx-no-std", [
            "tree", "-p", "migtd", "--no-default-features", "--features", "main,virtio-vsock",
            "--edges", "normal,build", "--prefix", "none", "--format", "{p} features={f}",
        ])
        for line in tdx_tree.splitlines():
            if line.split()[0] == "migtd" and "std" in line.split("features=", 1)[1].split(","):
                raise AssertionError("TDX firmware unexpectedly enables std")

        emulator_options = [
            "SnpEmuAzure", "SnpEmu", "snp-fixture", "snp-state-emulator",
            "snp-tcp-transport", "snp-mock-installation", "snp-mock-rebind",
            "snp_fixture_only",
        ]
        tdx_options = [
            "AzCVMEmu", "tdx-platform", "main", "virtio-vsock", "virtio-serial",
            "vmcall-vsock", "vmcall-raw", "test_disable_ra_and_accept_all",
            "test_mock_report", "use-mock-quote",
            "attestation", "stack-guard", "cet-shstk", "igvm-attest",
        ]
        for option in ["main", "tdx-platform", "spdm_attestation", "policy_v2",
                       "vmcall-raw", "virtio-vsock", "virtio-serial", "vmcall-vsock",
                       "AzCVMEmu", "test_disable_ra_and_accept_all", "test_mock_report",
                       "use-mock-quote", "stack-guard", "igvm-attest"]:
            run(f"reject-emulator-{option}", [
                "check", "-p", "migtd", "--no-default-features",
                "--features", f"SnpEmuAzure,{option}",
            ], expected_success=False, diagnostic="compositions are mutually exclusive"
                if option in {"AzCVMEmu", "test_mock_report"} else
                "SnpEmu cannot include TDX platform features")
        for option in emulator_options + tdx_options:
            diagnostic = (
                "SNP hardware cannot include fixture evidence, synthetic roots or TDX providers"
                if option in emulator_options else
                "SnpHardware cannot include TDX providers, transports, policy or attestation bypasses"
            )
            run(f"reject-{option}", [
                "check", "-p", "migtd", "--no-default-features",
                "--features", f"SnpHardware,{option}",
            ], expected_success=False, diagnostic=diagnostic)

        for option in ["snp-fixture", "snp-state-emulator", "snp-mock-installation",
                       "snp-mock-rebind", "snp_fixture_only", "tdx"]:
            run(f"reject-pal-{option}", [
                "check", "-p", "pal", "--no-default-features",
                "--features", f"snp-production,{option}",
            ], expected_success=False,
                diagnostic="SNP hardware cannot include fixture evidence, synthetic roots or TDX providers")

        run("reject-incomplete-std-entry", [
            "check", "-p", "migtd", "--no-default-features", "--features", "entry,std",
        ], expected_success=False, diagnostic="std entry requires an explicit")

        def check_public_api(family, features, cases, package="pal"):
            artifacts = run(f"build-api-{family}", [
                "build", "-p", package, "--lib", "--no-default-features",
                "--features", features, "--message-format", "json",
            ])
            libraries = [
                Path(filename)
                for line in artifacts.splitlines()
                for artifact in [json.loads(line)]
                if artifact.get("reason") == "compiler-artifact"
                and artifact["target"]["name"] == package
                for filename in artifact["filenames"] if filename.endswith(".rlib")
            ]
            if len(libraries) != 1:
                raise RuntimeError(f"expected exactly one {package} artifact for {family}: {libraries}")
            library = libraries[0]
            dependency_dir = library.parent if library.parent.name == "deps" else library.parent / "deps"
            for name, source, expected_success, diagnostic in cases:
                label = f"api-{family}-{name}"
                source_path = args.output_dir.resolve() / f"{label}.rs"
                source_path.write_text(source)
                result = subprocess.run([
                    "rustc", "--edition=2021", "--crate-type=lib",
                    "--crate-name", label.replace("-", "_"), "-C", "panic=abort",
                    "--emit", f"metadata={source_path.with_suffix('.rmeta')}",
                    "-L", f"dependency={dependency_dir}", "--extern", f"{package}={library}",
                    str(source_path),
                ], cwd=ROOT, env=os.environ.copy(), text=True, capture_output=True)
                text = result.stdout + result.stderr
                (args.output_dir / f"{label}.log").write_text(text)
                passed = (result.returncode == 0) == expected_success
                if diagnostic is not None:
                    passed = passed and diagnostic in text
                results.append({"name": label, "exit_code": result.returncode, "passed": passed})
                if not passed:
                    raise RuntimeError(f"{label} failed; see {args.output_dir / f'{label}.log'}")

        production = "pal::composition::snp::SnpHardware"
        emulator = "pal::composition::snp::SnpEmuAzure"
        check_public_api("production", "snp-production", [
            ("reachable", f"pub fn check() {{ let _ = {production}::compose(); }}", True, None),
            ("no-fixture-root", f"use {emulator};", False, "unresolved import"),
            ("no-fixture-provider", "use pal::snp::fixture::platform_services::MockMigrationKeyInstaller;",
             False, "could not find `fixture`"),
            ("no-legacy-fixture-codec", "use pal::snp::fixture::encode_legacy_ma_blob;",
             False, "could not find `fixture`"),
            ("closed-constructor", f"pub fn check() {{ let _ = {production}::compose(()); }}",
             False, "takes 0 arguments"),
            ("owned-randomness", f"pub fn check() {{ let mut set = {production}::compose(); "
             "set.randomness = pal::random::SystemRandomSource::default(); }",
             False, "is private"),
            ("no-deterministic-randomness", "use pal::random::DeterministicRandomSource;",
             False, "unresolved import"),
            ("no-forged-receipt", "pub fn check() { let _ = pal::snp::tenant_source::TenantEvidence {}; }",
             False, "private fields"),
            ("sealed-composition", "pub struct HostChoice; "
             "impl pal::composition::snp::SnpComposition for HostChoice { "
             "const PLATFORM: pal::composition::PlatformComposition = "
             "pal::composition::PlatformComposition::SnpHardware; }",
             False, "Sealed"),
        ])
        check_public_api("fixture", "snp-fixture", [
            ("reachable", f"pub fn check() {{ let _ = {emulator}::unavailable(); }}", True, None),
            ("no-production-root", f"use {production};", False, "unresolved import"),
            ("no-linux-hardware", "use pal::snp::hardware::SnpHardwareProvider;",
             False, "could not find `hardware`"),
        ])
        operation = "migtd::runtime::snp::requests::LegacyOperation"
        request = "migtd::runtime::snp::requests::HostRequest"
        check_public_api("snp-host", "SnpEmuAzure", [
            ("reachable", f"pub fn check(op: {operation}) -> {request} {{ "
             f"let _ = op.operation.managed_guest.value(); {request}::StartMigration(op) }}",
             True, None),
            ("no-tdx-session", "use migtd::migration::session;",
             False, "could not find `migration`"),
            ("no-td-uuid", f"pub fn check(op: {operation}) {{ let _ = op.target_td_uuid; }}",
             False, "no field `target_td_uuid`"),
            ("no-servtd-binding", f"pub fn check(op: {operation}) {{ let _ = op.binding_handle; }}",
             False, "no field `binding_handle`"),
            ("no-tdreport-verifier", "pub fn check() { let _ = migtd::spdm::verify_tdreport_data_binding; }",
             False, "cannot find value `verify_tdreport_data_binding`"),
        ], package="migtd")

        lockfile = (ROOT / "Cargo.lock").read_text()
        if any(f'name = "{name}"' in lockfile
               for name in ["tee-attestation-verification-lib",
                            "tee-attestation-verification-crypto", "tav-crypto"]):
            raise AssertionError("TAV remains in the workspace lockfile")
        print(f"PASS: {len(results)} compile/dependency checks; no TAV lockfile packages")
    finally:
        (args.output_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
