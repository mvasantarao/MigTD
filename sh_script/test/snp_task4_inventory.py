#!/usr/bin/env python3
"""Build separate provisional Task 4 ELF inventories; not P2.2 bundles."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_SYMBOLS = (
    "snp_emu::", "pal::snp::fixture::", "legacy_fixture",
    "MockMigrationKeyInstaller", "DeterministicRandomSource",
    "tee_attestation_verification", "tav_crypto",
    "tdx_tdcall", "tdx_tdcall_emu", "vmcall_raw::",
)
FORBIDDEN_FEATURES = {
    "snp-fixture", "snp-emu", "snp-state-emulator", "snp-tcp-transport",
    "snp-mock-installation", "snp-mock-rebind", "snp_fixture_only",
    "SnpEmu", "SnpEmuAzure", "tdx-platform", "test_mock_report",
    "test_disable_ra_and_accept_all", "use-mock-quote",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fixture_needles():
    directory = ROOT / "src/snp_emu/src/fixture_data"
    needles = {str(p.relative_to(ROOT)): p.read_bytes()
               for p in (directory / name for name in ("snp_report.bin", "vcek.der", "ask.der"))}
    vectors = ROOT / "src/pal/src/snp/test_data/p010_vectors.txt"
    for line in vectors.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in {"root_der", "unrelated_root_der"}:
            needles[f"{vectors.relative_to(ROOT)}:{fields[0]}"] = bytes.fromhex(fields[1])
    if len(needles) != 5 or any(not value for value in needles.values()):
        raise RuntimeError("expected three captured fixture assets and two synthetic roots")
    return needles


def scan_production(binary, symbols, needles):
    hits = [name for name, value in needles.items() if value in binary]
    symbols_found = [name for name in FORBIDDEN_SYMBOLS
                     if name in symbols or name.encode() in binary]
    if hits or symbols_found:
        raise RuntimeError(f"production isolation failed: assets={hits}, symbols={symbols_found}")
    return {"fixture_or_synthetic_root_hits": hits, "forbidden_symbol_hits": symbols_found}


def dependency_inventory(tree, production):
    packages = {}
    for line in tree.splitlines():
        identity, separator, features = line.partition("|")
        if not separator:
            raise RuntimeError(f"unrecognized Cargo tree line: {line}")
        active = set(features.removesuffix(" (*)").split(",")) - {""}
        name = identity.split()[0]
        if name.startswith(("tee-attestation", "tav-")):
            raise RuntimeError(f"TAV dependency found: {identity}")
        if production:
            if name.startswith(("td-", "tdx-")) or name in {
                "snp_emu", "vmcall_raw", "vsock", "attestation", "spdmlib",
            }:
                raise RuntimeError(f"production emulator/TDX dependency: {identity}")
            if name in {"pal", "migtd"} and active & FORBIDDEN_FEATURES:
                raise RuntimeError(f"production emulator/test features: {line}")
        if name == "azure-guest-attestation-sdk":
            if not {"native", "verify"} <= active or active & {"rustcrypto", "symcrypt"}:
                raise RuntimeError(f"unexpected AAS backend: {line}")
        packages.setdefault(identity, set()).update(active)
    if not any(key.startswith("azure-guest-attestation-sdk ") for key in packages):
        raise RuntimeError("selected AAS dependency missing")
    return [{"package": key, "features": sorted(value)} for key, value in sorted(packages.items())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--target", required=True, help="Explicit Rust target triple")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(label, command, expected_exit=0, timeout=None):
        result = subprocess.run(command, cwd=ROOT, env=os.environ.copy(),
                                capture_output=True, text=True, timeout=timeout)
        (output / f"{label}.log").write_text(result.stdout + result.stderr)
        commands.append({"name": label, "command": command, "exit_code": result.returncode,
                         "expected_exit": expected_exit})
        if result.returncode != expected_exit:
            raise RuntimeError(f"{label} exited {result.returncode}; see {output / f'{label}.log'}")
        return result.stdout

    try:
        rustc = run("rustc", ["rustc", "-vV"])
        cargo = run("cargo", ["cargo", "--version"])
        head = run("head", ["git", "rev-parse", "HEAD"]).strip()
        status = run("worktree", ["git", "--no-pager", "status", "--porcelain"])
        source_paths = run("source-paths", [
            "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z",
        ]).split("\0")
        source_hashes = {p: sha256((ROOT / p).read_bytes())
                         for p in source_paths if p and (ROOT / p).is_file()}
        needles = fixture_needles()
        for feature in ("SnpEmuAzure", "SnpHardware"):
            production = feature == "SnpHardware"
            directory = output / feature
            directory.mkdir()
            options = ["-p", "migtd", "--no-default-features", "--features", feature,
                       "--target", args.target, "--offline", "--locked"]
            tree = run(f"{feature}-tree", [
                "cargo", "tree", *options, "--edges", "normal,build", "--prefix", "none",
                "--format", "{p}|{f}",
            ])
            packages = dependency_inventory(tree, production)
            artifacts = run(f"{feature}-build", [
                "cargo", "build", "--release", *options, "--bin", "migtd",
                "--message-format", "json",
            ])
            executables = [
                entry["executable"] for line in artifacts.splitlines() if line.startswith("{")
                for entry in [json.loads(line)]
                if entry.get("reason") == "compiler-artifact" and entry.get("executable")
                and entry["target"]["name"] == "migtd"
            ]
            if len(executables) != 1:
                raise RuntimeError(f"expected exactly one {feature} binary: {executables}")
            binary_path = directory / "migtd"
            shutil.copy2(executables[0], binary_path)
            binary = binary_path.read_bytes()
            if binary[:4] != b"\x7fELF":
                raise RuntimeError(f"{feature} artifact is not ELF")
            symbols = run(f"{feature}-symbols", ["nm", "-C", str(binary_path)])
            if not re.search(r"\b[Tt]\s+", symbols):
                raise RuntimeError("symbol scan requires an unstripped executable with text symbols")
            scan = {"kind": "emulator-fixture-presence"}
            if production:
                scan = scan_production(binary, symbols, needles)
                run("production-startup", [str(binary_path)], expected_exit=2, timeout=15)
                startup = (output / "production-startup.log").read_text()
                if "HostControl(ProviderUnavailable)" not in startup or "no emulator fallback" not in startup:
                    raise RuntimeError("production startup did not report the selected unavailable host boundary")
            else:
                captured = [name for name, value in needles.items()
                            if "fixture_data/" in name and value in binary]
                if len(captured) != 3:
                    raise RuntimeError(f"emulator fixture scan is not a valid positive control: {captured}")
                scan["captured_assets_present"] = captured
            manifest = {
                "kind": "T4.19-provisional-image-content-inventory",
                "composition": feature, "target": args.target, "profile": "release",
                "default_features": False, "features": [feature],
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "git_head": head, "worktree_status": status,
                "source_sha256": source_hashes, "cargo_lock_sha256": sha256((ROOT / "Cargo.lock").read_bytes()),
                "rustc": rustc, "cargo": cargo,
                "environment": {key: os.environ.get(key) for key in (
                    "AS", "AR", "CC", "RUSTFLAGS", "RUSTUP_TOOLCHAIN", "CARGO_NET_OFFLINE",
                )},
                "images": [{"path": "migtd", "size": len(binary), "sha256": sha256(binary)}],
                "normal_build_dependency_inventory": packages,
                "scan": scan,
                "scan_needles": {name: {"size": len(value), "sha256": sha256(value)}
                                 for name, value in needles.items()},
                "limits": [
                    "Not a P2.2 versioned/qualified deployment bundle; ELF only, no kernel/initramfs.",
                    "Common AAS V6/layout verification remains unavailable; AAS1A-M executable tests deferred.",
                    "No full Task3 or V2 transport/state/effect activation or hardware qualification.",
                    "Captured legacy SDK verification is not common claims or fresh TH1 evidence.",
                    "Byte/symbol scans cover named assets and surviving symbols, not runtime qualification.",
                    "Linux MA acquisition is selected in source; optimized ELF presence is not required.",
                    "The genuine public AMD ARK is not a synthetic root or a forbidden fixture.",
                ],
            }
            (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print("PASS: separate emulator/production release inventories, isolation and fail-closed startup")
    finally:
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")


if __name__ == "__main__":
    main()
