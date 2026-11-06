#!/usr/bin/env python3
"""Build and atomically publish a closed-composition, static PID1 bundle."""

import argparse
import ctypes
from datetime import datetime, timezone
import fcntl
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from image_content import dependency_inventory, fingerprints, fixture_needles, sbom_components
from validate_bundle import (
    ARTIFACTS, NATIVE_SCOPE, QUALIFICATION, SCHEMA_NAME, file_hash, inspect_elf,
    legacy_contract, marker_contract, parse_initramfs, provider_contract,
    read_json, require, schema_path, sha256, validate_bundle,
)
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"
ENVIRONMENT_KEYS = (
    "AS", "AR", "CC", "CXX", "CFLAGS", "CXXFLAGS", "RUSTFLAGS", "RUSTUP_TOOLCHAIN",
    "CMAKE_TOOLCHAIN_FILE", "CMAKE_MAKE_PROGRAM", "SOURCE_DATE_EPOCH",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER", "CARGO_TARGET_DIR",
)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o644)


def run(command, *, env=None, log=None):
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(result.stdout + result.stderr)
        log.chmod(0o644)
    if result.returncode:
        raise RuntimeError(f"command exited {result.returncode}: {command}\n{result.stderr}")
    return result.stdout


def source_inventory():
    names = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    paths = sorted(p for p in names.split("\0") if p and not p.startswith("doc/")
                   and not p.endswith((".md", ".pyc")) and (ROOT / p).is_file())
    submodules = []
    for line in run(["git", "submodule", "status", "--recursive"]).splitlines():
        require(line[0] in " +", f"uninitialized/conflicted submodule: {line}")
        commit, path, *_ = line[1:].split()
        directory = ROOT / path
        tracked = run(["git", "-C", str(directory), "ls-files", "-z"]).split("\0")
        submodules.append({
            "path": path, "commit": commit,
            "worktree": run(["git", "-C", str(directory), "status", "--porcelain"]),
            "files": {p: file_hash(directory / p) for p in tracked
                      if p and (directory / p).is_file()},
        })
    return {
        "head": run(["git", "rev-parse", "HEAD"]).strip(),
        "worktree": run(["git", "status", "--porcelain"]),
        "scope": "Non-document top-level inputs plus recursively tracked submodule files; not registry/system hermeticity",
        "files": {p: file_hash(ROOT / p) for p in paths},
        "submodules": submodules,
    }


def newc_entry(name, payload, mode, ino):
    encoded = name.encode("ascii") + b"\0"
    fields = (ino, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + "".join(f"{n:08x}" for n in fields).encode("ascii")
    data = header + encoded
    data += b"\0" * (-len(data) % 4)
    data += payload
    return data + b"\0" * (-len(data) % 4)


def make_initramfs(binary, output):
    data = b""
    for ino, name in enumerate(("dev", "init", "proc", "sys"), 1):
        payload = binary.read_bytes() if name == "init" else b""
        mode = (stat.S_IFREG if name == "init" else stat.S_IFDIR) | 0o755
        data += newc_entry(name, payload, mode, ino)
    data += newc_entry("TRAILER!!!", b"", 0, 5)
    data += b"\0" * (-len(data) % 512)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(gzip.compress(data, compresslevel=9, mtime=0))
    output.chmod(0o644)


def external_input(path, identity, expected):
    require(path.is_file() and path.stat().st_size > 0, f"external input missing/empty: {path}")
    require(re.fullmatch("[0-9a-f]{64}", expected) is not None
            and file_hash(path) == expected, f"declared external input hash mismatch: {path}")
    return {
        "path": str(path.resolve()), "identity": identity,
        "sha256": expected, "size": path.stat().st_size,
        "qualification": "Identity/hash recorded; not requalified by P2.2",
    }


def native_inventory(messages):
    native = []
    for entry in messages:
        if entry.get("reason") != "build-script-executed":
            continue
        searches = [Path(p.removeprefix("native=")) for p in entry["linked_paths"]
                    if p.startswith("native=")]
        for library in entry["linked_libs"]:
            name = library.split("=")[-1].split(":")[-1]
            candidates = sorted({
                path.resolve() for directory in searches
                for pattern in (f"lib{name}.a", f"lib{name}.so", f"{name}.lib")
                for path in directory.glob(pattern) if path.is_file()
            })
            native.append({
                "package_id": entry["package_id"], "library": library,
                "link_search": [str(p) for p in searches],
                "archives": [{
                    "path": str(p), "sha256": file_hash(p), "size": p.stat().st_size,
                } for p in candidates],
            })
    require(native, "Cargo emitted no native inventory")
    return sorted(native, key=lambda e: (e["package_id"], e["library"]))


def copy_file(source, destination, mode):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def record(path, root):
    return {"path": path.relative_to(root).as_posix(), "sha256": file_hash(path),
            "size": path.stat().st_size, "mode": stat.S_IMODE(path.stat().st_mode)}


def verify_source_unchanged(source):
    require(run(["git", "rev-parse", "HEAD"]).strip() == source["head"],
            "source HEAD changed during bundle construction")
    for path, expected in source["files"].items():
        require(file_hash(ROOT / path) == expected, f"source changed during build: {path}")
    for module in source["submodules"]:
        directory = ROOT / module["path"]
        require(run(["git", "-C", str(directory), "rev-parse", "HEAD"]).strip() == module["commit"],
                f"submodule changed during build: {module['path']}")
        for path, expected in module["files"].items():
            require(file_hash(directory / path) == expected,
                    f"submodule source changed during build: {module['path']}/{path}")


def publish_directory(stage, output):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(output), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(output))


def publish(args, creation_command):
    output = args.output.absolute()
    require(not os.path.lexists(output), f"refusing to overwrite an existing output: {output}")
    for name in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_ENCODED_RUSTFLAGS",
                 "RUSTC_BOOTSTRAP"):
        require(not os.environ.get(name), f"undeclared compiler override is forbidden: {name}")
    external = {name: external_input(
        getattr(args, name), getattr(args, f"{name}_identity"), getattr(args, f"{name}_sha256"),
    ) for name in ("kernel", "qemu", "ovmf")}
    run(["bash", str(ROOT / "sh_script/preparation.sh"), "--snp-bundle"])
    linker = shutil.which(args.linker)
    require(linker is not None, f"declared linker not found: {args.linker}")
    env = os.environ.copy()
    env.update({
        "AS": "nasm", "AR": "llvm-ar", "CC": args.cc,
        "CARGO_TARGET_DIR": str(ROOT / "target/snp-bundle-build" / args.composition),
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER": linker,
        "RUSTFLAGS": f"-A dangerous-implicit-autorefs --remap-path-prefix={ROOT}=/migtd",
    })
    options = [
        "-p", "migtd", "--no-default-features", "--features", args.composition,
        "--target", TARGET, "--offline", "--locked",
    ]
    tree_command = [
        "cargo", "tree", *options, "--edges", "normal,build", "--prefix", "none",
        "--format", "{p}|{f}",
    ]
    build_command = [
        "cargo", "build", "--release", *options, "--bin", "migtd",
    ]
    if args.composition == "SnpEmuAzure":
        build_command += ["--bin", "host_wfr_test"]
    build_command += ["--message-format", "json"]
    metadata_command = [
        "cargo", "metadata", "--offline", "--locked", "--format-version", "1",
        "--no-default-features", "--features", args.composition, "--filter-platform", TARGET,
    ]
    source = source_inventory()
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        tree = run(tree_command, env=env)
        packages = dependency_inventory(tree, args.composition == "SnpHardware")
        metadata = json.loads(run(metadata_command, env=env))
        aas_packages = [p for p in metadata["packages"]
                        if p["name"] == "azure-guest-attestation-sdk"]
        require(len(aas_packages) == 1, "expected exactly one resolved AAS package")
        source_id = aas_packages[0]["source"]
        match = re.fullmatch(r"git\+(https://[^?]+)\?rev=[^#]+#([0-9a-f]{40})", source_id)
        require(match is not None, "AAS dependency is not pinned to a Git commit")
        aas = {"repository": match[1], "commit": match[2]}
        sdk_dir = Path(aas_packages[0]["manifest_path"]).parent
        sdk_status = run(["git", "-C", str(sdk_dir), "status", "--porcelain"])
        require(all(line == "?? .cargo-ok" for line in sdk_status.splitlines()),
                "resolved AAS dependency checkout contains non-Cargo-generated changes")
        sdk_root = Path(run(["git", "-C", str(sdk_dir), "rev-parse", "--show-toplevel"]).strip())
        sdk_files = run(["git", "-C", str(sdk_root), "ls-files", "-z"]).split("\0")
        source["aas"] = {
            **aas, "worktree": sdk_status, "ignored_generated_markers": [".cargo-ok"],
            "files": {p: file_hash(sdk_root / p) for p in sdk_files
                      if p and (sdk_root / p).is_file()},
        }
        artifact_output = run(build_command, env=env, log=stage / ARTIFACTS["build_log"])
        messages = [json.loads(line) for line in artifact_output.splitlines() if line.startswith("{")]
        executables = {}
        for entry in messages:
            if entry.get("reason") == "compiler-artifact" and entry.get("executable"):
                name = entry["target"]["name"]
                require(name not in executables, f"ambiguous compiler executable: {name}")
                executables[name] = Path(entry["executable"])
        expected = {"migtd"} | ({"host_wfr_test"} if args.composition == "SnpEmuAzure" else set())
        require(set(executables) == expected, f"unexpected compiler outputs: {set(executables)}")
        paths = dict(ARTIFACTS)
        if args.composition == "SnpEmuAzure":
            paths["host_controller"] = "bin/host_wfr_test"
        else:
            paths["startup_report"] = "reports/startup.json"
        copy_file(executables["migtd"], stage / paths["ma_elf"], 0o755)
        if "host_controller" in paths:
            copy_file(executables["host_wfr_test"], stage / paths["host_controller"], 0o755)
        copy_file(args.kernel, stage / paths["kernel"], 0o644)
        copy_file(ROOT / "Cargo.lock", stage / paths["cargo_lock"], 0o644)
        for name in ("validate_bundle.py", "image_content.py", "requirements.txt"):
            copy_file(Path(__file__).with_name(name), stage / "contract" / name, 0o644)
        copy_file(schema_path(), stage / "contract" / SCHEMA_NAME, 0o644)
        (stage / paths["tree_log"]).write_text(tree)
        (stage / paths["tree_log"]).chmod(0o644)
        write_json(stage / paths["source_inventory"], source)
        index = fingerprints(fixture_needles())
        write_json(stage / paths["fixture_fingerprints"], index)
        image_report = inspect_elf(stage / paths["ma_elf"], args.composition == "SnpHardware", index)
        write_json(stage / paths["image_report"], image_report)
        make_initramfs(stage / paths["ma_elf"], stage / paths["initramfs"])
        native = native_inventory(messages)
        components = sbom_components(packages, native)
        write_json(stage / paths["dependencies"], {
            "rust": packages, "native": native, "scope": NATIVE_SCOPE,
            "sbom_components": components,
        })
        write_json(stage / paths["sbom"], {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": args.composition}},
            "components": components,
        })
        write_json(stage / paths["runtime_config"], {
            "process_mode": "pid1", "start_mode": "wfr",
            "common_v6_v2_activated": False,
            "production_runtime_available": False,
            "qualification": QUALIFICATION,
        })
        if args.composition == "SnpHardware":
            refusal = subprocess.run([str(stage / paths["ma_elf"])],
                                     capture_output=True, text=True, timeout=15)
            write_json(stage / paths["startup_report"], {
                "exit_code": refusal.returncode, "stdout": refusal.stdout, "stderr": refusal.stderr,
            })
        providers = provider_contract(args.composition)
        manifest = {
            "schema_version": 1, "composition": args.composition,
            "classification": "production-shaped" if args.composition == "SnpHardware"
                              else "emulator-fixture",
            "qualification": QUALIFICATION,
            "repositories": {
                "migtd": {
                    "repository": "https://github.com/mvasantarao/MigTD",
                    "commit": source["head"], "dirty": bool(source["worktree"]),
                    "source_inventory": paths["source_inventory"],
                },
                "aas": aas,
            },
            "build": {
                "cargo_features": [args.composition], "default_features": False,
                "cargo_lock_sha256": file_hash(ROOT / "Cargo.lock"),
                "rustc": run(["rustc", "-vV"], env=env),
                "cargo": run(["cargo", "--version"], env=env).strip(),
                "target": TARGET, "profile": "release", "linking_mode": "static",
                "linker": {
                    "path": linker, "sha256": file_hash(Path(linker)),
                    "version": run([linker, "--version"], env=env),
                },
                "environment": {k: env[k] for k in ENVIRONMENT_KEYS if k in env},
                "commands": [tree_command, metadata_command, build_command],
                "dependency_inventory": paths["dependencies"], "native_inventory_scope": NATIVE_SCOPE,
            },
            "providers": providers,
            "legacy_compatibility": legacy_contract(args.composition),
            "unavailable_providers": sorted(
                k for k, v in providers.items() if v["classification"] == "unavailable"),
            "artifacts": {k: record(stage / path, stage) for k, path in paths.items()},
            "external_inputs": external,
            "root_filesystem": {
                "identity": "MigTD minimal PID1 rootfs v1", "format": "newc+gzip",
                "entries": parse_initramfs(stage / paths["initramfs"]),
            },
            "expected_markers": marker_contract(args.composition),
            "creation": {
                "timestamp": datetime.now(timezone.utc).isoformat(), "command": creation_command,
            },
        }
        write_json(stage / "manifest.json", manifest)
        sums = "".join(f"{file_hash(stage / p)}  {p}\n"
                       for p in sorted([*paths.values(), "manifest.json"]))
        (stage / "SHA256SUMS").write_text(sums)
        (stage / "SHA256SUMS").chmod(0o644)
        validate_bundle(stage)
        verify_source_unchanged(source)
        for path, expected_hash in source["aas"]["files"].items():
            require(file_hash(sdk_root / path) == expected_hash,
                    f"AAS source changed during build: {path}")
        require(not os.path.lexists(output), f"output appeared during build: {output}")
        publish_directory(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print(json.dumps({"result": "published", "bundle": str(output),
                      "composition": args.composition, "qualification": QUALIFICATION}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("composition", choices=("SnpEmuAzure", "SnpHardware"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--linker", default="x86_64-linux-musl-gcc")
    parser.add_argument("--cc", default="x86_64-linux-musl-gcc")
    for name in ("kernel", "qemu", "ovmf"):
        parser.add_argument(f"--{name}", type=Path, required=True)
        parser.add_argument(f"--{name}-identity", required=True)
        parser.add_argument(f"--{name}-sha256", required=True)
    args = parser.parse_args()
    try:
        lock_path = ROOT / "target/snp-bundle-build" / f"{args.composition}.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            publish(args, [sys.executable, *sys.argv])
    except (OSError, ValueError, RuntimeError, ValidationError, subprocess.SubprocessError) as error:
        print(f"bundle build FAILED (no output published): {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
