#!/usr/bin/env python3
"""Validate the v1 contract without a MigTD source checkout or executing its MA."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from image_content import asset_hits, dependency_inventory, sbom_components, scan_production


SCHEMA_NAME = "snp-ma-bundle-manifest-v1.json"
QUALIFICATION = "Build-validated/migration-unqualified"
NATIVE_SCOPE = (
    "Cargo-declared native link libraries and discovered archives; implicit "
    "CRT/runtime is toolchain-scoped, not a hermetic native closure"
)
MAX_INITRAMFS = 64 * 1024 * 1024
FIXTURE_INDEX_SHA256 = "4f09a01b84c57f0a9135a852d3a4bfb5f752bc016cc658fd62cbf53fd4a28317"
ARTIFACTS = {
    "ma_elf": "bin/migtd",
    "initramfs": "boot/initramfs.cpio.gz",
    "kernel": "boot/bzImage",
    "sbom": "provenance/sbom.cdx.json",
    "dependencies": "provenance/dependencies.json",
    "source_inventory": "provenance/source.json",
    "cargo_lock": "provenance/Cargo.lock",
    "image_report": "reports/image.json",
    "fixture_fingerprints": "contract/fixture-fingerprints.json",
    "validator": "contract/validate_bundle.py",
    "image_rules": "contract/image_content.py",
    "schema": f"contract/{SCHEMA_NAME}",
    "requirements": "contract/requirements.txt",
    "runtime_config": "config/runtime.json",
    "build_log": "logs/cargo-build.log",
    "tree_log": "logs/cargo-tree.log",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"non-JSON constant: {value}")


def read_json(path):
    value = json.loads(path.read_text(), object_pairs_hook=no_duplicates,
                       parse_constant=reject_constant)
    require(isinstance(value, dict), f"JSON object required: {path.name}")
    return value


def require(condition, message):
    if not condition:
        raise ValueError(message)


def schema_path():
    adjacent = Path(__file__).with_name(SCHEMA_NAME)
    if adjacent.is_file():
        return adjacent
    return Path(__file__).resolve().parents[2] / "schemas" / SCHEMA_NAME


def validate_manifest(manifest):
    schema = read_json(schema_path())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)
    composition = manifest["composition"]
    require(manifest["providers"] == provider_contract(composition),
            "provider identities/classifications contradict the selected composition")
    require(manifest["legacy_compatibility"] == legacy_contract(composition),
            "legacy compatibility contradicts the selected composition")
    require(manifest["expected_markers"] == marker_contract(composition),
            "unexpected evidence/operation markers for this contract")
    unavailable = sorted(k for k, v in manifest["providers"].items()
                         if v["classification"] == "unavailable")
    require(manifest["unavailable_providers"] == unavailable,
            "unavailable providers must be explicit, complete and ordered")
    paths = dict(ARTIFACTS)
    if composition == "SnpEmuAzure":
        paths["host_controller"] = "bin/host_wfr_test"
    else:
        paths["startup_report"] = "reports/startup.json"
    require(set(manifest["artifacts"]) == set(paths), "unexpected or missing bundle artifacts")
    require(all(manifest["artifacts"][k]["path"] == v for k, v in paths.items()),
            "noncanonical artifact path")


def provider_contract(composition):
    identities = {
        "verifier": "pal::snp_report::UnavailableSnpReportVerifier",
        "evidence": "pal::composition::snp::UnavailableEvidence",
        "collateral": "pal::composition::snp::UnavailableEvidence",
        "transport": "pal::snp::peer_channel::UnavailablePeerTransportFactoryV1",
        "peer_clock": "pal::composition::snp::UnavailableClock",
        "host_control": "pal::snp::host_control::UnavailableSnpHostControlTransportV1",
        "host_context": "pal::snp::host_control::UnavailableHostControlContextAuthorityV1",
        "installation": "pal::snp::migration_install::UnavailableMigrationKeyInstallerV1",
        "rebind": "pal::snp::binding_manager::UnavailableMaBindingManagerV1",
        "persistence": "pal::tenant_replay::UnavailableTenantReplayStoreV1",
        "firmware_state": "pal::tenant_replay::UnavailableTenantFirmwareStateV1",
        "handoff_authority": "pal::snp::local_handoff::UnavailableLocalHandoffServicesV1",
        "handoff_secrets": "pal::snp::local_handoff::UnavailableLocalHandoffServicesV1",
        "platform_keys": "pal::traits::UnavailablePlatformKeyProvider",
    }
    providers = {k: {"identity": v, "classification": "unavailable"}
                 for k, v in identities.items()}
    providers["randomness"] = {
        "identity": "pal::random::SystemRandomSource", "classification": "production",
    }
    if composition == "SnpEmuAzure":
        for key in ("evidence", "collateral"):
            providers[key] = {
                "identity": "snp_emu::provider_fixture::SnpFixtureProvider",
                "classification": "fixture",
            }
    elif composition == "SnpHardware":
        providers["evidence"] = {
            "identity": "pal::snp::hardware::SnpHardwareProvider",
            "classification": "production",
        }
    else:
        raise ValueError(f"unsupported composition: {composition}")
    return providers


def legacy_contract(composition):
    if composition == "SnpHardware":
        return None
    return {
        "verifier": {
            "identity": "pal::snp::qvl::verify::SnpQvl/AzureNative/captured-v5",
            "classification": "fixture",
        },
        "transport": {"identity": "TCP/SPDM legacy compatibility", "classification": "emulated"},
        "host_control": {
            "identity": "EmulatedHostControlTransport/TcpTransport", "classification": "emulated",
        },
        "installation": {
            "identity": "pal::snp::fixture::platform_services::MockMigrationKeyInstaller",
            "classification": "emulated",
        },
        "limitation": (
            "Captured v5 signature/chain and key-only mock installation; not common V6 "
            "authentication, live TH1 binding or V2 migration"
        ),
    }


def marker_contract(composition):
    if composition == "SnpHardware":
        return {
            "startup_refusal": ["HostControl(ProviderUnavailable)", "no emulator fallback"],
            "forbidden": ["operation=MSG_KEY_REQ", "operation=MSG_VERIFY_REPORT"],
        }
    return {
        "boot": ["[MA] MA_BOOT_STAGE_1:", "[MA] MA_BOOT_STAGE_2:"],
        "destination_listening": ["[MA] PEER_CHANNEL_LISTENING:"],
        "source_peer_ready": ["[MA] PEER_CHANNEL_READY: role=source"],
        "destination_peer_ready": ["[MA] PEER_CHANNEL_READY: role=destination"],
        "destination_wfr_ready": ["[MA] TcpTransport: bound, waiting for connection..."],
        "source_wfr_ready": ["[MA] TcpTransport: connected to"],
        "destination_start": ["[MA] START_MIGRATION_WORKFLOW_BEGIN: role=destination"],
        "evidence": ["operation=AZURE_VERIFY_ATTESTATION", "[MA] FIXTURE_LIMITATION:"],
        "operations": ["operation=MSG_SET_MIGRATION_INFO"],
        "resident_completion": [
            "[MA] PID1_SERVICE_COMPLETE: migration finished; remaining resident",
        ],
        "forbidden": ["operation=MSG_KEY_REQ", "operation=MSG_VERIFY_REPORT"],
    }


def safe_file(root, name):
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and ".." not in relative.parts
            and name == relative.as_posix() and name not in ("", "."),
            f"unsafe bundle path: {name}")
    path = root
    for part in relative.parts:
        path /= part
        require(not path.is_symlink(), f"symlink in bundle path: {name}")
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode),
            f"missing/nonregular artifact: {name}")
    return path


def parse_initramfs(path):
    with gzip.open(path, "rb") as stream:
        data = stream.read(MAX_INITRAMFS + 1)
    require(len(data) <= MAX_INITRAMFS, "initramfs exceeds the v1 size limit")
    offset = 0
    entries = {}
    while True:
        header = data[offset:offset + 110]
        require(len(header) == 110 and header[:6] == b"070701"
                and re.fullmatch(b"[0-9a-fA-F]{104}", header[6:]) is not None,
                "invalid newc header")
        fields = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        _, mode, uid, gid, nlink, mtime, size, major, minor, rmajor, rminor, namesize, check = fields
        require(uid == gid == mtime == major == minor == rmajor == rminor == check == 0
                and nlink == 1, "noncanonical newc metadata or hard link")
        offset += 110
        require(1 <= namesize <= 256, "invalid newc name size")
        name_data = data[offset:offset + namesize]
        require(len(name_data) == namesize and name_data[-1:] == b"\0"
                and b"\0" not in name_data[:-1], "invalid newc name")
        name = name_data[:-1].decode("ascii")
        offset = (offset + namesize + 3) & ~3
        require(offset + size <= len(data), "truncated newc payload")
        payload = data[offset:offset + size]
        offset = (offset + size + 3) & ~3
        if name == "TRAILER!!!":
            require(size == mode == 0 and not any(data[offset:]), "invalid newc trailer")
            break
        require(name in {"init", "proc", "sys", "dev"} and name not in entries,
                f"unexpected/duplicate initramfs entry: {name}")
        expected_mode = (stat.S_IFREG if name == "init" else stat.S_IFDIR) | 0o755
        require(mode == expected_mode and (name == "init" or size == 0),
                f"invalid initramfs entry mode/size: {name}")
        entries[name] = {
            "path": name, "mode": mode, "size": size, "sha256": sha256(payload),
        }
    require(set(entries) == {"init", "proc", "sys", "dev"}, "incomplete PID1 filesystem")
    return [entries[k] for k in sorted(entries)]


def command_output(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=True)
    return result.stdout


def static_elf(path):
    data = path.read_bytes()
    require(data[:6] == b"\x7fELF\x02\x01" and len(data) >= 64
            and data[18:20] == b"\x3e\x00", f"not an x86-64 ELF: {path.name}")
    program = command_output(["readelf", "-lW", str(path)])
    dynamic = command_output(["readelf", "-dW", str(path)])
    require("INTERP" not in program and "(NEEDED)" not in dynamic,
            "v1 minimal rootfs requires a statically linked ELF")
    symbols = command_output(["nm", "-C", str(path)])
    require(re.search(r"\b[Tt]\s+", symbols) is not None,
            "image inspection requires unstripped text symbols")
    return data, symbols


def inspect_elf(path, production, index):
    data, symbols = static_elf(path)
    hits = asset_hits(data, index)
    if production:
        scan_production(data, symbols, {})
        require(not hits, f"production contains captured fixture/synthetic root: {hits}")
    else:
        require(len([n for n in hits if "fixture_data/" in n]) == 3,
                "emulator captured-asset positive control failed")
    return {"linking_mode": "static", "fixture_asset_hits": hits,
            "forbidden_symbols": [], "elf_sha256": sha256(data)}


def validate_external(entry, override=None):
    path = Path(override) if override is not None else Path(entry["path"])
    require(path.is_file(), f"external input missing: {path}")
    require(path.stat().st_size == entry["size"] and file_hash(path) == entry["sha256"],
            f"external input hash/size mismatch: {path}")
    return str(path.resolve())


def validate_bundle(directory, *, qemu=None, ovmf=None, composition=None):
    root = Path(directory)
    require(root.is_dir() and not root.is_symlink(), "bundle must be a nonsymlink directory")
    root = root.resolve()
    manifest_path = safe_file(root, "manifest.json")
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    require(composition is None or manifest["composition"] == composition,
            "bundle composition is unsupported by this consumer")
    expected = {"manifest.json", "SHA256SUMS"}
    for record in manifest["artifacts"].values():
        path = safe_file(root, record["path"])
        require(path.stat().st_size == record["size"]
                and file_hash(path) == record["sha256"]
                and stat.S_IMODE(path.stat().st_mode) == record["mode"],
                f"artifact hash/size/mode mismatch: {record['path']}")
        expected.add(record["path"])
    actual = set()
    for path in root.rglob("*"):
        require(not path.is_symlink(), f"symlink in bundle: {path.relative_to(root)}")
        if not path.is_dir():
            require(path.is_file(), f"nonregular bundle member: {path.relative_to(root)}")
            actual.add(path.relative_to(root).as_posix())
    require(actual == expected, f"undeclared/missing bundle members: {actual ^ expected}")
    sums = "".join(f"{file_hash(safe_file(root, p))}  {p}\n"
                   for p in sorted(expected - {"SHA256SUMS"}))
    require(safe_file(root, "SHA256SUMS").read_text() == sums, "checksum record mismatch")
    require(read_json(root / ARTIFACTS["schema"]) == read_json(schema_path()),
            "embedded schema differs from the trusted v1 schema")
    ma = manifest["artifacts"]["ma_elf"]
    entries = parse_initramfs(root / ARTIFACTS["initramfs"])
    require(entries == manifest["root_filesystem"]["entries"], "rootfs inventory mismatch")
    init = next(e for e in entries if e["path"] == "init")
    require(init["sha256"] == ma["sha256"] and init["size"] == ma["size"],
            "initramfs /init differs from MA ELF")
    require(manifest["external_inputs"]["kernel"]["sha256"]
            == manifest["artifacts"]["kernel"]["sha256"],
            "bundled kernel differs from declared external input")
    validate_external(manifest["external_inputs"]["qemu"], qemu)
    validate_external(manifest["external_inputs"]["ovmf"], ovmf)
    source = read_json(root / ARTIFACTS["source_inventory"])
    require(source["head"] == manifest["repositories"]["migtd"]["commit"]
            and bool(source["worktree"]) == manifest["repositories"]["migtd"]["dirty"],
            "source provenance does not match manifest")
    lock_hash = file_hash(root / ARTIFACTS["cargo_lock"])
    require(lock_hash == manifest["build"]["cargo_lock_sha256"]
            == source["files"]["Cargo.lock"], "Cargo.lock provenance mismatch")
    production = manifest["composition"] == "SnpHardware"
    dependencies = read_json(root / ARTIFACTS["dependencies"])
    packages = dependency_inventory((root / ARTIFACTS["tree_log"]).read_text(), production)
    require(packages == dependencies["rust"], "Rust dependency inventory mismatch")
    require(dependencies["native"] and dependencies["scope"] == NATIVE_SCOPE,
            "missing or overstated native inventory")
    aas = manifest["repositories"]["aas"]
    require(source["aas"]["repository"] == aas["repository"]
            and source["aas"]["commit"] == aas["commit"] and source["aas"]["files"],
            "AAS source inventory differs from manifest")
    require(any(p["package"].startswith("azure-guest-attestation-sdk ")
                and aas["commit"] in p["package"] and aas["repository"] in p["package"]
                for p in packages), "AAS provenance differs from selected dependency")
    sbom = read_json(root / ARTIFACTS["sbom"])
    require(sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
            and sbom["metadata"]["component"]["name"] == manifest["composition"],
            "invalid SBOM identity")
    require(sbom["components"] == dependencies["sbom_components"]
            == sbom_components(packages, dependencies["native"]), "SBOM inventory mismatch")
    index = read_json(root / ARTIFACTS["fixture_fingerprints"])
    require(file_hash(root / ARTIFACTS["fixture_fingerprints"]) == FIXTURE_INDEX_SHA256,
            "fixture/synthetic-root fingerprint policy differs from the trusted v1 contract")
    require(len(index) == 5 and all(
        re.fullmatch("[0-9a-f]{64}", v["sha256"]) and len(bytes.fromhex(v["prefix"])) == 32
        and isinstance(v["size"], int) and v["size"] > 32 for v in index.values()),
        "incomplete captured-fixture/synthetic-root fingerprint index")
    report = inspect_elf(root / ARTIFACTS["ma_elf"], production, index)
    require(read_json(root / ARTIFACTS["image_report"]) == report, "image report mismatch")
    if production:
        startup = read_json(root / "reports/startup.json")
        require(startup["exit_code"] == 2 and all(
            m in startup["stdout"] + startup["stderr"]
            for m in manifest["expected_markers"]["startup_refusal"]),
            "production startup refusal record missing")
    else:
        controller = root / "bin/host_wfr_test"
        require(controller.stat().st_mode & 0o111, "controller is not executable")
        static_elf(controller)
    require(stat.S_IMODE((root / ARTIFACTS["ma_elf"]).stat().st_mode) == 0o755,
            "MA is not executable")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--qemu", type=Path)
    parser.add_argument("--ovmf", type=Path)
    parser.add_argument("--require-composition", choices=("SnpEmuAzure", "SnpHardware"))
    args = parser.parse_args()
    try:
        manifest = validate_bundle(args.bundle, qemu=args.qemu, ovmf=args.ovmf,
                                   composition=args.require_composition)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, ValidationError,
            subprocess.SubprocessError) as error:
        print(f"bundle validation FAILED: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"result": "valid", "composition": manifest["composition"],
                      "qualification": manifest["qualification"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
