"""Shared dependency and ELF isolation rules, including Task 4 prior art."""

import hashlib


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


def fingerprints(needles):
    return {name: {
        "size": len(value), "prefix": value[:32].hex(),
        "sha256": hashlib.sha256(value).hexdigest(),
    } for name, value in sorted(needles.items())}


def asset_hits(binary, index):
    hits = []
    for name, entry in index.items():
        prefix = bytes.fromhex(entry["prefix"])
        offset = binary.find(prefix)
        while offset >= 0:
            candidate = binary[offset:offset + entry["size"]]
            if hashlib.sha256(candidate).hexdigest() == entry["sha256"]:
                hits.append(name)
                break
            offset = binary.find(prefix, offset + 1)
    return hits


def sbom_components(packages, native):
    components = [{
        "type": "library", "name": item["package"], "bom-ref": f"rust:{index}",
        "properties": [{"name": "cargo:features", "value": ",".join(item["features"])}],
    } for index, item in enumerate(packages)]
    for index, item in enumerate(native):
        component = {
            "type": "library", "name": item["library"], "bom-ref": f"native:{index}",
            "properties": [{"name": "cargo:package-id", "value": item["package_id"]}],
        }
        if item["archives"]:
            component["hashes"] = [{"alg": "SHA-256", "content": archive["sha256"]}
                                   for archive in item["archives"]]
        components.append(component)
    return components
