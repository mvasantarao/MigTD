"""Contract vectors only: these metadata examples are not built/attested bundles."""

import copy
import gzip
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/snp"))
from build_bundle import make_initramfs, newc_entry, publish_directory
from validate_bundle import (
    ARTIFACTS, NATIVE_SCOPE, QUALIFICATION, ValidationError, legacy_contract,
    marker_contract, parse_initramfs, provider_contract, read_json, safe_file,
    sha256, validate_manifest,
)


def vector(composition):
    paths = dict(ARTIFACTS)
    if composition == "SnpEmuAzure":
        paths["host_controller"] = "bin/host_wfr_test"
    else:
        paths["startup_report"] = "reports/startup.json"
    providers = provider_contract(composition)
    return {
        "schema_version": 1, "composition": composition,
        "classification": "production-shaped" if composition == "SnpHardware" else "emulator-fixture",
        "qualification": QUALIFICATION,
        "repositories": {
            "migtd": {"repository": "contract-vector-not-built", "commit": "1" * 40,
                      "dirty": False, "source_inventory": ARTIFACTS["source_inventory"]},
            "aas": {"repository": "https://example.invalid/aas", "commit": "2" * 40},
        },
        "build": {
            "cargo_features": [composition], "default_features": False,
            "cargo_lock_sha256": "3" * 64, "rustc": "contract vector", "cargo": "contract vector",
            "target": "x86_64-unknown-linux-musl", "profile": "release", "linking_mode": "static",
            "linker": {"path": "/declared/linker", "sha256": "4" * 64, "version": "contract vector"},
            "environment": {"CC": "declared"}, "commands": [["not-a-build"]],
            "dependency_inventory": ARTIFACTS["dependencies"], "native_inventory_scope": NATIVE_SCOPE,
        },
        "providers": providers, "legacy_compatibility": legacy_contract(composition),
        "unavailable_providers": sorted(k for k, v in providers.items()
                                        if v["classification"] == "unavailable"),
        "artifacts": {k: {"path": p, "sha256": "5" * 64, "size": 1, "mode": 420}
                      for k, p in paths.items()},
        "external_inputs": {
            k: {"path": f"/declared/{k}", "identity": "contract vector", "sha256": "6" * 64,
                "size": 1, "qualification": "Identity/hash recorded; not requalified by P2.2"}
            for k in ("kernel", "qemu", "ovmf")
        },
        "root_filesystem": {
            "identity": "MigTD minimal PID1 rootfs v1", "format": "newc+gzip",
            "entries": [{"path": p, "mode": 0, "sha256": "7" * 64, "size": 0}
                        for p in ("dev", "init", "proc", "sys")],
        },
        "expected_markers": marker_contract(composition),
        "creation": {"timestamp": "2026-11-06T00:49:32Z", "command": ["contract-vector-not-built"]},
    }


class ContractTests(unittest.TestCase):
    def test_both_compositions_have_positive_schema_vectors(self):
        for composition in ("SnpEmuAzure", "SnpHardware"):
            with self.subTest(composition=composition):
                validate_manifest(vector(composition))

    def test_required_members_unknown_fields_and_versions_fail(self):
        original = vector("SnpEmuAzure")
        for key in original:
            with self.subTest(missing=key):
                invalid = copy.deepcopy(original)
                del invalid[key]
                with self.assertRaises((ValueError, ValidationError)):
                    validate_manifest(invalid)
        for key, value in (("schema_version", 2), ("schema_version", True),
                           ("unexpected", "field"), ("composition", "SnpEmu"),
                           ("qualification", "Migration-emulator-verified")):
            with self.subTest(member=key, value=value):
                invalid = copy.deepcopy(original)
                invalid[key] = value
                with self.assertRaises((ValueError, ValidationError)):
                    validate_manifest(invalid)

    def test_every_provider_identity_and_classification_is_closed(self):
        for composition in ("SnpEmuAzure", "SnpHardware"):
            for provider in provider_contract(composition):
                for field in ("identity", "classification"):
                    with self.subTest(composition=composition, provider=provider, field=field):
                        invalid = vector(composition)
                        invalid["providers"][provider][field] = "production" if field == "classification" else "other"
                        if invalid["providers"][provider] == provider_contract(composition)[provider]:
                            invalid["providers"][provider][field] = "fixture"
                        with self.assertRaises(ValueError):
                            validate_manifest(invalid)

    def test_cross_composition_features_markers_and_compatibility_fail(self):
        mutations = (
            lambda m: m.update(classification="production-shaped"),
            lambda m: m["build"].update(cargo_features=["SnpHardware"]),
            lambda m: m["build"].update(default_features=True),
            lambda m: m["build"].update(cargo_features=["SnpEmuAzure", "test_mock_report"]),
            lambda m: m["build"].update(linking_mode="dynamic"),
            lambda m: m.update(legacy_compatibility=None),
            lambda m: m.update(unavailable_providers=[]),
            lambda m: m["expected_markers"].update(evidence=["operation=TAV_VERIFY_ATTESTATION"]),
            lambda m: m["artifacts"]["ma_elf"].update(path="../migtd"),
            lambda m: m["artifacts"].pop("sbom"),
        )
        for number, mutate in enumerate(mutations):
            with self.subTest(number=number):
                invalid = vector("SnpEmuAzure")
                mutate(invalid)
                with self.assertRaises((ValueError, ValidationError)):
                    validate_manifest(invalid)

    def test_json_duplicate_members_and_nonfinite_values_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            for value in ('{"schema_version":1,"schema_version":2}', '{"value":NaN}'):
                path.write_text(value)
                with self.assertRaises(ValueError):
                    read_json(path)

    def test_safe_paths_reject_traversal_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file").write_bytes(b"data")
            (root / "link").symlink_to(root / "file")
            self.assertEqual(safe_file(root, "file"), root / "file")
            for path in ("../file", "/file", "./file", "link", "missing", "a//file"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    safe_file(root, path)

    def test_initramfs_is_deterministic_and_contains_exact_init(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "input"
            binary.write_bytes(b"archive parser test; not an ELF or attestation")
            first, second = root / "first.gz", root / "second.gz"
            make_initramfs(binary, first)
            make_initramfs(binary, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            entries = parse_initramfs(first)
            self.assertEqual([e["path"] for e in entries], ["dev", "init", "proc", "sys"])
            init = next(e for e in entries if e["path"] == "init")
            self.assertEqual(init["sha256"], sha256(binary.read_bytes()))
            self.assertEqual(init["mode"], stat.S_IFREG | 0o755)

    def test_initramfs_rejects_malformed_duplicate_and_unapproved_entries(self):
        valid = newc_entry("init", b"test", stat.S_IFREG | 0o755, 1)
        for name, data in (
            ("truncated", valid[:-1]),
            ("duplicate", valid + valid),
            ("traversal", newc_entry("../bad", b"", stat.S_IFREG | 0o755, 1)),
            ("symlink", newc_entry("init", b"bad", stat.S_IFLNK | 0o777, 1)),
            ("missing-init", newc_entry("TRAILER!!!", b"", 0, 1)),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "test.gz"
                path.write_bytes(gzip.compress(data, mtime=0))
                with self.assertRaises(ValueError):
                    parse_initramfs(path)

    def test_publication_is_atomic_and_never_replaces_even_an_empty_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage, output = root / "stage", root / "published"
            stage.mkdir()
            (stage / "manifest.json").write_text("complete")
            output.mkdir()
            with self.assertRaises(FileExistsError):
                publish_directory(stage, output)
            self.assertEqual(list(output.iterdir()), [])
            self.assertTrue(stage.is_dir())
            output.rmdir()
            publish_directory(stage, output)
            self.assertFalse(stage.exists())
            self.assertEqual((output / "manifest.json").read_text(), "complete")


if __name__ == "__main__":
    unittest.main()
