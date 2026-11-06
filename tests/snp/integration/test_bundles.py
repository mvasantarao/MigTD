#!/usr/bin/env python3
"""Exercise real built bundles; no substitute attestation or successful fake MA."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/snp"))
sys.path.insert(0, str(ROOT / "sh_script/test"))
from build_bundle import make_initramfs
from snp_task4_inventory import fixture_needles
from validate_bundle import (
    ARTIFACTS, ValidationError, file_hash, parse_initramfs, read_json, validate_bundle,
)

BUNDLES = {}
CONSUMER = None


@contextmanager
def copied(composition):
    with tempfile.TemporaryDirectory(prefix="snp-bundle-vector-") as directory:
        root = Path(directory) / "bundle"
        shutil.copytree(BUNDLES[composition], root)
        yield root, read_json(root / "manifest.json")


def reseal(root, manifest):
    for record in manifest["artifacts"].values():
        path = root / record["path"]
        record.update(sha256=file_hash(path), size=path.stat().st_size,
                      mode=path.stat().st_mode & 0o777)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    names = [e["path"] for e in manifest["artifacts"].values()] + ["manifest.json"]
    (root / "SHA256SUMS").write_text("".join(
        f"{file_hash(root / p)}  {p}\n" for p in sorted(names)))


class BundleTests(unittest.TestCase):
    def test_both_real_compositions_validate_with_explicit_unavailable_verifier(self):
        for composition, bundle in BUNDLES.items():
            with self.subTest(composition=composition):
                manifest = validate_bundle(bundle)
                self.assertEqual(manifest["composition"], composition)
                self.assertEqual(manifest["qualification"], "Build-validated/migration-unqualified")
                self.assertIn("verifier", manifest["unavailable_providers"])
                self.assertEqual(manifest["build"]["cargo_features"], [composition])

    def test_packaged_validator_needs_no_source_checkout(self):
        for composition, bundle in BUNDLES.items():
            with self.subTest(composition=composition), tempfile.TemporaryDirectory() as directory:
                env = os.environ.copy()
                env.pop("PYTHONPATH", None)
                result = subprocess.run([
                    sys.executable, str(bundle / "contract/validate_bundle.py"),
                    "--bundle", str(bundle),
                ], cwd=directory, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_corruption_of_every_declared_artifact_fails(self):
        for composition, bundle in BUNDLES.items():
            keys = read_json(bundle / "manifest.json")["artifacts"]
            for key in keys:
                with self.subTest(composition=composition, artifact=key), copied(composition) as (root, m):
                    path = root / m["artifacts"][key]["path"]
                    with path.open("ab") as stream:
                        stream.write(b"\nCORRUPTED\n")
                    with self.assertRaisesRegex(ValueError, "artifact hash/size/mode"):
                        validate_bundle(root)

    def test_missing_artifact_symlink_and_undeclared_file_fail(self):
        for kind in ("missing", "symlink", "undeclared"):
            with self.subTest(kind=kind), copied("SnpEmuAzure") as (root, _):
                if kind in ("missing", "symlink"):
                    (root / "bin/migtd").unlink()
                if kind == "symlink":
                    (root / "bin/migtd").symlink_to(BUNDLES["SnpEmuAzure"] / "bin/migtd")
                if kind == "undeclared":
                    (root / "unapproved-fixture").write_bytes(b"not declared")
                with self.assertRaises(ValueError):
                    validate_bundle(root)

    def test_mode_corruption_fails(self):
        with copied("SnpEmuAzure") as (root, _):
            (root / "bin/migtd").chmod(0o644)
            with self.assertRaisesRegex(ValueError, "artifact hash/size/mode"):
                validate_bundle(root)

    def test_resealed_wrong_init_is_rejected(self):
        with copied("SnpEmuAzure") as (root, m), tempfile.TemporaryDirectory() as directory:
            different = Path(directory) / "different"
            different.write_bytes(b"wrong init; deliberately not an ELF")
            make_initramfs(different, root / ARTIFACTS["initramfs"])
            m["root_filesystem"]["entries"] = parse_initramfs(root / ARTIFACTS["initramfs"])
            reseal(root, m)
            with self.assertRaisesRegex(ValueError, "/init differs"):
                validate_bundle(root)

    def test_resealed_production_fixture_injection_is_rejected(self):
        for name, value in fixture_needles().items():
            with self.subTest(asset=name), copied("SnpHardware") as (root, m):
                with (root / "bin/migtd").open("ab") as stream:
                    stream.write(value)
                make_initramfs(root / "bin/migtd", root / ARTIFACTS["initramfs"])
                m["root_filesystem"]["entries"] = parse_initramfs(root / ARTIFACTS["initramfs"])
                reseal(root, m)
                with self.assertRaisesRegex(ValueError, "production contains captured"):
                    validate_bundle(root)

    def test_resealed_fixture_policy_replacement_is_rejected(self):
        with copied("SnpHardware") as (root, m):
            path = root / ARTIFACTS["fixture_fingerprints"]
            index = read_json(path)
            for value in index.values():
                value["sha256"] = "0" * 64
            path.write_text(json.dumps(index))
            reseal(root, m)
            with self.assertRaisesRegex(ValueError, "fingerprint policy"):
                validate_bundle(root)

    def test_resealed_production_dependency_leak_is_rejected(self):
        with copied("SnpHardware") as (root, m):
            with (root / ARTIFACTS["tree_log"]).open("a") as stream:
                stream.write("snp_emu v0.1.0|snp-fixture\n")
            reseal(root, m)
            with self.assertRaisesRegex(RuntimeError, "production emulator/TDX dependency"):
                validate_bundle(root)

    def test_resealed_sbom_and_lock_provenance_corruption_fail(self):
        for kind in ("sbom", "lock"):
            with self.subTest(kind=kind), copied("SnpHardware") as (root, m):
                if kind == "sbom":
                    path = root / ARTIFACTS["sbom"]
                    sbom = read_json(path)
                    sbom["components"] = []
                    path.write_text(json.dumps(sbom))
                else:
                    m["build"]["cargo_lock_sha256"] = "0" * 64
                reseal(root, m)
                with self.assertRaisesRegex(ValueError, "SBOM inventory|Cargo.lock provenance"):
                    validate_bundle(root)

    def test_resealed_matching_but_empty_sbom_inventories_fail(self):
        with copied("SnpHardware") as (root, m):
            for key, member in (("sbom", "components"), ("dependencies", "sbom_components")):
                path = root / ARTIFACTS[key]
                value = read_json(path)
                value[member] = []
                path.write_text(json.dumps(value))
            reseal(root, m)
            with self.assertRaisesRegex(ValueError, "SBOM inventory"):
                validate_bundle(root)

    def test_resealed_non_elf_controller_fails(self):
        with copied("SnpEmuAzure") as (root, m):
            (root / "bin/host_wfr_test").write_bytes(b"not an ELF controller")
            reseal(root, m)
            with self.assertRaisesRegex(ValueError, "x86-64 ELF"):
                validate_bundle(root)

    def test_resealed_production_success_fallback_is_rejected(self):
        with copied("SnpHardware") as (root, m):
            path = root / "reports/startup.json"
            report = read_json(path)
            report["exit_code"] = 0
            path.write_text(json.dumps(report))
            reseal(root, m)
            with self.assertRaisesRegex(ValueError, "production startup refusal"):
                validate_bundle(root)

    def test_wrong_external_tool_relocation_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-qemu"
            path.write_bytes(b"not the declared QEMU")
            with self.assertRaisesRegex(ValueError, "external input hash/size"):
                validate_bundle(BUNDLES["SnpEmuAzure"], qemu=path)

    def test_production_inspector_cannot_be_overridden_to_accept_emulator(self):
        result = subprocess.run([
            "bash", str(ROOT / "tools/snp/inspect-production-image.sh"),
            "--bundle", str(BUNDLES["SnpEmuAzure"]),
            "--require-composition", "SnpEmuAzure",
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("composition is unsupported", result.stderr)

    def test_builder_entry_points_cannot_override_their_compositions(self):
        manifest = read_json(BUNDLES["SnpEmuAzure"] / "manifest.json")
        for script, opposite in (
            ("build-emulator-bundle.sh", "SnpHardware"),
            ("build-production-bundle.sh", "SnpEmuAzure"),
        ):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "must-not-exist"
                command = ["bash", str(ROOT / "tools/snp" / script), "--output", str(output)]
                for name, entry in manifest["external_inputs"].items():
                    command += [f"--{name}", entry["path"], f"--{name}-identity", entry["identity"],
                                f"--{name}-sha256", entry["sha256"]]
                command += ["--composition", opposite]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("unrecognized arguments", result.stderr)
                self.assertFalse(output.exists())

    def test_consumers_accept_both_schemas_without_vm_launch(self):
        for composition, bundle in BUNDLES.items():
            with self.subTest(composition=composition):
                result = subprocess.run([
                    sys.executable, str(CONSUMER / "consume_bundle.py"),
                    "validate", "--bundle", str(bundle),
                ], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_consumer_records_corruption_failure_before_launch(self):
        with copied("SnpEmuAzure") as (root, m), tempfile.TemporaryDirectory() as directory:
            m["schema_version"] = 999
            (root / "manifest.json").write_text(json.dumps(m))
            logs = Path(directory)
            result = subprocess.run([
                sys.executable, str(CONSUMER / "consume_bundle.py"),
                "run", "--bundle", str(root), "--log-root", str(logs),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            reports = list(logs.glob("*/result.json"))
            self.assertEqual(len(reports), 1)
            report = read_json(reports[0])
            self.assertEqual(report["outcome"], "bundle-validation-failed")
            self.assertFalse(report["validated"])
            self.assertEqual(report["processes"], [])

    def test_consumer_records_malformed_nested_record_before_launch(self):
        with copied("SnpEmuAzure") as (root, m), tempfile.TemporaryDirectory() as directory:
            path = root / ARTIFACTS["sbom"]
            value = read_json(path)
            value["metadata"] = None
            path.write_text(json.dumps(value))
            reseal(root, m)
            result = subprocess.run([
                sys.executable, str(CONSUMER / "consume_bundle.py"),
                "run", "--bundle", str(root), "--log-root", directory,
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = read_json(next(Path(directory).glob("*/result.json")))
            self.assertEqual(report["outcome"], "bundle-validation-failed")
            self.assertTrue(report["error"])
            self.assertEqual(report["processes"], [])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", required=True, type=Path)
    parser.add_argument("--production", required=True, type=Path)
    parser.add_argument("--consumer", required=True, type=Path)
    args, remainder = parser.parse_known_args()
    BUNDLES = {"SnpEmuAzure": args.emulator.resolve(), "SnpHardware": args.production.resolve()}
    CONSUMER = args.consumer.resolve()
    unittest.main(argv=[sys.argv[0], *remainder])
