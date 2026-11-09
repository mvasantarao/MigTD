#!/usr/bin/env python3
# Copyright (c) 2026 Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Fixture reproducibility and independent negative controls; no live provider."""

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "sh_script/test"))
import snp_v6_fixtures as generator
import snp_v6_verify as oracle


class V6FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = generator.DESTINATION
        cls.catalogue = oracle.read_json(cls.directory, "case-catalogue.json")
        cls.cases = {case["name"]: case for case in cls.catalogue["cases"]}
        _, leaf = oracle.chain(cls.directory, "certificates/vcek.der", 100)
        cls.key = leaf.public_key()
        cls.signing_key = ec.derive_private_key(3, ec.SECP384R1())
        cls.source = cls.cases["source_session_v2"]
        cls.report = oracle.read(cls.directory, cls.source["report"])
        cls.supplement = oracle.read(cls.directory, cls.source["supplement"])
        cls.signature = oracle.read(cls.directory, cls.source["signature"])
        cls.expected_data = cls.report[0x50:0x90]

    def rejects(self, error, action):
        with self.assertRaises(oracle.FixtureError) as raised:
            action()
        self.assertEqual(raised.exception.code, error)

    def test_exact_package_and_coverage_counts(self):
        counts = oracle.verify_package(self.directory)
        self.assertEqual(counts["reports"], 19)
        self.assertEqual(counts["certificates"], 6)
        self.assertEqual(counts["positive_cases"], 7)
        self.assertEqual(counts["negative_cases"], 31)
        self.assertEqual(counts["cases"], 38)

    def test_two_independent_generations_match_all_saved_bytes(self):
        first, second = generator.build(), generator.build()
        self.assertEqual(first, second)
        saved = {p.relative_to(self.directory).as_posix(): p.read_bytes()
                 for p in self.directory.rglob("*") if p.is_file()}
        self.assertEqual(first, saved)

    def test_all_case_errors_are_specific_not_just_any_failure(self):
        for name, case in self.cases.items():
            with self.subTest(case=name):
                if case["expected"] == "OK":
                    oracle.verify_case(self.directory, case)
                else:
                    self.rejects(case["expected"], lambda: oracle.verify_case(self.directory, case))

    def test_report_signature_body_padding_and_lengths(self):
        for offset in range(672, 1184):
            report = bytearray(self.report)
            report[offset] ^= 1
            expected = ("ReportSignaturePadding" if 720 <= offset < 744 or offset >= 792
                        else "InvalidReportSignature")
            with self.subTest(offset=offset):
                self.rejects(expected, lambda: oracle.verify_report(
                    report, self.key, "ma", self.expected_data))
        for size in (0, 1183, 1185):
            self.rejects("ReportLength", lambda: oracle.verify_report(
                self.report[:size].ljust(size, b"\0"), self.key, "ma", self.expected_data))

    def test_full64_guest_data_and_host_zero_semantics(self):
        arbitrary = bytes(range(64))
        report = generator.make_report(0, arbitrary, self.signing_key)
        oracle.verify_report(report, self.key, "ma", arbitrary)
        tenant = oracle.read(self.directory, self.cases["tenant_uninitialized"]["report"])
        for index in range(64):
            changed = bytearray(arbitrary)
            changed[index] ^= 1
            self.rejects("ReportData", lambda: oracle.verify_report(report, self.key, "ma", changed))
            changed = bytearray(tenant)
            changed[0x50 + index] = 1
            changed = generator.reference.sign_report(changed, self.signing_key)
            self.rejects("ReportData", lambda: oracle.verify_report(
                changed, self.key, "tenant", bytes(64)))
        for value in (0, 1, 2, 3):
            changed = bytearray(tenant)
            struct.pack_into("<I", changed, 0x30, value)
            changed = generator.reference.sign_report(changed, self.signing_key)
            self.rejects("ReportVmpl", lambda: oracle.verify_report(
                changed, self.key, "tenant", bytes(64)))
        for size in (0, 63, 65):
            with self.assertRaisesRegex(ValueError, "exactly 64"):
                generator.make_report(0, bytes(size), self.signing_key)

    def test_all_reserved_report_tcb_etcb_and_supplement_bytes(self):
        for start, end in ((0x4C, 0x50), (0x18B, 0x1A0), (0x1EB, 0x1EC),
                           (0x1EF, 0x1F0), (0x208, 0x220), (0x280, 0x2A0)):
            for offset in range(start, end):
                changed = bytearray(self.report)
                changed[offset] = 1
                changed = generator.reference.sign_report(changed, self.signing_key)
                self.rejects("ReservedReport", lambda: oracle.verify_report(
                    changed, self.key, "ma", self.expected_data))
        for base, size, error in ((0x38, 8, "ReservedTcb"), (0x180, 8, "ReservedTcb"),
                                  (0x1E0, 8, "ReservedTcb"), (0x1F0, 8, "ReservedTcb"),
                                  (0x220, 32, "ReservedEtcb"), (0x240, 32, "ReservedEtcb"),
                                  (0x260, 32, "ReservedEtcb")):
            for offset in range(base + (3 if size == 8 else 14), base + size):
                changed = bytearray(self.report)
                changed[offset] = 1
                changed = generator.reference.sign_report(changed, self.signing_key)
                self.rejects(error, lambda: oracle.verify_report(
                    changed, self.key, "ma", self.expected_data))
        for offset in range(149, 156):
            value = bytearray(self.supplement)
            value[offset] = 1
            signature = generator.reference.fixed_signature(
                self.signing_key, b"SNP-EMU-SUPPLEMENT-v1" + value)
            self.rejects("ReservedSupplement", lambda: oracle.verify_supplement(
                self.report, value, signature, self.key))

    def test_supplement_all_digest_etcb_and_signature_bytes(self):
        for offset in range(4, 148):
            value = bytearray(self.supplement)
            value[offset] ^= 1
            signature = generator.reference.fixed_signature(
                self.signing_key, b"SNP-EMU-SUPPLEMENT-v1" + value)
            expected = "ReportDigestMismatch" if offset < 52 else "SupplementEtcbMismatch"
            self.rejects(expected, lambda: oracle.verify_supplement(
                self.report, value, signature, self.key))
        for offset in range(96):
            signature = bytearray(self.signature)
            signature[offset] ^= 1
            self.rejects("InvalidSupplementSignature", lambda: oracle.verify_supplement(
                self.report, self.supplement, signature, self.key))
        for flag in range(2, 256):
            value = bytearray(self.supplement)
            value[148] = flag
            signature = generator.reference.fixed_signature(
                self.signing_key, b"SNP-EMU-SUPPLEMENT-v1" + value)
            self.rejects("InvalidHistoryFlag", lambda: oracle.verify_supplement(
                self.report, value, signature, self.key))

    def test_each_identity_field_and_context_is_independently_reconstructed(self):
        for name in ("source_session_v2", "destination_session_v2",
                     "source_authorization_v2", "destination_authorization_v2"):
            case = self.cases[name]
            context = oracle.expected_context(self.directory, case["purpose"], case["role"])
            self.assertEqual(len(context), 220)
            self.assertEqual(context, oracle.read(self.directory, f"bindings/{name}.bin"))
        for field in ("measurement", "guest_svn", "family", "image", "id_key",
                      "author_key", "host_data", "guest_policy"):
            case = self.cases[f"changed_{field}"]
            report = oracle.read(self.directory, case["report"])
            oracle.verify_report(report, self.key, "ma", self.expected_data)
            oracle.verify_supplement(report, oracle.read(self.directory, case["supplement"]),
                                     oracle.read(self.directory, case["signature"]), self.key)
            self.assertNotEqual(oracle.identity_input(report),
                                oracle.read(self.directory, "identity/input.bin"))

    def test_history_minima_mitigation_and_initial_identity(self):
        tenant = oracle.read(self.directory, self.cases["tenant_initialized"]["report"])
        initial = oracle.expected_history(tenant)
        after = oracle.read(self.directory, self.cases["tenant_subsequent"]["report"])
        subsequent = oracle.expected_history(after, initial)
        self.assertEqual(initial, generator.first_history(tenant))
        self.assertEqual(subsequent, generator.next_history(initial, after))
        self.assertEqual(subsequent[32:], initial[32:])
        for offset in (2, 3, 4, *range(18, 32)):
            self.assertLessEqual(subsequent[offset], initial[offset])
        self.assertEqual(struct.unpack_from("<Q", subsequent, 10)[0],
                         struct.unpack_from("<Q", initial, 10)[0] &
                         struct.unpack_from("<Q", after, 0x1F8)[0])

    def test_platform_floors_are_componentwise_and_history_independent(self):
        oracle.verify_platform(self.report)
        for offset in range(0x38, 0x3B):
            report = bytearray(self.report)
            report[offset] = 0
            self.rejects("TcbBelowFloor", lambda: oracle.verify_platform(report))
        for offset in range(0x220, 0x22E):
            report = bytearray(self.report)
            report[offset] = 0
            self.rejects("ArgBelowFloor" if offset == 0x22D else "EtcbBelowFloor",
                         lambda: oracle.verify_platform(report))
        report = bytearray(self.report)
        report[0x200] &= 0xFE
        self.rejects("MitigationBelowFloor", lambda: oracle.verify_platform(report))
        report = bytearray(self.report)
        report[0x240:0x24E] = bytes(14)
        oracle.verify_platform(report)

    def test_signed_history_increases_and_initial_ma_substitutions_fail(self):
        case = self.cases["tenant_subsequent"]
        report = oracle.read(self.directory, case["report"])
        value = oracle.read(self.directory, case["supplement"])
        previous = bytes.fromhex(case["previous_history"])
        offsets = [158, 159, 160, *range(174, 188), *range(188, 220)]
        for offset in offsets:
            changed = bytearray(value)
            changed[offset] = changed[offset] + 1
            signature = generator.reference.fixed_signature(
                self.signing_key, b"SNP-EMU-SUPPLEMENT-v1" + changed)
            oracle.verify_supplement(report, changed, signature, self.key)
            self.rejects("HistoryMismatch", lambda: oracle.verify_history(
                report, changed, previous, oracle.DESTINATION_ID))
        mitigation = struct.unpack_from("<Q", value, 166)[0]
        for bit in range(64):
            changed = bytearray(value)
            struct.pack_into("<Q", changed, 166, mitigation ^ (1 << bit))
            signature = generator.reference.fixed_signature(
                self.signing_key, b"SNP-EMU-SUPPLEMENT-v1" + changed)
            oracle.verify_supplement(report, changed, signature, self.key)
            self.rejects("HistoryMismatch", lambda: oracle.verify_history(
                report, changed, previous, oracle.DESTINATION_ID))
        for index in range(32):
            changed = bytearray(report)
            changed[0x160 + index] ^= 1
            self.rejects("TenantMaBinding", lambda: oracle.verify_history(
                changed, value, previous, oracle.DESTINATION_ID))

    def test_allowlist_time_sequence_and_signature_boundaries(self):
        value = oracle.read(self.directory, "allowlists/approved.bin")
        identity = value[40:88]

        def verify(record, now=100, previous=None):
            oracle.verify_allowlist(self.directory, record, identity, now,
                                    "certificates/authorization.der", "certificates/ark.der", previous)

        for now in (20, 100, 179):
            verify(value, now)
        self.rejects("NotYetValidAllowlist", lambda: verify(value, 19))
        self.rejects("ExpiredAllowlist", lambda: verify(value, 180))
        verify(value, previous=value)
        key = ec.derive_private_key(4, ec.SECP384R1())
        for sequence, error in ((9, "SequenceRollback"), (10, "SequenceContentConflict")):
            body = bytearray(value[:224])
            struct.pack_into("<Q", body, 8, sequence)
            body[88] ^= 1
            record = body + generator.reference.fixed_signature(key, body)
            self.rejects(error, lambda: verify(record, previous=value))
        for offset in range(224, 320):
            record = bytearray(value)
            record[offset] ^= 1
            self.rejects("InvalidAllowlistSignature", lambda: verify(record))

    def test_fixture_roots_preserve_existing_image_fingerprints(self):
        lines = (ROOT / "src/pal/src/snp/test_data/p010_vectors.txt").read_text().splitlines()
        vectors = {line.split(" ", 1)[0]: bytes.fromhex(line.split(" ", 1)[1])
                   for line in lines if line and not line.startswith("#")}
        for name, key in (("ark", "root_der"), ("unrelated-root", "unrelated_root_der")):
            self.assertEqual(oracle.read(self.directory, f"certificates/{name}.der"), vectors[key])

    def test_manifest_corruption_extra_files_and_symlinks_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, data in generator.build().items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            oracle.verify_package(directory)
            extra = directory / "extra"
            extra.write_bytes(b"undeclared")
            self.rejects("ManifestMembership", lambda: oracle.verify_package(directory))
            extra.unlink()
            report = directory / self.source["report"]
            original = report.read_bytes()
            report.write_bytes(original[:-1])
            self.rejects("ManifestHash", lambda: oracle.verify_package(directory))
            report.unlink()
            report.symlink_to(self.directory / self.source["report"])
            self.rejects("SymlinkAsset", lambda: oracle.verify_package(directory))
        for name in ("../outside", "/absolute"):
            self.rejects("UnsafeAssetPath", lambda: oracle.read(self.directory, name))
        self.rejects("DuplicateJsonKey", lambda: json.loads(
            '{"a":1,"a":2}', object_pairs_hook=oracle.unique_pairs))

    def test_cli_default_is_check_only(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "sh_script/test/snp_v6_fixtures.py")],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        self.assertIn("files match", result.stdout)

    def test_all_generated_assets_can_be_checked_into_git(self):
        prefix = self.directory.relative_to(ROOT).as_posix()
        names = "\n".join(f"{prefix}/{name}" for name in generator.build()) + "\n"
        result = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"], cwd=ROOT,
                                input=names, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
