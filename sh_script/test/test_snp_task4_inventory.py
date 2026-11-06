#!/usr/bin/env python3
"""Negative and positive controls for the provisional image inventory gates."""

import unittest

from snp_task4_inventory import (
    FORBIDDEN_SYMBOLS, dependency_inventory, fixture_needles, scan_production,
)


class InventoryTests(unittest.TestCase):
    def test_every_fixture_and_synthetic_root_is_rejected(self):
        needles = fixture_needles()
        self.assertEqual(len(needles), 5)
        for name, value in needles.items():
            with self.subTest(asset=name), self.assertRaises(RuntimeError):
                scan_production(b"prefix" + value + b"suffix", "", needles)

    def test_every_forbidden_symbol_is_rejected_in_symbols_and_bytes(self):
        for marker in FORBIDDEN_SYMBOLS:
            with self.subTest(marker=marker):
                with self.assertRaises(RuntimeError):
                    scan_production(b"", marker, {})
                with self.assertRaises(RuntimeError):
                    scan_production(marker.encode(), "", {})

    def test_absence_returns_explicit_empty_scan_results(self):
        self.assertEqual(scan_production(b"\x7fELF", "", fixture_needles()), {
            "fixture_or_synthetic_root_hits": [], "forbidden_symbol_hits": [],
        })

    def test_dependency_inventory_preserves_features_and_deduplicates(self):
        tree = ("migtd v0.1.0|SnpHardware,std\n"
                "azure-guest-attestation-sdk v0.2.0|native,verify\n"
                "pal v0.1.0|snp-core,snp-production\n"
                "pal v0.1.0|snp-core,snp-production (*)\n")
        packages = dependency_inventory(tree, True)
        self.assertEqual(len(packages), 3)
        self.assertEqual(packages[-1]["features"], ["snp-core", "snp-production"])

    def test_production_dependency_and_backend_leaks_fail(self):
        aas = "azure-guest-attestation-sdk v0.2.0|native,verify\n"
        for line in (
            "snp_emu v0.1.0|", "tdx-tdcall v0.1.0|", "vmcall_raw v0.1.0|",
            "pal v0.1.0|snp-fixture", "migtd v0.1.0|test_disable_ra_and_accept_all",
            "tav-crypto v0.1.0|", "tee-attestation-verification-lib v0.1.0|",
            "azure-guest-attestation-sdk v0.2.0|rustcrypto,verify",
        ):
            with self.subTest(line=line), self.assertRaises(RuntimeError):
                dependency_inventory(aas + line, True)

    def test_missing_aas_or_malformed_tree_fails(self):
        for tree in ("pal v0.1.0|snp-production\n", "unexpected cargo output\n"):
            with self.subTest(tree=tree), self.assertRaises(RuntimeError):
                dependency_inventory(tree, True)

    def test_emulator_can_include_fixtures_but_not_tav(self):
        aas = "azure-guest-attestation-sdk v0.2.0|native,verify\n"
        self.assertEqual(len(dependency_inventory(aas + "snp_emu v0.1.0|", False)), 2)
        with self.assertRaises(RuntimeError):
            dependency_inventory(aas + "tav-crypto v0.1.0|", False)


if __name__ == "__main__":
    unittest.main()
