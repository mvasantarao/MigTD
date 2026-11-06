#!/usr/bin/env python3
"""Naming/compatibility controls; failing doubles do not emulate migration."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNERS = ROOT / "sh_script/test"
SCENARIOS = (
    ("single_process_migration", "SingleProcessMigration", "A", False),
    ("inter_node_two_process_migration", "InterNodeTwoProcessMigration", "B", True),
)
FAILING_PROCESS = r'''
import sys
from pathlib import Path

args = sys.argv[1:]
if "--role" in args:
    role = args[args.index("--role") + 1]
    request = 1003 if "--start-mode" in args else 1
    print("PEER_CHANNEL_LISTENING", flush=True)
    print("TcpTransport: bound", flush=True)
    print(f"START_MIGRATION_WORKFLOW_BEGIN: role={role} request_id={request}", flush=True)
else:
    print("Listening on test-only endpoint", flush=True)
    Path(args[args.index("--ready-file") + 1]).touch()
sys.exit(7)
'''


class MigrationRunnerNames(unittest.TestCase):
    def invoke(self, scenario, extra_env=None, alias=False, default_directory=False):
        slug, name, old, controller = scenario
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            executable = cwd / "failing-process"
            executable.write_text(f"#!{sys.executable}\n" + FAILING_PROCESS)
            executable.chmod(0o755)
            env = {
                key: value for key, value in os.environ.items()
                if key not in {"MIGTD_POLICY_FILE", "MIGTD_ROOT_CA_FILE", "MIGTD_POLICY_ISSUER_CHAIN_FILE"}
                and not key.startswith(("MIGTD_STAGE_", "MIGTD_SINGLE_PROCESS_MIGRATION_",
                                       "MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION_"))
            }
            env.update(extra_env or {})
            path = (f"run_snp_unified_stage_{old.lower()}.sh" if alias
                    else f"run_snp_{slug}.sh")
            command = [str(RUNNERS / path), str(executable)]
            if controller:
                command.append(str(executable))
            evidence = cwd / ("snp-" + slug.replace("_", "-") + "-evidence")
            if not default_directory:
                evidence = cwd / "explicit evidence"
                command.append(str(evidence))
            result = subprocess.run(
                command, cwd=cwd, env=env, capture_output=True, text=True, timeout=20,
            )
            manifest = evidence / "manifest.txt"
            values = {}
            if manifest.exists():
                values = dict(line.split("=", 1) for line in manifest.read_text().splitlines())
            return result, values

    def assert_failure_record(self, result, values, name):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(name + " process failure", result.stderr)
        self.assertEqual(values["source_exit"], "7")
        self.assertEqual(values["destination_exit"], "7")
        self.assertEqual(values["source_sha256"], values["destination_sha256"])

    def test_canonical_names_and_default_evidence_directories(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario[1]):
                result, values = self.invoke(scenario, default_directory=True)
                self.assert_failure_record(result, values, scenario[1])
                self.assertEqual(values["peer_address"],
                                 "127.0.0.1:19503" if scenario[3] else "127.0.0.1:19410")

    def test_tdx_fixture_environment_is_ignored(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario[1]):
                result, values = self.invoke(scenario, {
                    "MIGTD_POLICY_FILE": "/nonexistent/tdx-policy",
                    "MIGTD_ROOT_CA_FILE": "/nonexistent/tdx-root",
                })
                self.assert_failure_record(result, values, scenario[1])

    def test_compatibility_entry_points_forward_explicit_arguments(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario[1]):
                result, values = self.invoke(scenario, alias=True)
                self.assert_failure_record(result, values, scenario[1])

    def test_canonical_environment_wins_over_legacy_alias(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario[1]):
                prefix = "MIGTD_" + scenario[0].upper()
                result, values = self.invoke(scenario, {
                    prefix + "_PEER_ADDRESS": "127.0.0.1:21901",
                    f"MIGTD_STAGE_{scenario[2]}_PEER_ADDRESS": "127.0.0.1:21902",
                    prefix + "_TIMEOUT_SECONDS": "3",
                    f"MIGTD_STAGE_{scenario[2]}_TIMEOUT_SECONDS": "invalid",
                })
                self.assert_failure_record(result, values, scenario[1])
                self.assertEqual(values["peer_address"], "127.0.0.1:21901")

    def test_legacy_environment_remains_supported(self):
        for scenario in SCENARIOS:
            for alias in (False, True):
                with self.subTest(scenario=scenario[1], alias=alias):
                    result, values = self.invoke(scenario, {
                        f"MIGTD_STAGE_{scenario[2]}_PEER_ADDRESS": "127.0.0.1:21902",
                        f"MIGTD_STAGE_{scenario[2]}_TIMEOUT_SECONDS": "3",
                    }, alias=alias)
                    self.assert_failure_record(result, values, scenario[1])
                    self.assertEqual(values["peer_address"], "127.0.0.1:21902")

    def test_inter_node_host_environment_names_and_legacy_aliases(self):
        scenario = SCENARIOS[1]
        for canonical in (False, True):
            with self.subTest(canonical=canonical):
                prefix = ("MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION" if canonical
                          else "MIGTD_STAGE_B")
                env = {
                    "MIGTD_STAGE_B_SOURCE_HOST_ADDRESS": "127.0.0.1:21905",
                    "MIGTD_STAGE_B_DESTINATION_HOST_ADDRESS": "127.0.0.1:21906",
                }
                env.update({
                    prefix + "_SOURCE_HOST_ADDRESS": "127.0.0.1:21903",
                    prefix + "_DESTINATION_HOST_ADDRESS": "127.0.0.1:21904",
                })
                result, values = self.invoke(scenario, env)
                self.assert_failure_record(result, values, scenario[1])
                self.assertEqual(values["source_host_address"], "127.0.0.1:21903")
                self.assertEqual(values["destination_host_address"], "127.0.0.1:21904")

    def test_empty_canonical_environment_uses_legacy_fallback(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario[1]):
                prefix = "MIGTD_" + scenario[0].upper()
                result, values = self.invoke(scenario, {
                    prefix + "_PEER_ADDRESS": "",
                    prefix + "_TIMEOUT_SECONDS": "",
                    f"MIGTD_STAGE_{scenario[2]}_PEER_ADDRESS": "127.0.0.1:21902",
                    f"MIGTD_STAGE_{scenario[2]}_TIMEOUT_SECONDS": "3",
                })
                self.assert_failure_record(result, values, scenario[1])
                self.assertEqual(values["peer_address"], "127.0.0.1:21902")

    def test_inter_node_address_collision_still_rejected(self):
        result, values = self.invoke(SCENARIOS[1], {
            "MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION_SOURCE_HOST_ADDRESS": "same",
            "MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION_PEER_ADDRESS": "same",
        })
        self.assertEqual(result.returncode, 2)
        self.assertIn("InterNodeTwoProcessMigration", result.stderr)
        self.assertIn("must be distinct", result.stderr)
        self.assertEqual(values, {})

    def test_usage_and_exit_status_forwarded_by_aliases(self):
        for slug, _, old, _ in SCENARIOS:
            canonical = subprocess.run(
                [str(RUNNERS / f"run_snp_{slug}.sh")],
                capture_output=True, text=True, check=False,
            )
            alias = subprocess.run(
                [str(RUNNERS / f"run_snp_unified_stage_{old.lower()}.sh")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(canonical.returncode, 2)
            self.assertEqual(alias.returncode, canonical.returncode)
            self.assertEqual(alias.stderr, canonical.stderr)


if __name__ == "__main__":
    unittest.main()
