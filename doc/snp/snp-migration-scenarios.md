# SNP migration scenario names

The canonical names are `SingleProcessMigration`,
`InterNodeTwoProcessMigration`, and `LocalMaHandoffTwoProcess`.
These names replace historical Stage A/B and ambiguous local old/new labels
without changing migration behavior, process arguments, protocol or trust.

## Current captured-fixture compatibility runners

Build the emulator/controller through the [bundle producer](snp-bundles.md),
then supply their frozen executable paths. These runners do not build or
change them. Task 5 removes the obsolete TDX policy/root-CA inputs; neither
`MIGTD_POLICY_FILE` nor `MIGTD_ROOT_CA_FILE` is required or loaded.

```bash
bash sh_script/test/run_snp_single_process_migration.sh \
  target/bundles/emulator/bin/migtd \
  target/single-process-migration

bash sh_script/test/run_snp_inter_node_two_process_migration.sh \
  target/bundles/emulator/bin/migtd \
  target/bundles/emulator/bin/host_wfr_test \
  target/inter-node-two-process-migration
```

Run scenarios sequentially. `SingleProcessMigration` is the canonical name
of the historical autostart scenario, not a new process-count assertion: its
runner still launches source and destination MA processes from the same ELF.
`InterNodeTwoProcessMigration` retains two MA processes and two WFR controller
processes, with separate host-control and peer addresses. No process is merged,
new provider selected or previously unavailable workflow activated.

When omitted, the evidence directories are
`snp-single-process-migration-evidence` and
`snp-inter-node-two-process-migration-evidence` under the current directory.
Explicit evidence paths and manifest field names are unchanged.

| Canonical environment variable | Default |
|---|---|
| `MIGTD_SINGLE_PROCESS_MIGRATION_PEER_ADDRESS` | `127.0.0.1:19410` |
| `MIGTD_SINGLE_PROCESS_MIGRATION_TIMEOUT_SECONDS` | `90` |
| `MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION_SOURCE_HOST_ADDRESS` | `127.0.0.1:19501` |
| `MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION_DESTINATION_HOST_ADDRESS` | `127.0.0.1:19502` |
| `MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION_PEER_ADDRESS` | `127.0.0.1:19503` |
| `MIGTD_INTER_NODE_TWO_PROCESS_MIGRATION_TIMEOUT_SECONDS` | `90` |

### Compatibility and historical records

The old `run_snp_unified_stage_a.sh` and `run_snp_unified_stage_b.sh` paths are
thin executable aliases to the canonical runners. They forward all arguments
and exit status; output uses the canonical scenario name.
The corresponding `MIGTD_STAGE_A_*` / `MIGTD_STAGE_B_*` environment variables
remain fallback aliases for the same suffixes in the table. A nonempty
canonical variable wins; empty/unset canonical values retain the old fallback
and default behavior. New automation should use canonical paths and variables.

Historical execution logs, hashes, commits, frozen addenda, inventory manifests
and validation summaries retain their original names and bytes. A historical
filename/hash does not describe the current compatibility wrapper's contents.
The rename-only commit deliberately excludes pre-existing uncommitted
implementation and acceptance changes; it is not a reproducible snapshot of
the accepted working implementation.

## Local handoff is a different scenario

`LocalMaHandoffTwoProcess` is reserved for the Phase4 old/new-MA workflow with
independent authoritative firmware-state emulation. There is no current
executable local-handoff runner to rename or claim as implemented.
Inter-node source/destination conformance tests are not local handoff.
The [frozen consumer matrix (removed)](master-execution-plan.md#removed-task4-documentation) retains
the R4.1-R4.7 implementation and qualification obligations.

## Validation

```bash
bash -n sh_script/test/run_snp_single_process_migration.sh \
  sh_script/test/run_snp_inter_node_two_process_migration.sh \
  sh_script/test/run_snp_unified_stage_a.sh \
  sh_script/test/run_snp_unified_stage_b.sh
python3 -m unittest discover -s sh_script/test -p test_snp_migration_runners.py
```

Naming/alias tests use deliberately failing processes, not successful
attestation or migration doubles. Actual captured-fixture scenario regressions
remain separate from common V6, V2, local-handoff or production qualification.
