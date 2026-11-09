# Synthetic Venice V6 fixtures

PUBLIC TEST ONLY. All private signing keys are publicly reproducible from `key-recipe.json`; none are production secrets or AMD-derived keys.

Task6FixtureP384V1 reuses the P0.10 fixture ARK/ASK/VCEK and authorization certificates. It is generic P-384 fixture PKI, without AMD product/TCB/HWID extensions. Zero CPUID/CHIP_ID are synthetic placeholders, not Venice hardware identity. These assets do not qualify the native AAS verifier.

Reports use the ABI 1.59 V6 field layout, exact 672-byte signed body and 512-byte signature structure. The separately signed 220-byte supplement carries history; base bit 5 remains zero. The author-key convention follows the accepted MA contract and ABI launch-finish assignment; inconsistent report-table zeroing prose is not a new production parser rule.

MA contexts use V2 purposes 6/7; REPORT_DATA is SHA384(context) plus 16 zero bytes. Tenant reports have VMPL 0xffffffff and 64 zero bytes. The fixed policy is the existing test-only model, not an approved Microsoft schema. Time is a fixed test epoch, not the current wall clock.

`case-catalogue.json` names positive/negative cases and expected oracle errors. Semantically invalid but re-signed assets are intentional. Trust/hardware negatives check fixture-profile selection only; common provider conformance, V6 runtime activation and production qualification remain downstream.

## Verify the saved fixtures (read-only)

Use Python 3.12 or later, preferably in an activated virtual environment. Run these commands from the MigTD repository root (the directory containing `Cargo.toml`):

```bash
python3 -m pip install -r sh_script/test/requirements-snp-v6.txt
python3 -B sh_script/test/snp_v6_fixtures.py
```

The first command installs the required Python packages. The second regenerates the expected fixture bytes in memory and compares them with the saved files. It does not modify any fixture files. A successful check prints `Task6 deterministic fixture package: 100 files match`; a mismatch is reported as an error.

## Regenerate the saved fixtures (writes files)

Only when intentionally updating this synthetic package, run:

```bash
python3 -B sh_script/test/snp_v6_fixtures.py --write
```

This overwrites the generated files in `src/snp_emu/src/fixture_data/venice_v6_synthetic/`, including its README and manifest hashes. It is not needed for routine verification. Update the README text in `sh_script/test/snp_v6_fixtures.py`, not directly in this generated file.

Neither mode rewrites the parent captured report/certificates or the historical P0.10 and direct-random V2 corpora.
