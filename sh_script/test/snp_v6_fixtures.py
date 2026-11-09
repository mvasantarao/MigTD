#!/usr/bin/env python3
# Copyright (c) 2026 Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Reproduce public TEST ONLY V6 fixtures; never install or activate them."""

import argparse
import copy
import hashlib
import importlib.metadata
import json
import pathlib
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import snp_crypto_vectors as reference


ROOT = pathlib.Path(__file__).resolve().parents[2]
DESTINATION = ROOT / "src/snp_emu/src/fixture_data/venice_v6_synthetic"
REQUEST = 0x0102030405060708
TH1 = hashlib.sha384(b"Task6 synthetic transcript, not a live SPDM session").digest()
POLICY = b'{"test_only":true}'
SOURCE_ID = bytes([0x11]) * 32
DESTINATION_ID = bytes([0x22]) * 32
TENANT_ID = bytes([0x77]) * 32
GROUPS = [
    "GuestProvidedReportData", "HostRequestedZeroReportData",
    "NonzeroEtcbReserved", "UnknownHistoryProfile", "HistoryMinimumIncrease",
    "ArgBelowPolicyFloor", "IdentityOrPolicyDigestMismatch", "ChangedIdentityField",
    "UnknownRootOrWrongPurpose", "InvalidAllowlistSignature", "ExpiredAllowlist",
    "NonApprovedAllowlist", "FixtureRootToProduction", "ChangedReportDigest",
    "ChangedSupplementSignature", "NonzeroSupplementReserved", "SupplementEtcbMismatch",
    "InvalidHistoryFlagOrData", "FixtureEvidenceToSnpHardware",
]


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


def digest(*values):
    return hashlib.sha384(b"".join(values)).digest()


def policy_digest():
    return digest(b"SNP-LM-POLICY-v1", struct.pack("<I", len(POLICY)), POLICY)


def identity(report):
    return (struct.pack("<HHII", 1, 1, 6, 0) + report[0x90:0xC0] + report[4:8]
            + report[0x10:0x30] + report[0xE0:0x140] + report[0xC0:0xE0]
            + report[8:16] + policy_digest())


def make_report(role, report_data, key, subsequent=False):
    if len(report_data) != 64:
        raise ValueError("REPORT_DATA must contain exactly 64 bytes")
    report = bytearray(reference.report(role, report_data, key))
    for offset, components in ((0x38, (20, 21, 22)), (0x180, (18, 19, 20)),
                               (0x1E0, (19, 20, 21)), (0x1F0, (9, 8, 7))):
        report[offset:offset + 8] = bytes(components) + bytes(5)
    report[0x220:0x240] = bytes(range(30, 44)) + bytes(18)
    report[0x240:0x260] = bytes(range(10, 24)) + bytes(18)
    report[0x260:0x280] = bytes(range(20, 34)) + bytes(18)
    report[0x200:0x208] = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
    if subsequent:
        report[0x160:0x180] = DESTINATION_ID
        report[0x1F0:0x1F8] = bytes([5, 8, 4]) + bytes(5)
        report[0x240:0x260] = bytes(8 if i % 2 == 0 else 25 for i in range(14)) + bytes(18)
        report[0x1F8:0x200] = struct.pack("<Q", 0xCCCCCCCCCCCCCCCC)
    return reference.sign_report(report, key)


def first_history(report):
    return (bytes([1, 3]) + report[0x1F0:0x200] + report[0x240:0x24E] + SOURCE_ID)


def next_history(previous, report):
    tcb = bytes(min(a, b) for a, b in zip(previous[2:5], report[0x1F0:0x1F3]))
    mitigation = struct.unpack_from("<Q", previous, 10)[0]
    mitigation &= struct.unpack_from("<Q", report, 0x1F8)[0]
    etcb = bytes(min(a, b) for a, b in zip(previous[18:32], report[0x240:0x24E]))
    return bytes([1, 3]) + tcb + bytes(5) + struct.pack("<Q", mitigation) + etcb + previous[32:]


def context(purpose, role, binding, identity_digest):
    return (b"AMD-SNP-MA-LM-REPORT-DATA-V1" + struct.pack("<HBBQHH", 1, purpose, role,
            REQUEST, 1, 3) + TENANT_ID + TH1 + binding + identity_digest)


def build():
    if sys.version_info < (3, 12) or importlib.metadata.version("cryptography") != "50.0.1":
        raise RuntimeError("fixtures require Python >=3.12 and cryptography==50.0.1")
    assets, cases = {}, []
    keys = [ec.derive_private_key(i, ec.SECP384R1()) for i in range(1, 7)]
    ark = reference.certificate(keys[0], "ROOT", None, keys[0], 1, True)
    ask = reference.certificate(keys[1], "ASK", ark, keys[0], 2, True)
    vcek = reference.certificate(keys[2], "VCEK", ask, keys[1], 3, False)
    signer = reference.certificate(keys[3], "AUTH", ask, keys[1], 4, False, reference.PURPOSE)
    wrong = reference.certificate(keys[4], "WRONG PURPOSE", ask, keys[1], 5, False,
                                  reference.PURPOSE + ".99")
    unrelated = reference.certificate(keys[5], "UNRELATED ROOT", None, keys[5], 6, True)

    def put(path, data):
        if path in assets and assets[path] != data:
            raise ValueError(f"conflicting fixture asset: {path}")
        assets[path] = bytes(data)
        return path

    for name, cert in (("ark", ark), ("ask", ask), ("vcek", vcek),
                       ("authorization", signer), ("wrong-purpose", wrong),
                       ("unrelated-root", unrelated)):
        put(f"certificates/{name}.der", cert.public_bytes(serialization.Encoding.DER))
    put("policy/canonical.json", POLICY)
    put("key-recipe.json", json_bytes({
        "classification": "PUBLIC TEST ONLY PRIVATE KEY RECIPE; NOT SECRETS",
        "curve": "secp384r1", "derivation": "derive_private_key(integer_scalar)",
        "keys": dict(zip(("ark", "ask", "vcek", "authorization", "wrong-purpose",
                          "unrelated-root"), range(1, 7))),
        "certificate_profile": "Task6FixtureP384V1",
        "certificate_validity_unix_seconds": [10, 200],
        "verification_time_unix_seconds": 100,
        "eku": reference.PURPOSE,
        "production_trust": False,
    }))

    def bundle(name, report, history=None, report_path=None, **metadata):
        report_path = report_path or f"reports/{name}.bin"
        put(report_path, report)
        supplement, signature = reference.supplement(report, history, keys[2])
        return dict(report=report_path,
                    supplement=put(f"supplements/{name}.bin", supplement),
                    signature=put(f"supplements/{name}.sig", signature), **metadata)

    tenant = make_report(2, bytes(64), keys[2])
    initial = first_history(tenant)
    after = make_report(2, bytes(64), keys[2], subsequent=True)
    tenant_cases = {
        "tenant_uninitialized": bundle("tenant_uninitialized", tenant, kind="tenant",
                                       report_path="reports/tenant_source.bin"),
        "tenant_initialized": bundle("tenant_initialized", tenant, initial, kind="tenant",
                                     report_path="reports/tenant_source.bin"),
        "tenant_subsequent": bundle("tenant_subsequent", after, next_history(initial, after),
                                    kind="tenant", previous_history=initial.hex(),
                                    expected_ma_id=DESTINATION_ID.hex()),
    }
    bound_tenant = tenant_cases["tenant_uninitialized"]
    tenant_digest = reference.evidence_digest(b"SNP-LM-TENANT-EVIDENCE-v1", tenant, (
        assets[bound_tenant["supplement"]], assets[bound_tenant["signature"]]))
    identity_bytes = identity(make_report(0, bytes(64), keys[2]))
    put("identity/input.bin", identity_bytes)
    identity_digest = digest(b"SNP-MA-POLICY-IDENTITY-v1", identity_bytes)
    session_binding = digest(b"SNP-LM-SESSION-BIND-v2", struct.pack("<QHH", REQUEST, 1, 3),
                             TENANT_ID, tenant_digest, TH1)
    authorization = (b"SNP-LM-TENANT-AUTH-v2" + struct.pack("<HQHHBB", 2, REQUEST, 1, 3, 0, 1)
                     + TENANT_ID + tenant_digest + TH1 + SOURCE_ID + DESTINATION_ID
                     + identity_digest * 2)
    put("bindings/authorization-v2.bin", authorization)
    source_cases = {}
    for purpose in (6, 7):
        for role, name in ((0, "source"), (1, "destination")):
            name += "_session_v2" if purpose == 6 else "_authorization_v2"
            ctx = context(purpose, role, session_binding if purpose == 6
                          else digest(authorization), identity_digest)
            report = make_report(role, digest(ctx) + bytes(16), keys[2])
            source_cases[name] = bundle(name, report, kind="ma", role=role, purpose=purpose)
            put(f"bindings/{name}.bin", ctx)

    root_spki = ark.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    root_id = digest(root_spki)
    subject = signer.subject.public_bytes()
    signer_id = digest(b"SNP-MA-AUTH-SIGNER-v1", root_id, struct.pack("<I", len(subject)), subject)
    allowlist_body = (struct.pack("<HHIQQQII", 1, 1, 320, 10, 20, 180, 1, 0)
                      + identity_digest + b"task6" + bytes(27) + signer_id + root_id
                      + struct.pack("<HHHH", 1, 1, 1, 0))

    def signed_allowlist(body):
        return body + reference.fixed_signature(keys[3], body)

    allowlist = put("allowlists/approved.bin", signed_allowlist(allowlist_body))
    for name, case in source_cases.items():
        case["allowlist"] = allowlist
        cases.append(dict(name=name, group=1, expected="OK", **case))
    for name, case in tenant_cases.items():
        cases.append(dict(name=name, group=2, expected="OK", **case))
    base = source_cases["source_session_v2"]

    def negative(name, group, expected, base_case=None, **changes):
        case = copy.deepcopy(base_case or base)
        case.update(changes)
        cases.append(dict(name=name, group=group, expected=expected, **case))

    def changed_report(name, mutate, group, expected, base_case=None):
        case = copy.deepcopy(base_case or base)
        report = bytearray(assets[case["report"]])
        mutate(report)
        report = reference.sign_report(report, keys[2])
        replacement = bundle(name, report)
        negative(name, group, expected, case, **replacement)

    for field, offset in (("current", 0x220), ("launch", 0x240), ("committed", 0x260)):
        changed_report(f"reserved_etcb_{field}",
                       lambda report, offset=offset: report.__setitem__(offset + 14, 1),
                       3, "ReservedEtcb")

    def changed_supplement(name, mutate, group, expected, base_case=None):
        case = copy.deepcopy(base_case or base)
        value = bytearray(assets[case["supplement"]])
        mutate(value)
        signature = reference.fixed_signature(keys[2], b"SNP-EMU-SUPPLEMENT-v1" + value)
        negative(name, group, expected, case,
                 supplement=put(f"supplements/{name}.bin", value),
                 signature=put(f"supplements/{name}.sig", signature))

    initialized = tenant_cases["tenant_initialized"]
    changed_supplement("unknown_history_profile", lambda value: value.__setitem__(157, 255),
                       4, "UnknownHistoryProfile", initialized)
    changed_supplement("history_minimum_increase", lambda value: value.__setitem__(158, 10),
                       5, "HistoryMismatch", initialized)

    def low_arg(report):
        report[0x22D] = 0
        report[0x26D] = 0

    changed_report("arg_below_floor", low_arg, 6, "ArgBelowFloor")
    changed = bytearray(allowlist_body)
    changed[40] ^= 1
    negative("identity_allowlist_mismatch", 7, "IdentityMismatch",
             allowlist=put("allowlists/identity-mismatch.bin", signed_allowlist(bytes(changed))))
    changed_policy = bytearray(policy_digest())
    changed_policy[0] ^= 1
    negative("policy_digest_mismatch", 7, "PolicyDigestMismatch",
             envelope_policy_digest=changed_policy.hex())
    for field, offset in (("measurement", 0x90), ("guest_svn", 4), ("family", 0x10),
                          ("image", 0x20), ("id_key", 0xE0), ("author_key", 0x110),
                          ("host_data", 0xC0), ("guest_policy", 8)):
        changed_report(f"changed_{field}", lambda report, offset=offset:
                       report.__setitem__(offset, report[offset] ^ 1), 8, "IdentityMismatch")
    negative("unknown_authorization_root", 9, "UnknownRoot",
             authorization_root="certificates/unrelated-root.der")
    negative("wrong_signer_purpose", 9, "WrongPurpose",
             authorization_leaf="certificates/wrong-purpose.der")
    bad_signature = bytearray(assets[allowlist])
    bad_signature[-1] ^= 1
    negative("bad_allowlist_signature", 10, "InvalidAllowlistSignature",
             allowlist=put("allowlists/bad-signature.bin", bad_signature))
    negative("expired_allowlist", 11, "ExpiredAllowlist", now=180)
    changed = bytearray(allowlist_body)
    changed[32:36] = struct.pack("<I", 2)
    negative("non_approved_allowlist", 12, "NonApprovedAllowlist",
             allowlist=put("allowlists/non-approved.bin", signed_allowlist(bytes(changed))))
    negative("fixture_root_to_production", 13, "FixtureTrustRejected", trust="production")
    changed = bytearray(assets[base["report"]])
    changed[0x140] ^= 1
    negative("changed_report_digest", 14, "ReportDigestMismatch",
             report=put("reports/changed_report_digest.bin", reference.sign_report(changed, keys[2])))
    changed = bytearray(assets[base["signature"]])
    changed[-1] ^= 1
    negative("bad_supplement_signature", 15, "InvalidSupplementSignature",
             signature=put("supplements/bad-signature.sig", changed))
    changed_supplement("reserved_supplement", lambda value: value.__setitem__(149, 1),
                       16, "ReservedSupplement")
    for field, offset in (("current", 52), ("launch", 84), ("committed", 116)):
        changed_supplement(f"mismatched_{field}_etcb",
                           lambda value, offset=offset: value.__setitem__(offset, value[offset] ^ 1),
                           17, "SupplementEtcbMismatch")
    changed_supplement("invalid_history_flag", lambda value: value.__setitem__(148, 2),
                       18, "InvalidHistoryFlag")
    changed_supplement("nonzero_invalid_history", lambda value: value.__setitem__(156, 1),
                       18, "NonzeroInvalidHistory")
    negative("fixture_to_hardware", 19, "FixtureProfileRejected", provider="SnpHardware")

    vcek_der, ask_der = assets["certificates/vcek.der"], assets["certificates/ask.der"]
    collateral = (b"SNP-LM-C" + struct.pack("<BBHIBBH", 1, 0, 3,
                  40 + len(vcek_der) + len(ask_der), 2, 3, 2) + bytes(4)
                  + struct.pack("<HHI", 1, 0, len(vcek_der)) + vcek_der
                  + struct.pack("<HHI", 3, 0, len(ask_der)) + ask_der)
    put("collateral/report-chain.bin", collateral)
    for name, case in source_cases.items():
        ctx = assets[f"bindings/{name}.bin"]
        header = (b"SNP-LM-E" + struct.pack("<BBHIQBBBBI", 1, 0, 1, 1540, REQUEST,
                  case["role"], case["purpose"], 2, 3, 0))
        envelope = (header + ctx + struct.pack("<HHI", 1, 0, 56) + policy_digest()
                    + digest(collateral) + assets[case["report"]])
        if len(envelope) != 1540:
            raise ValueError("invalid MA evidence envelope size")
        put(f"envelopes/{name}.bin", envelope)
    put("case-catalogue.json", json_bytes({
        "classification": "PUBLIC TEST ONLY; not authenticated runtime receipts",
        "qualification": "Independent fixture oracle only; AAS1A/AAS1A-M pending",
        "groups": dict(enumerate(GROUPS, 1)), "cases": cases,
        "binding_tenant": bound_tenant,
        "identity_digest": identity_digest.hex(), "policy_digest": policy_digest().hex(),
        "tenant_complete_evidence_digest": tenant_digest.hex(),
        "request_id": REQUEST, "th1": TH1.hex(),
        "time": 100, "minimum_current_arg_svn": 1,
        "fixture_policy_model": "TestPolicy with immutable all-component floor 1; not Microsoft schema",
        "provider_negatives": "Trust/profile selection checks, not executable production provider qualification",
    }))
    put("README.md", (
        "# Synthetic Venice V6 fixtures\n\n"
        "PUBLIC TEST ONLY. All private signing keys are publicly reproducible from "
        "`key-recipe.json`; none are production secrets or AMD-derived keys.\n\n"
        "Task6FixtureP384V1 reuses the P0.10 fixture ARK/ASK/VCEK and authorization "
        "certificates. It is generic P-384 fixture PKI, without AMD product/TCB/HWID "
        "extensions. Zero CPUID/CHIP_ID are synthetic placeholders, not Venice "
        "hardware identity. These assets do not qualify the native AAS verifier.\n\n"
        "Reports use the ABI 1.59 V6 field layout, exact 672-byte signed body and "
        "512-byte signature structure. The separately signed 220-byte supplement "
        "carries history; base bit 5 remains zero. The author-key convention follows "
        "the accepted MA contract and ABI launch-finish assignment; inconsistent "
        "report-table zeroing prose is not a new production parser rule.\n\n"
        "MA contexts use V2 purposes 6/7; REPORT_DATA is SHA384(context) plus 16 zero "
        "bytes. Tenant reports have VMPL 0xffffffff and 64 zero bytes. The fixed "
        "policy is the existing test-only model, not an approved Microsoft schema. "
        "Time is a fixed test epoch, not the current wall clock.\n\n"
        "`case-catalogue.json` names positive/negative cases and expected oracle errors. "
        "Semantically invalid but re-signed assets are intentional. Trust/hardware "
        "negatives check fixture-profile selection only; common provider conformance, "
        "V6 runtime activation and production qualification remain downstream.\n\n"
        "## Verify the saved fixtures (read-only)\n\n"
        "Use Python 3.12 or later, preferably in an activated virtual environment. "
        "Run these commands from the MigTD repository root (the directory containing "
        "`Cargo.toml`):\n\n"
        "```bash\n"
        "python3 -m pip install -r sh_script/test/requirements-snp-v6.txt\n"
        "python3 -B sh_script/test/snp_v6_fixtures.py\n"
        "```\n\n"
        "The first command installs the required Python packages. The second "
        "regenerates the expected fixture bytes in memory and compares them with "
        "the saved files. It does not modify any fixture files. A successful check "
        "prints `Task6 deterministic fixture package: 100 files match`; a mismatch "
        "is reported as an error.\n\n"
        "## Regenerate the saved fixtures (writes files)\n\n"
        "Only when intentionally updating this synthetic package, run:\n\n"
        "```bash\n"
        "python3 -B sh_script/test/snp_v6_fixtures.py --write\n"
        "```\n\n"
        "This overwrites the generated files in "
        "`src/snp_emu/src/fixture_data/venice_v6_synthetic/`, including its README "
        "and manifest hashes. It is not needed for routine verification. Update "
        "the README text in `sh_script/test/snp_v6_fixtures.py`, not directly in "
        "this generated file.\n\n"
        "Neither mode rewrites the parent captured report/certificates or the "
        "historical P0.10 and direct-random V2 corpora.\n"
    ).encode("ascii"))
    preserved = ("src/snp_emu/src/fixture_data/snp_report.bin",
                 "src/snp_emu/src/fixture_data/ark.der", "src/snp_emu/src/fixture_data/ask.der",
                 "src/snp_emu/src/fixture_data/vcek.der", "src/pal/src/snp/test_data/p010_vectors.txt",
                 "src/pal/src/snp/test_data/direct_random_v2.txt")
    manifest = {
        "format": "Task6SyntheticVeniceV6-v1", "trust": "fixture-only",
        "evidence_profile": "SnpEmulatorV1", "common_adapter_qualified": False,
        "certificate_profile": "Task6FixtureP384V1", "vlek": False,
        "qualification": "signed synthetic fixture corpus; migration-unqualified",
        "generator": "sh_script/test/snp_v6_fixtures.py",
        "generator_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        "reference_helper_sha256": hashlib.sha256(pathlib.Path(reference.__file__).read_bytes()).hexdigest(),
        "toolchain": {"python_minimum": "3.12", "cryptography": "50.0.1"},
        "certificate_chain_sha384": digest(
            b"SNP-CERT-CHAIN-v1",
            *[struct.pack("<I", len(value)) + value for value in
              (vcek_der, ask_der, assets["certificates/ark.der"])]).hex(),
        "authorization_root_id_sha384": root_id.hex(),
        "ma_policy_identity_digest_sha384": identity_digest.hex(),
        "counts": {"reports": sum(p.startswith("reports/") for p in assets),
                   "certificates": 6, "private_key_roles": 6, "groups": len(GROUPS),
                   "positive_cases": 7, "negative_cases": len(cases) - 7,
                   "cases": len(cases), "payload_files": len(assets)},
        "preserved_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in preserved},
        "files": {p: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "sha384": hashlib.sha384(data).hexdigest()}
                  for p, data in sorted(assets.items())},
    }
    put("manifest.json", json_bytes(manifest))
    return assets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly write generated assets")
    parser.add_argument("--output", type=pathlib.Path, default=DESTINATION)
    args = parser.parse_args()
    assets = build()
    if args.write:
        args.output.mkdir(parents=True, exist_ok=True)
        extra = {p.relative_to(args.output).as_posix() for p in args.output.rglob("*")
                 if p.is_file()} - assets.keys()
        if extra:
            raise SystemExit(f"refusing to overwrite an unsealed directory; undeclared files: {sorted(extra)}")
        for name, data in assets.items():
            path = args.output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    found = {p.relative_to(args.output).as_posix(): p.read_bytes()
             for p in args.output.rglob("*") if p.is_file()}
    if found != assets:
        missing, extra = assets.keys() - found.keys(), found.keys() - assets.keys()
        changed = [p for p in assets.keys() & found.keys() if assets[p] != found[p]]
        raise SystemExit(f"fixture mismatch: missing={sorted(missing)}, extra={sorted(extra)}, changed={changed}")
    print(f"Task6 deterministic fixture package: {len(assets)} files match")


if __name__ == "__main__":
    main()
