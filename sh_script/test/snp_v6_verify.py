#!/usr/bin/env python3
# Copyright (c) 2026 Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Independent fixture oracle, NOT the common AAS or production SNP verifier."""

import argparse
import hashlib
import json
import pathlib
import struct

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier, SignatureAlgorithmOID


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "src/snp_emu/src/fixture_data/venice_v6_synthetic"
ARK_SHA256 = "bbdd2ccc508d8fc4d2a3c4ce8bafcbb6883ed3fdaa06058d84a7ced487f33f17"
PURPOSE = "1.3.6.1.4.1.55555.162.1"
POLICY = b'{"test_only":true}'
REQUEST = 0x0102030405060708
TH1 = hashlib.sha384(b"Task6 synthetic transcript, not a live SPDM session").digest()
SOURCE_ID, DESTINATION_ID, TENANT_ID = (bytes([n]) * 32 for n in (0x11, 0x22, 0x77))
PRESERVED = {
    "src/snp_emu/src/fixture_data/snp_report.bin": "f5ae949a6c9c5715386a67ac5ab7acd12249c67f6a4480ee29d961d39d3f94b5",
    "src/snp_emu/src/fixture_data/ark.der": "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
    "src/snp_emu/src/fixture_data/ask.der": "67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b",
    "src/snp_emu/src/fixture_data/vcek.der": "2f82c6431fe1b8182f8c1807be22502c86df72e83cac0ad59c03c1dde3332da3",
    "src/pal/src/snp/test_data/p010_vectors.txt": "9de46afad2a51c2f9fa51cea9ec809573a170906f9ad0397cf5a17e20a86fd31",
    "src/pal/src/snp/test_data/direct_random_v2.txt": "4b9cb31bfd0a61473478b86f7571a9410898358542eed0074059822b7685dad6",
}


class FixtureError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(condition, code):
    if not condition:
        raise FixtureError(code)


def sha(value):
    return hashlib.sha384(value).digest()


def read(directory, relative, limit=65536):
    path = pathlib.PurePosixPath(relative)
    require(not path.is_absolute() and bool(path.parts) and
            all(part not in ("..", ".") for part in path.parts), "UnsafeAssetPath")
    current = directory
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), "SymlinkAsset")
    require(current.is_file() and current.stat().st_size <= limit, "AssetSize")
    return current.read_bytes()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DuplicateJsonKey")
        result[key] = value
    return result


def read_json(directory, name):
    return json.loads(read(directory, name), object_pairs_hook=unique_pairs)


def verify_signature(key, signature, message, error):
    require(len(signature) == 96, error)
    r, s = int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")
    try:
        key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise FixtureError(error) from exc


def chain(directory, leaf_name, now, purpose=False, root_name="certificates/ark.der"):
    root_der = read(directory, root_name, 16384)
    require(hashlib.sha256(root_der).hexdigest() == ARK_SHA256, "UnknownRoot")
    der = [root_der, read(directory, "certificates/ask.der", 16384),
           read(directory, leaf_name, 16384)]
    certs = []
    for index, value in enumerate(der):
        try:
            cert = x509.load_der_x509_certificate(value)
        except ValueError as exc:
            raise FixtureError("InvalidCertificate") from exc
        require(cert.public_bytes(serialization.Encoding.DER) == value, "InvalidCertificate")
        key = cert.public_key()
        require(isinstance(key, ec.EllipticCurvePublicKey) and
                isinstance(key.curve, ec.SECP384R1), "CertificateKeyType")
        require(cert.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA384,
                "CertificateSignatureAlgorithm")
        require(cert.not_valid_before_utc.timestamp() <= now <
                cert.not_valid_after_utc.timestamp(), "CertificateTime")
        constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        require(constraints.ca == (index < 2), "CertificateRole")
        if index < 2:
            require(usage.key_cert_sign and constraints.path_length == 1 - index, "CertificateRole")
        else:
            require(usage.digital_signature and not usage.key_cert_sign, "CertificateRole")
        certs.append(cert)
    for parent, child in ((certs[0], certs[0]), (certs[0], certs[1]), (certs[1], certs[2])):
        require(child.issuer == parent.subject, "CertificateIssuer")
        try:
            parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
                                       ec.ECDSA(hashes.SHA384()))
        except InvalidSignature as exc:
            raise FixtureError("CertificateSignature") from exc
    if purpose:
        eku = certs[2].extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        require(ObjectIdentifier(PURPOSE) in eku, "WrongPurpose")
    else:
        require(certs[2].subject.rfc4514_string() == "CN=P010 TEST ONLY VCEK", "CertificateRole")
    return certs[0], certs[2]


def verify_report(report, key, kind, expected_data):
    require(len(report) == 1184, "ReportLength")
    require(struct.unpack_from("<I", report)[0] == 6, "ReportVersion")
    require(struct.unpack_from("<I", report, 0x34)[0] == 1, "ReportSignatureAlgorithm")
    require(struct.unpack_from("<I", report, 0x48)[0] == 1, "ReportKeyInfo")
    for start, end in ((0x4C, 0x50), (0x18B, 0x1A0), (0x1EB, 0x1EC),
                       (0x1EF, 0x1F0), (0x208, 0x220), (0x280, 0x2A0)):
        require(report[start:end] == bytes(end - start), "ReservedReport")
    require(report[0x188:0x18B] == bytes(3) and report[0x1A0:0x1E0] == bytes(64),
            "FixtureCertificateProfile")
    require(report[0x2D0:0x2E8] == bytes(24) and report[0x318:] == bytes(392),
            "ReportSignaturePadding")
    r = int.from_bytes(report[0x2A0:0x2E8], "little")
    s = int.from_bytes(report[0x2E8:0x330], "little")
    try:
        key.verify(utils.encode_dss_signature(r, s), report[:672], ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise FixtureError("InvalidReportSignature") from exc
    vmpl = struct.unpack_from("<I", report, 0x30)[0]
    require(vmpl == (0xFFFFFFFF if kind == "tenant" else 0), "ReportVmpl")
    require(len(expected_data) == 64 and report[0x50:0x90] == expected_data, "ReportData")
    for offset in (0x38, 0x180, 0x1E0, 0x1F0):
        require(report[offset + 3:offset + 8] == bytes(5), "ReservedTcb")
    for offset in (0x220, 0x240, 0x260):
        require(report[offset + 14:offset + 32] == bytes(18), "ReservedEtcb")


def verify_supplement(report, value, signature, key):
    require(len(value) == 220, "SupplementLength")
    require(value[:4] == b"\x01\x00\x01\x00", "SupplementVersion")
    verify_signature(key, signature, b"SNP-EMU-SUPPLEMENT-v1" + value,
                     "InvalidSupplementSignature")
    require(value[4:52] == sha(report), "ReportDigestMismatch")
    require(value[149:156] == bytes(7), "ReservedSupplement")
    for a, b in ((52, 0x220), (84, 0x240), (116, 0x260)):
        require(value[a:a + 32] == report[b:b + 32], "SupplementEtcbMismatch")
    require(value[148] in (0, 1), "InvalidHistoryFlag")
    if value[148] == 0:
        require(value[156:] == bytes(64), "NonzeroInvalidHistory")
    else:
        require(value[156] == 1, "UnknownHistoryVersion")
        require(value[157] == 3, "UnknownHistoryProfile")
        require(value[161:166] == bytes(5), "ReservedHistoryTcb")


def expected_history(report, previous=None):
    current_tcb, current_etcb = report[0x1F0:0x1F3], report[0x240:0x24E]
    mitigation = struct.unpack_from("<Q", report, 0x1F8)[0]
    initial_id = SOURCE_ID
    if previous is not None:
        require(len(previous) == 64 and previous[:2] == b"\x01\x03"
                and previous[5:10] == bytes(5), "PreviousHistory")
        current_tcb = bytes(min(a, b) for a, b in zip(previous[2:5], current_tcb))
        current_etcb = bytes(min(a, b) for a, b in zip(previous[18:32], current_etcb))
        mitigation &= struct.unpack_from("<Q", previous, 10)[0]
        initial_id = previous[32:]
    return b"\x01\x03" + current_tcb + bytes(5) + struct.pack("<Q", mitigation) + current_etcb + initial_id


def identity_input(report):
    policy_hash = sha(b"SNP-LM-POLICY-v1" + struct.pack("<I", len(POLICY)) + POLICY)
    value = (b"\x01\x00\x01\x00\x06\x00\x00\x00" + bytes(4)
             + report[144:192] + report[4:8] + report[16:48]
             + report[224:320] + report[192:224] + report[8:16] + policy_hash)
    require(len(value) == 280, "IdentityLength")
    return value


def tenant_digest(directory):
    report = read(directory, "reports/tenant_source.bin")
    value = read(directory, "supplements/tenant_uninitialized.bin")
    signature = read(directory, "supplements/tenant_uninitialized.sig")
    _, leaf = chain(directory, "certificates/vcek.der", 100)
    verify_report(report, leaf.public_key(), "tenant", bytes(64))
    verify_supplement(report, value, signature, leaf.public_key())
    return sha(b"SNP-LM-TENANT-EVIDENCE-v1" + struct.pack("<HI", 2, 1184) + report
               + struct.pack("<I", 220) + value + struct.pack("<I", 96) + signature)


def expected_context(directory, purpose, role):
    require(purpose in (6, 7) and role in (0, 1), "ContextPurpose")
    identity_hash = sha(b"SNP-MA-POLICY-IDENTITY-v1" + read(directory, "identity/input.bin"))
    tenant = tenant_digest(directory)
    common = struct.pack("<QHH", REQUEST, 1, 3) + TENANT_ID
    if purpose == 6:
        binding = sha(b"SNP-LM-SESSION-BIND-v2" + common + tenant + TH1)
    else:
        authorization = (b"SNP-LM-TENANT-AUTH-v2" + struct.pack("<H", 2)
                         + common[:12] + bytes([0, 1]) + TENANT_ID + tenant + TH1
                         + SOURCE_ID + DESTINATION_ID + identity_hash * 2)
        require(len(authorization) == 325, "AuthorizationLength")
        require(read(directory, "bindings/authorization-v2.bin") == authorization,
                "AuthorizationBinding")
        binding = sha(authorization)
    return (b"AMD-SNP-MA-LM-REPORT-DATA-V1" + struct.pack("<HBB", 1, purpose, role)
            + common + TH1 + binding + identity_hash)


def verify_allowlist(directory, value, identity_hash, now, leaf_name, root_name,
                     previous=None):
    require(len(value) == 320, "AllowlistLength")
    require(value[:8] == struct.pack("<HHI", 1, 1, 320) and
            value[36:40] == bytes(4) and value[216:224] == struct.pack("<HHHH", 1, 1, 1, 0),
            "AllowlistFormat")
    root, signer = chain(directory, leaf_name, now, purpose=True, root_name=root_name)
    root_id = sha(root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    subject = signer.subject.public_bytes()
    signer_id = sha(b"SNP-MA-AUTH-SIGNER-v1" + root_id + struct.pack("<I", len(subject)) + subject)
    require(value[120:168] == signer_id and value[168:216] == root_id, "SignerIdentity")
    verify_signature(signer.public_key(), value[224:], value[:224], "InvalidAllowlistSignature")
    issued, expires = struct.unpack_from("<QQ", value, 16)
    require(issued < expires and now >= issued, "NotYetValidAllowlist")
    require(now < expires, "ExpiredAllowlist")
    require(struct.unpack_from("<I", value, 32)[0] == 1, "NonApprovedAllowlist")
    release = value[88:120].rstrip(b"\0")
    require(bool(release) and all(32 <= c <= 126 for c in release) and
            value[88:120] == release.ljust(32, b"\0"), "ReleaseId")
    require(value[40:88] == identity_hash, "IdentityMismatch")
    if previous is not None:
        require(len(previous) == 320, "PreviousAllowlist")
        verify_signature(signer.public_key(), previous[224:], previous[:224], "PreviousAllowlist")
        require(previous[168:216] == root_id, "PreviousAllowlist")
        sequence, old = struct.unpack_from("<Q", value, 8)[0], struct.unpack_from("<Q", previous, 8)[0]
        require(sequence >= old, "SequenceRollback")
        require(sequence != old or value[:224] == previous[:224], "SequenceContentConflict")


def verify_platform(report):
    require(report[0x22D] >= 1, "ArgBelowFloor")
    require(all(component >= 1 for component in report[0x38:0x3B]), "TcbBelowFloor")
    require(all(component >= 1 for component in report[0x220:0x22E]), "EtcbBelowFloor")
    require(struct.unpack_from("<Q", report, 0x200)[0] & 1 == 1, "MitigationBelowFloor")


def verify_history(report, value, previous=None, expected_ma_id=SOURCE_ID):
    require(report[0x140:0x160] == TENANT_ID and report[0x160:0x180] == expected_ma_id,
            "TenantMaBinding")
    if value[148]:
        require(value[156:] == expected_history(report, previous), "HistoryMismatch")


def verify_case(directory, case):
    require(case.get("trust", "fixture") == "fixture", "FixtureTrustRejected")
    require(case.get("provider", "fixture-oracle") == "fixture-oracle", "FixtureProfileRejected")
    now = case.get("now", 100)
    _, leaf = chain(directory, "certificates/vcek.der", now)
    report = read(directory, case["report"])
    context = expected_context(directory, case["purpose"], case["role"]) if case["kind"] == "ma" else None
    verify_report(report, leaf.public_key(), case["kind"],
                  sha(context) + bytes(16) if context else bytes(64))
    value = read(directory, case["supplement"])
    verify_supplement(report, value, read(directory, case["signature"]), leaf.public_key())
    if case["kind"] == "tenant":
        previous = bytes.fromhex(case["previous_history"]) if "previous_history" in case else None
        verify_history(report, value, previous,
                       bytes.fromhex(case.get("expected_ma_id", SOURCE_ID.hex())))
        return
    require(report[0x140:0x160] == (SOURCE_ID if case["role"] == 0 else DESTINATION_ID),
            "MaRoleIdentity")
    verify_platform(report)
    policy_hash = sha(b"SNP-LM-POLICY-v1" + struct.pack("<I", len(POLICY)) + POLICY)
    require(bytes.fromhex(case.get("envelope_policy_digest", policy_hash.hex())) == policy_hash,
            "PolicyDigestMismatch")
    actual = identity_input(report)
    require(actual == read(directory, "identity/input.bin"), "IdentityMismatch")
    identity_hash = sha(b"SNP-MA-POLICY-IDENTITY-v1" + actual)
    verify_allowlist(directory, read(directory, case["allowlist"]), identity_hash, now,
                     case.get("authorization_leaf", "certificates/authorization.der"),
                     case.get("authorization_root", "certificates/ark.der"))


def verify_package(directory):
    manifest = read_json(directory, "manifest.json")
    require(manifest["format"] == "Task6SyntheticVeniceV6-v1" and
            manifest["trust"] == "fixture-only" and
            manifest["evidence_profile"] == "SnpEmulatorV1" and
            manifest["common_adapter_qualified"] is False and
            manifest["certificate_profile"] == "Task6FixtureP384V1" and not manifest["vlek"],
            "ManifestProfile")
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "SymlinkAsset")
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    require(actual == set(manifest["files"]) | {"manifest.json"}, "ManifestMembership")
    for name, metadata in manifest["files"].items():
        value = read(directory, name)
        require(len(value) == metadata["size"] and
                hashlib.sha256(value).hexdigest() == metadata["sha256"] and
                sha(value).hex() == metadata["sha384"], "ManifestHash")
    require(manifest["preserved_sha256"] == PRESERVED, "PreservationBaseline")
    for name, expected in PRESERVED.items():
        require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, "PreservationHash")
    require(read(directory, "policy/canonical.json") == POLICY, "FixturePolicyModel")
    certificate_bytes = [read(directory, f"certificates/{name}.der") for name in ("vcek", "ask", "ark")]
    encoded_chain = b"SNP-CERT-CHAIN-v1"
    for certificate in certificate_bytes:
        encoded_chain += struct.pack("<I", len(certificate)) + certificate
    require(manifest["certificate_chain_sha384"] == sha(encoded_chain).hex(), "CertificateChainDigest")
    root = x509.load_der_x509_certificate(certificate_bytes[2])
    spki = root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(manifest["authorization_root_id_sha384"] == sha(spki).hex(), "AuthorizationRootId")
    require(manifest["ma_policy_identity_digest_sha384"] ==
            sha(b"SNP-MA-POLICY-IDENTITY-v1" + read(directory, "identity/input.bin")).hex(),
            "ManifestIdentityDigest")
    catalogue = read_json(directory, "case-catalogue.json")
    cases = catalogue["cases"]
    require(len({case["name"] for case in cases}) == len(cases) and
            {case["group"] for case in cases} == set(range(1, 20)), "CoverageGroups")
    counts = manifest["counts"]
    require(counts == {
        "reports": sum(name.startswith("reports/") for name in manifest["files"]),
        "certificates": sum(name.startswith("certificates/") for name in manifest["files"]),
        "private_key_roles": 6, "groups": 19,
        "positive_cases": sum(case["expected"] == "OK" for case in cases),
        "negative_cases": sum(case["expected"] != "OK" for case in cases),
        "cases": len(cases), "payload_files": len(manifest["files"]),
    }, "ManifestCounts")
    for case in cases:
        outcome = "OK"
        try:
            verify_case(directory, case)
        except FixtureError as exc:
            outcome = exc.code
        require(outcome == case["expected"], f"CaseOutcome:{case['name']}:{outcome}")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=pathlib.Path, default=DEFAULT)
    args = parser.parse_args()
    print("Task6 independent fixture oracle PASS:", json.dumps(verify_package(args.directory), sort_keys=True))


if __name__ == "__main__":
    main()
