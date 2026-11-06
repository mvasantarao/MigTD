#!/usr/bin/env python3
# Copyright (c) 2026 Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Independent P0.10 fixture oracle. All keys/secrets are public TEST ONLY.

Requires Python cryptography with deterministic ECDSA certificate signing.
Default checks the committed corpus; --write regenerates it deterministically.
No runtime input, production trust anchor or production report is accepted.
"""

import argparse
import datetime
import hashlib
import hmac
import pathlib
import struct

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier


OUTPUT = pathlib.Path(__file__).resolve().parents[2] / "src/pal/src/snp/test_data/p010_vectors.txt"
REQUEST = 0x0102030405060708
PURPOSE = "1.3.6.1.4.1.55555.162.1"  # Fixture-only EKU, not a production assignment.
UTC = datetime.timezone.utc


def u16(value):
    return struct.pack("<H", value)


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def sha(*parts):
    return hashlib.sha384(b"".join(parts)).digest()


def mac(key, message):
    return hmac.digest(key, message, "sha384")


def expand(prk, info, length):
    previous, output = b"", b""
    for counter in range(1, (length + 47) // 48 + 1):
        previous = mac(prk, previous + info + bytes([counter]))
        output += previous
    return output[:length]


def fixed_signature(key, message):
    der = key.sign(message, ec.ECDSA(hashes.SHA384(), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(48, "big") + s.to_bytes(48, "big")


def verify_fixed(key, message, signature):
    assert len(signature) == 96
    key.verify(
        utils.encode_dss_signature(int.from_bytes(signature[:48], "big"),
                                   int.from_bytes(signature[48:], "big")),
        message, ec.ECDSA(hashes.SHA384()))


def certificate(key, name, issuer, issuer_key, serial, ca, purpose=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "P010 TEST ONLY " + name)])
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(subject if issuer is None else issuer.subject)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(datetime.datetime.fromtimestamp(10, UTC))
               .not_valid_after(datetime.datetime.fromtimestamp(200, UTC))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if issuer is None else 0)
                              if ca else x509.BasicConstraints(ca=False, path_length=None), True)
               .add_extension(x509.KeyUsage(
                   digital_signature=not ca, content_commitment=False, key_encipherment=False,
                   data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                   crl_sign=ca, encipher_only=False, decipher_only=False), True))
    if purpose is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ObjectIdentifier(purpose)]), False)
    return builder.sign(issuer_key, hashes.SHA384(), ecdsa_deterministic=True)


def validate_chain(root, ask, leaf, now, purpose=None):
    for cert in (root, ask, leaf):
        assert cert.not_valid_before_utc.timestamp() <= now <= cert.not_valid_after_utc.timestamp()
    for parent, child in ((root, root), (root, ask), (ask, leaf)):
        assert parent.subject == child.issuer
        parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
                                   ec.ECDSA(hashes.SHA384()))
    for cert in (root, ask):
        assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        assert cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    if purpose:
        assert ObjectIdentifier(purpose) in leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value


def rejects(action):
    try:
        action()
    except (AssertionError, InvalidSignature):
        return
    raise AssertionError("negative unexpectedly succeeded")


def context(purpose, role, binding, identity):
    local = purpose >= 4
    algorithm = 0 if purpose == 5 else 4 if purpose == 4 else 3
    result = (b"AMD-SNP-MA-LM-REPORT-DATA-V1" + u16(1) + bytes([purpose, role])
              + u64(REQUEST) + u16(1) + u16(algorithm)
              + (bytes(32) if local else bytes([0x77]) * 32)
              + (bytes(48) if purpose == 5 else bytes([0x88]) * 48)
              + binding + identity)
    assert len(result) == 220
    return result


def report(role, report_data, vcek_key):
    out = bytearray(1184)
    out[:8] = u32(6) + u32(7)
    out[8:16] = u64(0x1234)
    out[0x10:0x20] = bytes([0x11]) * 16
    out[0x20:0x30] = bytes([0x22]) * 16
    out[0x30:0x34] = u32(0xFFFFFFFF if role == 2 else 0)
    out[0x34:0x38] = u32(1)
    out[0x38:0x40] = bytes([2, 2, 2, 0, 0, 0, 0, 0])
    out[0x48] = 1
    out[0x50:0x90] = report_data
    for start, size, value in ((0x90, 48, 0x33), (0xC0, 32, 0x44),
                               (0xE0, 48, 0x55), (0x110, 48, 0x66)):
        out[start:start + size] = bytes([value]) * size
    out[0x140:0x160] = bytes([0x77 if role == 2 else 0x11 if role == 0 else 0x22]) * 32
    if role == 2:
        out[0x160:0x180] = bytes([0x11]) * 32
    out[0x180:0x188] = bytes([2, 2, 2, 0, 0, 0, 0, 0])
    out[0x1E0:0x1E8] = bytes([2, 2, 2, 0, 0, 0, 0, 0])
    out[0x1F0:0x1F8] = bytes([9, 2, 11, 0, 0, 0, 0, 0])
    out[0x1F8:0x200] = u64(0xF0F0CCCCAAAA5555)
    out[0x200:0x208] = u64(3)
    out[0x220:0x240] = bytes([2]) * 14 + bytes(18)
    out[0x240:0x260] = bytes(range(20, 34)) + bytes(18)
    out[0x260:0x280] = bytes([2]) * 14 + bytes(18)
    return sign_report(out, vcek_key)


def sign_report(out, vcek_key):
    out = bytearray(out)
    signature = fixed_signature(vcek_key, out[:0x2A0])
    r, s = int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")
    out[0x2A0:0x2E8] = r.to_bytes(72, "little")
    out[0x2E8:0x330] = s.to_bytes(72, "little")
    return bytes(out)


def supplement(base, history, key):
    value = (u16(1) + u16(1) + sha(base) + base[0x220:0x240]
             + base[0x240:0x260] + base[0x260:0x280]
             + bytes([int(history is not None)]) + bytes(7) + (history or bytes(64)))
    assert len(value) == 220
    return value, fixed_signature(key, b"SNP-EMU-SUPPLEMENT-v1" + value)


def validate_supplement(base, value, signature, key):
    assert len(base) == 1184 and len(value) == 220
    assert base[0x48] & 0x20 == 0
    assert value[:4] == u16(1) + u16(1) and value[149:156] == bytes(7)
    verify_fixed(key, b"SNP-EMU-SUPPLEMENT-v1" + value, signature)
    assert value[4:52] == sha(base)
    assert value[52:84] == base[0x220:0x240]
    assert value[84:116] == base[0x240:0x260]
    assert value[116:148] == base[0x260:0x280]
    assert value[148] in (0, 1)
    if value[148] == 0:
        assert value[156:] == bytes(64)


def evidence_digest(domain, encoded, supp=None):
    return sha(domain, u16(2 if supp else 1), u32(len(encoded)), encoded,
               u32(220 if supp else 0), supp[0] if supp else b"",
               u32(96 if supp else 0), supp[1] if supp else b"")


def build():
    values = {}

    def put(name, value):
        assert name not in values, name
        values[name] = bytes(value)
        return values[name]

    keys = [ec.derive_private_key(i, ec.SECP384R1()) for i in range(1, 9)]
    root = certificate(keys[0], "ROOT", None, keys[0], 1, True)
    ask = certificate(keys[1], "ASK", root, keys[0], 2, True)
    vcek = certificate(keys[2], "VCEK", ask, keys[1], 3, False)
    signer = certificate(keys[3], "AUTH", ask, keys[1], 4, False, PURPOSE)
    wrong = certificate(keys[4], "WRONG PURPOSE", ask, keys[1], 5, False, PURPOSE + ".99")
    unrelated = certificate(keys[5], "UNRELATED ROOT", None, keys[5], 6, True)
    release = certificate(keys[6], "RELEASE", ask, keys[1], 7, False, PURPOSE + ".2")
    initial = certificate(keys[7], "INITIAL", ask, keys[1], 8, False, PURPOSE + ".3")
    for name, cert in (("root", root), ("ask", ask), ("vcek", vcek), ("signer", signer),
                       ("wrong_purpose", wrong), ("unrelated_root", unrelated),
                       ("release", release), ("initial", initial)):
        put(name + "_der", cert.public_bytes(serialization.Encoding.DER))
        put(name + "_sec1", cert.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    validate_chain(root, ask, signer, 100, PURPOSE)
    validate_chain(root, ask, vcek, 100)
    rejects(lambda: validate_chain(unrelated, ask, signer, 100, PURPOSE))
    rejects(lambda: validate_chain(root, ask, wrong, 100, PURPOSE))
    for now in (9, 201):
        rejects(lambda: validate_chain(root, ask, signer, now, PURPOSE))

    policy = put("policy_canonical", b'{"test_only":true}')
    policy_digest = put("policy_digest", sha(b"SNP-LM-POLICY-v1", u32(len(policy)), policy))
    identity = put("identity", u16(1) + u16(1) + u32(6) + u32(0)
                   + bytes([0x33]) * 48 + u32(7) + bytes([0x11]) * 16
                   + bytes([0x22]) * 16 + bytes([0x55]) * 48 + bytes([0x66]) * 48
                   + bytes([0x44]) * 32 + u64(0x1234) + policy_digest)
    assert len(identity) == 280
    identity_digest = put("identity_digest", sha(b"SNP-MA-POLICY-IDENTITY-v1", identity))
    root_id = put("root_id", sha(root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    subject = signer.subject.public_bytes()
    signer_id = put("signer_id", sha(b"SNP-MA-AUTH-SIGNER-v1", root_id,
                                    u32(len(subject)), subject))
    put("signer_purpose_der", signer.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage).value.public_bytes())
    signed_allowlist = (u16(1) + u16(1) + u32(320) + u64(10) + u64(20) + u64(180)
                       + u32(1) + u32(0) + identity_digest + b"test" + bytes(28)
                       + signer_id + root_id + u16(1) * 3 + u16(0))
    assert len(signed_allowlist) == 224
    allowlist = put("allowlist", signed_allowlist + fixed_signature(keys[3], signed_allowlist))
    verify_fixed(signer.public_key(), allowlist[:224], allowlist[224:])
    approval = put("fixed_approval_digest",
                   sha(b"SNP-LM-APPROVAL-v1", u16(1), allowlist))

    history = put("history_first", bytes([1, 3, 9, 2, 11]) + bytes(5)
                  + u64(0xF0F0CCCCAAAA5555) + bytes(range(20, 34)) + bytes([0x11]) * 32)
    history_next = put("history_next", bytes([1, 3, 8, 2, 10]) + bytes(5)
                       + u64(0xC0C0C0C0AAAA0505)
                       + bytes(10 + i if i % 2 == 0 else 20 + i for i in range(14))
                       + bytes([0x11]) * 32)
    assert len(history) == len(history_next) == 64
    vcek_der, ask_der = values["vcek_der"], values["ask_der"]
    collateral = put("collateral", b"SNP-LM-C" + bytes([1, 0]) + u16(3)
                     + u32(40 + len(vcek_der) + len(ask_der)) + bytes([2, 3])
                     + u16(2) + u32(0) + u16(1) + u16(0) + u32(len(vcek_der)) + vcek_der
                     + u16(3) + u16(0) + u32(len(ask_der)) + ask_der)
    collateral_digest = put("collateral_digest", sha(collateral))
    tenant = put("tenant_report", report(2, bytes(64), keys[2]))
    for role in (0, 1):
        name = "source" if role == 0 else "destination"
        secret = put(name + "_secret", bytes(range(role * 32, role * 32 + 32)))
        ctx0 = put(name + "_context_zero", context(1, role, bytes(48), identity_digest))
        commitment = put(name + "_commitment", sha(b"SNP-LM-CONTRIBUTION-v1", ctx0, secret))
        ctx = put(name + "_context", context(1, role, commitment, identity_digest))
        put(name + "_report_data", sha(ctx) + bytes(16))
        base = put(name + "_report", report(role, values[name + "_report_data"], keys[2]))
        supp = supplement(base, None, keys[2])
        put(name + "_supplement", supp[0])
        put(name + "_supplement_signature", supp[1])
        validate_supplement(base, *supp, vcek.public_key())
        header = b"SNP-LM-E" + bytes([1, 0]) + u16(1) + u32(1540) + u64(REQUEST)
        header += bytes([role, 1, 2, 3]) + u32(0)
        evidence = put(name + "_ma_evidence", header + ctx + u16(1) + u16(0)
                       + u32(56) + policy_digest + collateral_digest + base)
        assert len(evidence) == 1540
        for profile, extra in (("raw", None), ("emulator", supp)):
            put(name + "_" + profile + "_evidence_digest",
                evidence_digest(b"SNP-LM-MA-EVIDENCE-v1", evidence, extra))
    for name, offset in (("measurement", 0x90), ("guest_svn", 4), ("family", 0x10),
                         ("image", 0x20), ("id_key", 0xE0), ("author_key", 0x110),
                         ("host_data", 0xC0), ("guest_policy", 8)):
        changed = bytearray(values["source_report"])
        changed[offset] ^= 1
        put("changed_" + name + "_report", sign_report(changed, keys[2]))

    tenant_supp = supplement(tenant, None, keys[2])
    put("tenant_supplement", tenant_supp[0])
    put("tenant_supplement_signature", tenant_supp[1])
    initialized = supplement(tenant, history, keys[2])
    put("tenant_initialized_supplement", initialized[0])
    put("tenant_initialized_supplement_signature", initialized[1])
    validate_supplement(tenant, *initialized, vcek.public_key())
    for name, offset in (("current_etcb", 52), ("launch_etcb", 84),
                         ("committed_etcb", 116), ("uninitialized_history", 156),
                         ("invalid_history_flag", 148)):
        changed = bytearray(tenant_supp[0])
        changed[offset] ^= 2 if name == "invalid_history_flag" else 1
        signature = fixed_signature(keys[2], b"SNP-EMU-SUPPLEMENT-v1" + changed)
        put("invalid_" + name + "_supplement", changed)
        put("invalid_" + name + "_signature", signature)
        verify_fixed(vcek.public_key(), b"SNP-EMU-SUPPLEMENT-v1" + changed, signature)
        rejects(lambda: validate_supplement(tenant, changed, signature, vcek.public_key()))
    put("legal_purpose_role_algorithm", bytes([
        1, 0, 3, 1, 1, 3, 2, 0, 3, 2, 1, 3, 3, 1, 3, 4, 2, 4, 4, 3, 4, 5, 3, 0]))
    for profile, extra in (("raw", None), ("emulator", tenant_supp)):
        put("tenant_" + profile + "_evidence_digest",
            evidence_digest(b"SNP-LM-TENANT-EVIDENCE-v1", tenant, extra))

    publisher = sha(b"P010 TEST ONLY publisher")
    key_id = sha(b"SNP-COLLATERAL-KEY-v1", values["release_sec1"])
    put("ordered_key_id", key_id)
    put("initial_key_id", sha(b"SNP-COLLATERAL-KEY-v1", values["initial_sec1"]))
    snapshot_signed = (b"SNP-MA-R" + u16(1) + u16(2) + u32(304) + publisher + key_id
                       + u64(1) + u64(10) + u64(20) + u64(180) + u32(1) + u32(0)
                       + identity_digest + u32(7) + u16(1) + u16(0))
    snapshot = put("ordered_snapshot", snapshot_signed + fixed_signature(
        keys[6], b"SNP-MA-COLLATERAL-v1" + snapshot_signed))
    initial_signed = (b"SNP-MA-H" + u16(1) + u16(2) + u32(416) + publisher
                      + values["initial_key_id"] + u64(1) + u64(10) + u64(20) + u64(180)
                      + bytes([0x77]) * 32 + bytes([0x11]) * 32 + identity_digest
                      + policy_digest + u32(7) + u32(0) + u64(10))
    initial_record = put("initial_record", initial_signed + fixed_signature(
        keys[7], b"SNP-INITIAL-MA-AUTH-v1" + initial_signed))
    assert len(snapshot) == 304 and len(initial_record) == 416
    ordered_approval = put("ordered_approval_digest", sha(b"SNP-LM-APPROVAL-v1", u16(2), snapshot))
    initial_digest = put("initial_authorization_digest", sha(b"SNP-LM-INITIAL-v1", initial_record))

    for evidence_profile in ("raw", "emulator"):
        auth = put(evidence_profile + "_authorization_context",
                   b"SNP-LM-TENANT-AUTH-v1" + u16(1) + u64(REQUEST) + u16(1) + u16(3)
                   + bytes([0, 1]) + bytes([0x77]) * 32
                   + values["tenant_" + evidence_profile + "_evidence_digest"]
                   + bytes([0x88]) * 48 + bytes([0x11]) * 32 + bytes([0x22]) * 32
                   + identity_digest * 2 + values["source_commitment"] + values["destination_commitment"])
        assert len(auth) == 421
        put(evidence_profile + "_authorization_digest", sha(auth))
    for authorization_profile in ("fixed", "ordered"):
        name = authorization_profile + "_emulator"
        app = approval if authorization_profile == "fixed" else ordered_approval
        initial_hash = bytes(48) if authorization_profile == "fixed" else initial_digest
        session = put(name + "_session_context", b"SNP-LM-SESSION-v1" + u16(1)
                      + values["emulator_authorization_context"]
                      + values["source_emulator_evidence_digest"]
                      + values["destination_emulator_evidence_digest"]
                      + collateral_digest + history + u16(1) + u16(1) + bytes([3])
                      + u16(1 if authorization_profile == "fixed" else 2) + app * 2 + initial_hash)
        assert len(session) == 799
        digest = put(name + "_session_digest", sha(session))
        salt = put(name + "_salt", sha(b"SNP-LM-HKDF-SALT-v1", digest))
        ikm = put(name + "_ikm", values["source_secret"] + values["destination_secret"])
        prk = put(name + "_prk", mac(salt, ikm))
        for key_name, label, length in (
                ("msk", b"SNP-LM-MSK-v1", 32),
                ("destination_key", b"SNP-LM-CONFIRM-DST-KEY-v1", 48),
                ("source_key", b"SNP-LM-CONFIRM-SRC-KEY-v1", 48)):
            put(name + "_" + key_name, expand(prk, label + digest, length))
        for role in (0, 1):
            direction = "source" if role == 0 else "destination"
            confirmation = put(name + "_" + direction + "_confirmation_zero",
                               b"SNP-LM-C" + bytes([1, 0]) + u16(6) + u32(128)
                               + u64(REQUEST) + bytes([role, role]) + u16(1)
                               + digest + bytes(52))
            tag = put(name + "_" + direction + "_tag",
                      mac(values[name + "_" + direction + "_key"],
                          b"SNP-LM-CONFIRM-v1" + confirmation))
            put(name + "_" + direction + "_confirmation",
                confirmation[:76] + tag + confirmation[124:])

    installation = put("installation_preimage", b"SNP-LM-INSTALLATION-RESULT-v1"
                       + u16(1) + u32(0) + u16(3) + bytes([1, 0, 0, 0]) + sha(history))
    post = put("post_install_preimage", b"SNP-LM-POST-INSTALL-v1" + u16(1)
               + u64(REQUEST) + bytes([0x77]) * 32 + bytes([0x22]) * 32
               + sha(history) + sha(installation))
    post_ctx = put("post_install_context", context(3, 1, sha(post), identity_digest))
    put("post_install_report_data", sha(post_ctx) + bytes(16))
    tenants = put("tenant_set", u32(1) + bytes([0x77]) * 32)
    result = put("firmware_result", bytes([0x77]) * 32 + u32(0) + bytes([1, 0, 0, 0])
                 + bytes([0x11]) * 32 + bytes([0x22]) * 32)
    for purpose, label in ((4, b"SNP-LM-PLANNED-HANDOFF-v1"),
                           (5, b"SNP-LM-RECOVERY-HANDOFF-v1")):
        for stage in (1, 2):
            name = ("planned" if purpose == 4 else "recovery") + ("_prepare" if stage == 1 else "_result")
            binding = put(name + "_preimage", label + u16(1) + bytes([stage, 0])
                          + u32(0) + bytes([0xAA]) * 16 + u64(REQUEST) + u64(1) + u64(180)
                          + bytes([0x11]) * 32 + bytes([0x22]) * 32
                          + sha(b"SNP-LM-TENANT-SET-v1", tenants) + identity_digest
                          + (bytes(48) if stage == 1 else sha(b"SNP-LM-REBIND-RESULT-SET-v1", u32(1), result)))
            ctx = put(name + "_context", context(purpose, 3, sha(binding), identity_digest))
            put(name + "_report_data", sha(ctx) + bytes(16))
            if purpose == 4:
                outgoing = put(name + "_outgoing_context", context(purpose, 2, sha(binding), identity_digest))
                put(name + "_outgoing_report_data", sha(outgoing) + bytes(16))

    # Mutations must be detected by real signatures or change the exact bound hash.
    for index in range(224):
        changed = bytearray(allowlist[:224])
        changed[index] ^= 1
        rejects(lambda: verify_fixed(signer.public_key(), changed, allowlist[224:]))
    for name in ("source", "destination", "tenant"):
        base, value, signature = (values[name + "_report"], values[name + "_supplement"],
                                  values[name + "_supplement_signature"])
        validate_supplement(base, value, signature, vcek.public_key())
        for index in range(220):
            changed = bytearray(value)
            changed[index] ^= 1
            rejects(lambda: validate_supplement(base, changed, signature, vcek.public_key()))
        for offset in (0x220, 0x240, 0x260):
            changed = bytearray(value)
            changed[52 + offset - 0x220] ^= 1
            resigned = fixed_signature(keys[2], b"SNP-EMU-SUPPLEMENT-v1" + changed)
            rejects(lambda: validate_supplement(base, changed, resigned, vcek.public_key()))
        changed = bytearray(value)
        changed[156] = 1
        resigned = fixed_signature(keys[2], b"SNP-EMU-SUPPLEMENT-v1" + changed)
        rejects(lambda: validate_supplement(base, changed, resigned, vcek.public_key()))
        rejects(lambda: validate_supplement(base, value, signature, signer.public_key()))
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    values = build()
    corpus = ("# P0.10 deterministic PUBLIC TEST ONLY keys/secrets; not production evidence.\n"
              "# Recipe: P0.10-InterNodeCryptoRecipeV1-2026-11-03\n"
              + "".join(name + " " + value.hex() + "\n" for name, value in sorted(values.items())))
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(corpus, encoding="ascii")
    else:
        assert OUTPUT.read_text(encoding="ascii") == corpus, "golden corpus differs; do not silently update it"
    print(f"P0.10 independent oracle: {len(values)} exact entries; cryptographic negatives passed")


if __name__ == "__main__":
    main()
