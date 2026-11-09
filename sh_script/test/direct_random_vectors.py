#!/usr/bin/env python3
"""Independent stdlib V2 reference corpus; no signing or runtime authority."""

import argparse
import hashlib
import pathlib
import struct


def digest(value):
    return hashlib.sha384(value).digest()


def vectors():
    request = 0x0102030405060708
    tenant = bytearray(1184)
    tenant[:4] = struct.pack("<I", 6)
    tenant[0x30:0x34] = struct.pack("<I", 0xFFFFFFFF)
    tenant[0x140:0x160] = bytes([0x33]) * 32
    tenant[0x160:0x180] = bytes([0x11]) * 32
    tenant_digest = digest(
        b"SNP-LM-TENANT-EVIDENCE-v1"
        + struct.pack("<HI", 1, 1184)
        + tenant
        + bytes(8)
    )
    common = struct.pack("<QHH", request, 1, 3) + bytes([0x33]) * 32
    binding = digest(
        b"SNP-LM-SESSION-BIND-v2" + common + tenant_digest + bytes([0x44]) * 48
    )
    source_context = (
        b"AMD-SNP-MA-LM-REPORT-DATA-V1"
        + struct.pack("<HBB", 1, 6, 0)
        + common
        + bytes([0x44]) * 48
        + binding
        + bytes([0x77]) * 48
    )
    authorization = (
        b"SNP-LM-TENANT-AUTH-v2"
        + struct.pack("<H", 2)
        + struct.pack("<QHHBB", request, 1, 3, 0, 1)
        + bytes([0x33]) * 32
        + tenant_digest
        + bytes([0x44]) * 48
        + bytes([0x11]) * 32
        + bytes([0x22]) * 32
        + bytes([0x77]) * 48
        + bytes([0x88]) * 48
    )
    history = bytes([1, 3]) + bytes(62)
    session = (
        b"SNP-LM-SESSION-v2"
        + struct.pack("<H", 2)
        + authorization
        + bytes([10]) * 48
        + bytes([11]) * 48
        + bytes([12]) * 48
        + history
        + struct.pack("<HHBH", 1, 1, 3, 1)
        + bytes([13]) * 48
        + bytes([14]) * 48
        + bytes(48)
    )
    assert len(source_context) == 220
    assert len(authorization) == 325
    assert len(session) == 703
    reference = struct.pack("<Q", request) + digest(session)

    def header(magic, kind, size):
        return magic + struct.pack("<HHI", 2, kind, size)

    return {
        "tenant_digest": tenant_digest,
        "session_binding": binding,
        "source_context": source_context,
        "source_report_data": digest(source_context) + bytes(16),
        "authorization": authorization,
        "authorization_digest": digest(authorization),
        "session_preimage": session,
        "session_digest": digest(session),
        "key_delivery": header(b"SNP-LM-K", 10, 168) + reference + bytes([0x42]) * 32 + history,
        "acceptance": header(b"SNP-LM-A", 11, 80) + reference + bytes([1, 1]) + bytes(6),
        "poll": header(b"SNP-LM-Q", 13, 80) + reference + bytes([1]) + bytes(7),
        "destination_completion": header(b"SNP-LM-F", 12, 88) + reference + bytes([1, 1, 1, 1]) + bytes(12),
        "source_completion": header(b"SNP-LM-F", 12, 88) + reference + bytes([0, 1, 1, 1]) + bytes(12),
        "acknowledgement": header(b"SNP-LM-Q", 13, 80) + reference + bytes([2]) + bytes(7),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate V2 corpus; never modifies P0.10 history")
    args = parser.parse_args()
    path = pathlib.Path(__file__).resolve().parents[2] / "src/pal/src/snp/test_data/direct_random_v2.txt"
    expected = "# Independent direct-random V2 fixtures; public deterministic test values only.\n"
    expected += "".join(f"{key} {value.hex()}\n" for key, value in vectors().items())
    if args.write:
        path.write_text(expected, encoding="ascii")
    elif path.read_text(encoding="ascii") != expected:
        raise SystemExit("V2 reference corpus mismatch")
    print("V2 reference corpus matches independent SHA384/struct reference")


if __name__ == "__main__":
    main()
