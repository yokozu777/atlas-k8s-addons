#!/usr/bin/env python3
"""Fail unless BIND accepts a TSIG key. The probe does not change records."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

_TSIG_ERROR = {
    16: "bad authentication",
    17: "bad authentication",
    18: "bad time",
}
_RCODE = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    9: "NOTAUTH",
}


def encode_name(name: str) -> bytes:
    text = name.strip().rstrip(".").lower()
    if not text:
        return b"\x00"
    out = bytearray()
    for label in text.split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label in {name!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_update(zone: str, keyname: str, secret: bytes, now: int, msgid: int) -> bytes:
    """UPDATE that only requires the zone SOA to exist, signed with HMAC-SHA256."""
    flags = 0x2800
    header = struct.pack("!HHHHHH", msgid, flags, 1, 1, 0, 0)
    question = encode_name(zone) + struct.pack("!HH", 6, 1)
    prerequisite = encode_name(zone) + struct.pack("!HHIH", 6, 255, 0, 0)
    unsigned = header + question + prerequisite
    algorithm = encode_name("hmac-sha256")
    upper = (now >> 32) & 0xFFFF
    lower = now & 0xFFFFFFFF
    fudge = 300
    time_encoded = struct.pack("!HIH", upper, lower, fudge)
    mac_data = (
        struct.pack("!H", msgid)
        + unsigned[2:]
        + encode_name(keyname)
        + struct.pack("!HI", 255, 0)
        + algorithm
        + time_encoded
        + struct.pack("!HH", 0, 0)
    )
    mac = hmac.new(secret, mac_data, hashlib.sha256).digest()
    rdata = (
        algorithm
        + time_encoded
        + struct.pack("!H", len(mac))
        + mac
        + struct.pack("!HHH", msgid, 0, 0)
    )
    tsig = encode_name(keyname) + struct.pack("!HHIH", 250, 255, 0, len(rdata)) + rdata
    signed_header = struct.pack("!HHHHHH", msgid, flags, 1, 1, 0, 1)
    return signed_header + unsigned[12:] + tsig


def rejection_reason(response: bytes) -> str | None:
    if len(response) < 12:
        return "short DNS response"
    rcode = response[3] & 0x0F
    if rcode == 0:
        return None
    tsig_error = None
    if len(response) >= 6:
        tsig_error = struct.unpack("!H", response[-4:-2])[0]
    detail = _TSIG_ERROR.get(tsig_error or -1)
    if detail:
        return detail
    return _RCODE.get(rcode, f"rcode {rcode}")


def query(nameserver: str, port: int, payload: bytes, timeout: float = 10) -> bytes:
    with socket.create_connection((nameserver, port), timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        prefix = _recv_exact(sock, 2)
        size = struct.unpack("!H", prefix)[0]
        return _recv_exact(sock, size)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = sock.recv(size - len(chunks))
        if not piece:
            raise ConnectionError("DNS server closed the connection")
        chunks.extend(piece)
    return bytes(chunks)


def decode_secret(raw: str) -> bytes:
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    if not text:
        raise ValueError("TSIG secret is empty")
    try:
        secret = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("TSIG secret is not valid base64") from exc
    if not secret:
        raise ValueError("TSIG secret is empty")
    return secret


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(
            "usage: check_tsig.py <nameserver> <port> <zone> <keyname>",
            file=sys.stderr,
        )
        return 2
    nameserver, port_text, zone, keyname = argv[1:]
    try:
        port = int(port_text)
        secret = decode_secret(os.environ.get("ATLAS_TSIG_SECRET", ""))
        payload = build_update(zone, keyname, secret, int(time.time()), msgid=0x1A2B)
        response = query(nameserver, port, payload)
    except Exception as exc:
        print(
            f"TSIG key {keyname} check against {nameserver}:{port_text} for zone {zone} failed: {exc}",
            file=sys.stderr,
        )
        return 1
    reason = rejection_reason(response)
    if reason:
        print(
            f"TSIG key {keyname} rejected by {nameserver}:{port_text} for zone {zone}: {reason}",
            file=sys.stderr,
        )
        return 1
    print(f"TSIG key {keyname} accepted for zone {zone} at {nameserver}:{port_text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
