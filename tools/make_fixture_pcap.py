"""Generate tests/fixtures/sample.pcap — a small, deterministic capture with
**valid IP checksums** plus one deliberately corrupt packet, so the parser's
checksum verification can be tested. Committed to the repo for deterministic
testing.

Run:  python tools/make_fixture_pcap.py
"""

from __future__ import annotations

import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from packetql.capture.pcap import RawPacket, write_packets  # noqa: E402
from packetql.schema import ACK, FIN, PSH, SYN  # noqa: E402

_SRC_MAC = bytes.fromhex("aabbcc000001")
_DST_MAC = bytes.fromhex("aabbcc000002")


def _ip_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _eth() -> bytes:
    return _DST_MAC + _SRC_MAC + struct.pack("!H", 0x0800)


def _ipv4(src: str, dst: str, proto: int, l4_len: int, ttl: int, corrupt: bool = False) -> bytes:
    total = 20 + l4_len
    zero = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, ttl, proto, 0, _ip(src), _ip(dst))
    csum = _ip_checksum(zero)
    if corrupt:
        csum ^= 0xFFFF                       # flip every bit -> guaranteed wrong
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, ttl, proto, csum, _ip(src), _ip(dst))


def _tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload


def _udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp(typ: int, code: int, payload: bytes = b"") -> bytes:
    return struct.pack("!BBHHH", typ, code, 0, 1, 1) + payload


def build() -> list[RawPacket]:
    frames = [
        # TCP three-way handshake to an HTTPS server
        _eth() + _ipv4("192.168.0.2", "93.184.216.34", 6, 20, 64) + _tcp(51000, 443, SYN),
        _eth() + _ipv4("93.184.216.34", "192.168.0.2", 6, 20, 55) + _tcp(443, 51000, SYN | ACK),
        _eth() + _ipv4("192.168.0.2", "93.184.216.34", 6, 120, 64) + _tcp(51000, 443, PSH | ACK, b"\x00" * 100),
        # a DNS query (UDP) and an ICMP echo request
        _eth() + _ipv4("192.168.0.2", "8.8.8.8", 17, 38, 64) + _udp(50000, 53, b"\x00" * 30),
        _eth() + _ipv4("192.168.0.2", "192.168.0.1", 1, 40, 64) + _icmp(8, 0, b"\x00" * 32),
        # a TCP FIN with a CORRUPT IP checksum -> the parser must discard this one
        _eth() + _ipv4("192.168.0.2", "93.184.216.34", 6, 20, 64, corrupt=True) + _tcp(51000, 443, FIN | ACK),
    ]
    return [RawPacket(1_700_000_000 + i, i * 1000, len(f), f) for i, f in enumerate(frames)]


def main() -> None:
    out_dir = os.path.join(ROOT, "tests", "fixtures")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "sample.pcap")
    packets = build()
    write_packets(out, packets)
    print(f"wrote {len(packets)} packets ({sum(1 for _ in packets)} frames, 1 corrupt) "
          f"to {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
