"""Generate a small, deterministic ``data/sample.pcap`` for offline development.

We hand-build a handful of Ethernet/IP/TCP and Ethernet/IP/UDP frames with known
fields and write them in pcap format. This needs no admin rights and no capture
device, and it doubles as the inverse of the parser (handy as a test fixture):
craft known packets here, then assert the parser recovers them.

Run:  python tools/make_sample_pcap.py
"""

from __future__ import annotations

import os
import struct
import sys

# make the packetql package importable when run as a script from anywhere
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from packetql.capture.pcap import RawPacket, write_packets  # noqa: E402

_SRC_MAC = "aa:bb:cc:00:00:01"
_DST_MAC = "aa:bb:cc:00:00:02"


def _mac(s: str) -> bytes:
    return bytes(int(b, 16) for b in s.split(":"))


def _ip(s: str) -> bytes:
    return bytes(int(o) for o in s.split("."))


def _eth(ethertype: int = 0x0800) -> bytes:
    return _mac(_DST_MAC) + _mac(_SRC_MAC) + struct.pack("!H", ethertype)


def _ipv4(src: str, dst: str, proto: int, l4_len: int, ttl: int = 64) -> bytes:
    total = 20 + l4_len
    # ver/IHL, DSCP, total_len, id, flags/frag, ttl, proto, checksum(0), src, dst
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, ttl, proto, 0,
                       _ip(src), _ip(dst))


def _tcp(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    off_flags = (5 << 12) | flags  # data offset 5 words (20 B) + flags (PSH|ACK)
    return struct.pack("!HHIIHHHH", sport, dport, 0, 0, off_flags, 65535, 0, 0) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


# (src_ip, dst_ip, ip_proto, l4 bytes) — a realistic little mix
_FLOWS = [
    ("192.168.1.10", "93.184.216.34", 6, _tcp(51514, 443, b"\x00" * 100)),   # HTTPS small
    ("192.168.1.10", "93.184.216.34", 6, _tcp(51515, 443, b"\x00" * 1460)),  # HTTPS large
    ("192.168.1.20", "10.0.0.5", 6, _tcp(40000, 80, b"\x00" * 200)),         # HTTP
    ("192.168.1.20", "10.0.0.5", 6, _tcp(40001, 80, b"\x00" * 1500)),        # HTTP large
    ("192.168.1.10", "8.8.8.8", 17, _udp(50000, 53, b"\x00" * 40)),          # DNS query
    ("8.8.8.8", "192.168.1.10", 17, _udp(53, 50000, b"\x00" * 120)),         # DNS reply
    ("192.168.1.30", "192.168.1.10", 6, _tcp(22, 55000, b"\x00" * 80)),      # SSH
    ("192.168.1.10", "224.0.0.251", 17, _udp(5353, 5353, b"\x00" * 60)),     # mDNS
]


def build() -> list[RawPacket]:
    packets = []
    ts0 = 1_700_000_000
    for i, (src, dst, proto, l4) in enumerate(_FLOWS):
        frame = _eth() + _ipv4(src, dst, proto, len(l4)) + l4
        packets.append(RawPacket(ts0 + i, i * 1000, len(frame), frame))
    # one non-IPv4 frame (ARP, ethertype 0x0806) so the parser's non-IP path and
    # the columnar null bitmap (no IPs/ports/ttl) both get exercised.
    arp = _eth(0x0806) + b"\x00" * 28
    packets.append(RawPacket(ts0 + len(_FLOWS), 0, len(arp), arp))
    return packets


def main() -> None:
    out_dir = os.path.join(ROOT, "data")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "sample.pcap")
    packets = build()
    write_packets(out, packets)
    print(f"wrote {len(packets)} packets to {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
