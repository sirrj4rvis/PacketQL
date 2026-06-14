"""The locked PacketRecord schema — the contract every module depends on.

All fields are integers stored fixed-width on disk (see storage). IPs are
**uint32**, not strings: 4 bytes instead of ~11, and integer compares /
prefix-matching are O(1). ``protocol`` is the raw IANA number; ``tcp_flags`` is
the raw TCP flags byte; ``size`` is the IP-layer total length.
"""

from __future__ import annotations

from dataclasses import dataclass

# -- protocol numbers (IANA) -------------------------------------------------
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_NAMES = {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}

# -- TCP flag bits -----------------------------------------------------------
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
_FLAG_NAMES = [(URG, "URG"), (ACK, "ACK"), (PSH, "PSH"), (RST, "RST"), (SYN, "SYN"), (FIN, "FIN")]


@dataclass(frozen=True)
class PacketRecord:
    """One parsed IPv4 packet, flattened to fixed-width integer fields."""

    timestamp: float    # Unix epoch, microsecond precision
    src_ip: int         # uint32
    dst_ip: int         # uint32
    src_port: int       # uint16 (0 for ICMP)
    dst_port: int       # uint16 (0 for ICMP)
    protocol: int       # uint8: 6=TCP, 17=UDP, 1=ICMP
    size: int           # IP total length, in bytes
    tcp_flags: int      # uint8 bitmask (0 for non-TCP)
    ttl: int            # uint8


def ip_to_int(addr: str) -> int:
    a, b, c, d = (int(x) for x in addr.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def int_to_ip(value: int) -> str:
    return f"{(value >> 24) & 255}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}"


def proto_name(protocol: int) -> str:
    return PROTO_NAMES.get(protocol, f"IP-{protocol}")


def flags_str(flags: int) -> str:
    return "|".join(name for bit, name in _FLAG_NAMES if flags & bit) or "-"
