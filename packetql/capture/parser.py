"""Hand-decode a raw frame into a typed ``Packet`` — the Networks core.

We walk the nested headers ourselves rather than letting a library do it, since
understanding the byte layout is the whole point:

    Ethernet (14 B)  | dst MAC(6) | src MAC(6) | ethertype(2)            |
       IPv4 (20 B+)  | ver/IHL(1) | ... | TTL(1) | proto(1) | src(4) | dst(4) |
          TCP (20 B+)| src port(2)| dst port(2)| ...                    |
          UDP (8 B)  | src port(2)| dst port(2)| len(2) | csum(2)       |

Multi-byte fields in a packet are big-endian ("network byte order"), so we
unpack them with ``!`` — note this is the opposite of the pcap *file* header,
which is little-endian.

A frame that is not IPv4, or whose L4 protocol is not TCP/UDP, still yields a
``Packet`` (with a descriptive ``protocol`` and ``None`` ports) so nothing is
silently dropped.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .pcap import RawPacket

_ETH = struct.Struct("!6s6sH")  # dst MAC, src MAC, ethertype
_ETHERTYPE_IPV4 = 0x0800
_PROTO_TCP, _PROTO_UDP, _PROTO_ICMP = 6, 17, 1
_PORTS = struct.Struct("!HH")   # src port, dst port (first 4 bytes of TCP and UDP)


@dataclass(frozen=True)
class Packet:
    """A parsed packet, flattened to the fields a query cares about."""

    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    protocol: str               # "TCP" | "UDP" | "ICMP" | "IP-<n>" | "ETH-0x...."
    src_port: int | None
    dst_port: int | None
    size: int                   # length on the wire, in bytes
    ttl: int | None


def _ipv4(addr: bytes) -> str:
    return ".".join(str(b) for b in addr)


def parse_packet(raw: RawPacket) -> Packet:
    """Decode one captured frame into a ``Packet``."""
    data = raw.data
    ts = raw.timestamp
    size = raw.orig_len

    if len(data) < _ETH.size:
        return Packet(ts, None, None, "TRUNCATED", None, None, size, None)

    _dst_mac, _src_mac, ethertype = _ETH.unpack_from(data, 0)
    if ethertype != _ETHERTYPE_IPV4:
        return Packet(ts, None, None, f"ETH-0x{ethertype:04x}", None, None, size, None)

    ip_off = _ETH.size
    if len(data) < ip_off + 20:
        return Packet(ts, None, None, "TRUNCATED-IP", None, None, size, None)

    ver_ihl = data[ip_off]
    ihl = (ver_ihl & 0x0F) * 4          # IPv4 header length, in bytes (usually 20)
    ttl = data[ip_off + 8]
    proto = data[ip_off + 9]
    src_ip = _ipv4(data[ip_off + 12:ip_off + 16])
    dst_ip = _ipv4(data[ip_off + 16:ip_off + 20])
    l4_off = ip_off + ihl

    if proto in (_PROTO_TCP, _PROTO_UDP) and len(data) >= l4_off + 4:
        src_port, dst_port = _PORTS.unpack_from(data, l4_off)
        name = "TCP" if proto == _PROTO_TCP else "UDP"
        return Packet(ts, src_ip, dst_ip, name, src_port, dst_port, size, ttl)
    if proto == _PROTO_ICMP:
        return Packet(ts, src_ip, dst_ip, "ICMP", None, None, size, ttl)
    return Packet(ts, src_ip, dst_ip, f"IP-{proto}", None, None, size, ttl)


def parse_file(path: str) -> list[Packet]:
    """Convenience: read a ``.pcap`` and parse every packet in it."""
    from .pcap import read_packets
    return [parse_packet(p) for p in read_packets(path)]
