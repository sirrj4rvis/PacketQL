"""Pure-Python packet parser: raw bytes -> PacketRecord. No scapy.

Decodes Ethernet II -> IPv4 -> TCP/UDP/ICMP by hand, and **verifies the IPv4
header checksum** (one's-complement sum), discarding packets that fail — the
same integrity check Wireshark performs. Non-IPv4 frames, truncated frames, and
bad-checksum frames are dropped (``parse_packet`` returns ``None``).

Checksum verification is on by default for offline ``.pcap`` parsing (where a bad
checksum really means a corrupt frame). LIVE capture disables it: with NIC
transmit checksum offload, the host's own *outbound* packets are handed to the
card with a blank IP checksum and captured before the card fills it in, so a
strict check would silently drop all outgoing traffic. Wireshark turns checksum
validation off by default for exactly this reason.

Header layouts:
    Ethernet (14 B): dst MAC(6) | src MAC(6) | ethertype(2)
    IPv4 (20 B+):    ver/IHL(1) | TOS(1) | total_len(2) | id(2) | flags/frag(2)
                     | TTL(1) | proto(1) | checksum(2) | src(4) | dst(4)
    TCP (20 B+):     src port(2) | dst port(2) | seq(4) | ack(4)
                     | data-offset(1) | flags(1) | ...
    UDP (8 B):       src port(2) | dst port(2) | len(2) | checksum(2)
"""

from __future__ import annotations

import struct

from packetql.capture.pcap import read_packets
from packetql.schema import PROTO_TCP, PROTO_UDP, PacketRecord

_ETH = struct.Struct("!6s6sH")
_ETHERTYPE_IPV4 = 0x0800
_IP = struct.Struct("!BBHHHBBH4s4s")   # through src/dst addresses
_PORTS = struct.Struct("!HH")


def verify_ip_checksum(header: bytes) -> bool:
    """One's-complement check of an IPv4 header (incl. its checksum field).

    Summing all 16-bit words of a valid header folds to 0xFFFF.
    """
    if len(header) % 2:
        header = header + b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def parse_packet(data: bytes, timestamp: float, verify_checksum: bool = True) -> PacketRecord | None:
    """Decode one Ethernet frame into a PacketRecord, or None to discard it.

    ``verify_checksum`` defaults to True (offline ``.pcap``: a bad IP-header
    checksum means a corrupt frame, so drop it). Live capture passes False —
    NIC checksum offload blanks the checksum on the host's own outbound packets,
    so verifying would drop all outgoing traffic (see the module docstring).
    """
    if len(data) < _ETH.size:
        return None
    _dst_mac, _src_mac, ethertype = _ETH.unpack_from(data, 0)
    if ethertype != _ETHERTYPE_IPV4:
        return None                              # IPv4 only (the schema is uint32 IPs)

    off = _ETH.size
    if len(data) < off + 20:
        return None
    ver_ihl = data[off]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < off + ihl:
        return None
    if verify_checksum and not verify_ip_checksum(data[off:off + ihl]):
        return None                              # corrupt header -> discard (offline path)

    _v, _tos, total_len, _id, _ff, ttl, proto, _csum, src, dst = _IP.unpack_from(data, off)
    src_ip = int.from_bytes(src, "big")
    dst_ip = int.from_bytes(dst, "big")

    l4 = off + ihl
    src_port = dst_port = tcp_flags = 0
    if proto == PROTO_TCP and len(data) >= l4 + 14:
        src_port, dst_port = _PORTS.unpack_from(data, l4)
        tcp_flags = data[l4 + 13]                # byte 13 of the TCP header
    elif proto == PROTO_UDP and len(data) >= l4 + 8:
        src_port, dst_port = _PORTS.unpack_from(data, l4)
    # ICMP (and other IP protocols): no ports, flags 0.

    return PacketRecord(timestamp, src_ip, dst_ip, src_port, dst_port, proto, total_len, tcp_flags, ttl)


def parse_file(path: str) -> list[PacketRecord]:
    """Read a .pcap and parse it, dropping packets the parser discards."""
    out = []
    for raw in read_packets(path):
        rec = parse_packet(raw.data, raw.timestamp)
        if rec is not None:
            out.append(rec)
    return out
