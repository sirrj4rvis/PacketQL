"""Read (and write, for test fixtures) the classic libpcap capture-file format.

A ``.pcap`` file is dead simple, which is why we parse it ourselves instead of
pulling in a library:

    +-----------------------------+
    | global header  (24 bytes)   |   magic, version, snaplen, link type
    +-----------------------------+
    | record header  (16 bytes)   |   timestamp + captured/original length
    | packet bytes   (incl_len)   |   the frame exactly as it left the wire
    +-----------------------------+
    | record header  (16 bytes)   |
    | packet bytes   ...          |
    +-----------------------------+
    | ...                         |

We only read the *raw bytes* of each packet here; decoding Ethernet/IP/TCP from
those bytes is the parser's job (``parser.py``). Keeping the two separate means
the live-capture path (Phase 5) can feed the same parser without going through a
file at all.

Scope: little-endian, microsecond-resolution, Ethernet link type — the format
``tcpdump``/Wireshark write by default. Big-endian and nanosecond variants and
the newer pcapng format are out of scope (documented).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

#: global header: magic, version_major, version_minor, thiszone, sigfigs,
#: snaplen, network (all little-endian; thiszone is signed).
_GLOBAL = struct.Struct("<IHHiIII")
#: per-packet record header: ts_sec, ts_usec, incl_len, orig_len.
_RECORD = struct.Struct("<IIII")

_MAGIC_LE_USEC = 0xA1B2C3D4  # little-endian, microsecond timestamps
LINKTYPE_ETHERNET = 1


@dataclass(frozen=True)
class RawPacket:
    """One captured frame: a timestamp plus the raw bytes off the wire.

    ``orig_len`` is the packet's true length on the wire; ``data`` may be
    shorter if the capture used a small snap length. ``size`` reports the wire
    length, which is what a query means by a packet's "size".
    """

    ts_sec: int
    ts_usec: int
    orig_len: int
    data: bytes

    @property
    def timestamp(self) -> float:
        return self.ts_sec + self.ts_usec / 1_000_000


def read_packets(path: str) -> list[RawPacket]:
    """Read every packet from a ``.pcap`` file at ``path``.

    Raises ``ValueError`` on a file that is not a little-endian microsecond
    Ethernet pcap. A truncated trailing record is dropped (it was never fully
    written), mirroring how real tools tolerate an interrupted capture.
    """
    with open(path, "rb") as f:
        header = f.read(_GLOBAL.size)
        if len(header) < _GLOBAL.size:
            raise ValueError("file is too short to be a pcap")
        magic, _vmaj, _vmin, _tz, _sig, _snaplen, network = _GLOBAL.unpack(header)
        if magic != _MAGIC_LE_USEC:
            raise ValueError(
                f"unsupported pcap byte order/format (magic {magic:#010x}); "
                "expected little-endian microsecond pcap"
            )
        if network != LINKTYPE_ETHERNET:
            raise ValueError(f"unsupported link type {network} (only Ethernet=1)")

        packets: list[RawPacket] = []
        while True:
            rec = f.read(_RECORD.size)
            if len(rec) < _RECORD.size:
                break  # clean end of file (or a torn header) -> stop
            ts_sec, ts_usec, incl_len, orig_len = _RECORD.unpack(rec)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break  # truncated final record -> drop it
            packets.append(RawPacket(ts_sec, ts_usec, orig_len, data))
        return packets


def write_packets(path: str, packets: Iterator[RawPacket], snaplen: int = 65535) -> None:
    """Write packets to a ``.pcap`` file. Used to build test/sample fixtures."""
    with open(path, "wb") as f:
        f.write(_GLOBAL.pack(_MAGIC_LE_USEC, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET))
        for p in packets:
            f.write(_RECORD.pack(p.ts_sec, p.ts_usec, len(p.data), p.orig_len))
            f.write(p.data)
