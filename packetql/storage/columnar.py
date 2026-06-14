"""Phase 2 — the columnar store.

QueryX stored *rows*: a record's fields sit together on a page. PacketQL stores
*columns*: every timestamp in one file, every src_ip in another, every size in
another. The payoff is **selective I/O** — a query for ``size`` opens only
``size.col`` and never touches the other seven columns. This is how analytical
stores (Parquet, ClickHouse) work, and it fits packet analytics, where you scan
many rows but read only a few of their fields.

Two real columnar techniques are implemented:

* **Null bitmap (validity bitmap).** Some fields are absent for some packets — a
  non-IPv4 frame has no ``src_ip``; an ICMP packet has no ports. Each nullable
  column writes a bitmap (1 bit per row, 1 = null) ahead of its values, exactly
  like Arrow/Parquet, rather than burning a sentinel value.
* **Dictionary encoding.** ``protocol`` is one of a tiny set of strings repeated
  across every row. We store each distinct string once in a dictionary and keep
  a 2-byte code per row.

On-disk layout: a store is a directory with one ``<column>.col`` file per column
plus ``meta.json`` (row count, column kinds, and the protocol dictionary).

Scope: the whole column is read and decoded into a Python list per access — fine
at this scale and enough to show the selective-I/O win. Block/page layout,
compression, and lazy per-row iteration are future work.
"""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass

from packetql.capture.parser import Packet

# Fixed-width encodings, keyed by column "kind". 'dict' stores a uint16 code.
_STRUCTS = {
    "i64": struct.Struct("<q"),  # timestamp, in microseconds
    "u32": struct.Struct("<I"),  # IPv4 address, packet size
    "u16": struct.Struct("<H"),  # port
    "u8": struct.Struct("<B"),   # ttl
    "dict": struct.Struct("<H"),  # dictionary code
}


@dataclass(frozen=True)
class ColumnSpec:
    name: str
    kind: str
    nullable: bool


#: The packet schema, in column order. ``timestamp`` is stored as int64
#: microseconds; IPs as uint32; ``protocol`` is dictionary-encoded.
SCHEMA = [
    ColumnSpec("timestamp", "i64", False),
    ColumnSpec("src_ip", "u32", True),
    ColumnSpec("dst_ip", "u32", True),
    ColumnSpec("protocol", "dict", False),
    ColumnSpec("src_port", "u16", True),
    ColumnSpec("dst_port", "u16", True),
    ColumnSpec("size", "u32", False),
    ColumnSpec("ttl", "u8", True),
]
_BY_NAME = {c.name: c for c in SCHEMA}


# -- value <-> storage-integer conversions ----------------------------------


def _ip_to_int(s: str) -> int:
    a, b, c, d = (int(x) for x in s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def _int_to_ip(v: int) -> str:
    return f"{(v >> 24) & 255}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}"


def _to_storage(name: str, value):
    """Map a Packet field to the integer actually stored (None stays None)."""
    if value is None:
        return None
    if name in ("src_ip", "dst_ip"):
        return _ip_to_int(value)
    if name == "timestamp":
        return round(value * 1_000_000)
    return int(value)


def _from_storage(name: str, value):
    if value is None:
        return None
    if name in ("src_ip", "dst_ip"):
        return _int_to_ip(value)
    if name == "timestamp":
        return value / 1_000_000
    return value


# -- column (de)serialization ------------------------------------------------


def _bitmap_len(n: int) -> int:
    return (n + 7) // 8


def _pack_column(spec: ColumnSpec, storage_values: list) -> bytes:
    """Encode one column: an optional null bitmap, then the fixed-width values."""
    s = _STRUCTS[spec.kind]
    out = bytearray()
    n = len(storage_values)
    if spec.nullable:
        bitmap = bytearray(_bitmap_len(n))
        for i, v in enumerate(storage_values):
            if v is None:
                bitmap[i >> 3] |= 1 << (i & 7)
        out += bitmap
    for v in storage_values:
        out += s.pack(0 if v is None else v)
    return bytes(out)


def _unpack_column(spec: ColumnSpec, data: bytes, n: int) -> list:
    s = _STRUCTS[spec.kind]
    pos = 0
    bitmap = None
    if spec.nullable:
        nb = _bitmap_len(n)
        bitmap = data[:nb]
        pos = nb
    values = []
    for i in range(n):
        (raw,) = s.unpack_from(data, pos)
        pos += s.size
        if bitmap is not None and (bitmap[i >> 3] >> (i & 7)) & 1:
            values.append(None)
        else:
            values.append(raw)
    return values


# -- writing -----------------------------------------------------------------


def write_store(directory: str, packets: list[Packet]) -> None:
    """Write ``packets`` to a columnar store at ``directory`` (one file/column)."""
    os.makedirs(directory, exist_ok=True)
    n = len(packets)
    proto_dict: list[str] = []
    proto_index: dict[str, int] = {}
    meta = {"row_count": n, "columns": [], "protocol_dict": proto_dict}

    for spec in SCHEMA:
        raw = [getattr(p, spec.name) for p in packets]
        if spec.name == "protocol":
            codes = []
            for v in raw:
                if v not in proto_index:
                    proto_index[v] = len(proto_dict)
                    proto_dict.append(v)
                codes.append(proto_index[v])
            blob = _pack_column(spec, codes)
        else:
            blob = _pack_column(spec, [_to_storage(spec.name, v) for v in raw])
        with open(os.path.join(directory, spec.name + ".col"), "wb") as f:
            f.write(blob)
        meta["columns"].append({"name": spec.name, "kind": spec.kind, "nullable": spec.nullable})

    with open(os.path.join(directory, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# -- reading -----------------------------------------------------------------


class ColumnStore:
    """Read-side handle on a columnar store. Reads a column's file only when
    that column is requested — that lazy, per-column read is the whole point."""

    def __init__(self, directory: str) -> None:
        self.directory = directory
        with open(os.path.join(directory, "meta.json"), encoding="utf-8") as f:
            self.meta = json.load(f)
        self.row_count: int = self.meta["row_count"]
        self._proto_dict: list[str] = self.meta["protocol_dict"]
        #: bytes pulled off disk so far — lets a demo prove selective I/O.
        self.bytes_read = 0

    def column_names(self) -> list[str]:
        return [c["name"] for c in self.meta["columns"]]

    def column(self, name: str) -> list:
        """Read and decode a single column (opens only that column's file)."""
        if name not in _BY_NAME:
            raise KeyError(f"no such column {name!r}")
        spec = _BY_NAME[name]
        with open(os.path.join(self.directory, name + ".col"), "rb") as f:
            data = f.read()
        self.bytes_read += len(data)
        raw = _unpack_column(spec, data, self.row_count)
        if name == "protocol":
            return [self._proto_dict[code] for code in raw]
        return [_from_storage(name, v) for v in raw]

    def rows(self) -> list[Packet]:
        """Materialise every column back into Packet records (for round-trips)."""
        col = {name: self.column(name) for name in self.column_names()}
        return [
            Packet(
                timestamp=col["timestamp"][i], src_ip=col["src_ip"][i],
                dst_ip=col["dst_ip"][i], protocol=col["protocol"][i],
                src_port=col["src_port"][i], dst_port=col["dst_port"][i],
                size=col["size"][i], ttl=col["ttl"][i],
            )
            for i in range(self.row_count)
        ]


def store_disk_size(directory: str) -> int:
    """Total bytes of all column files in a store (excludes meta.json)."""
    return sum(
        os.path.getsize(os.path.join(directory, f))
        for f in os.listdir(directory)
        if f.endswith(".col")
    )
