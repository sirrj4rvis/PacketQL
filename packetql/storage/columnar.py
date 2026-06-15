"""Phase 2 — fixed-width columnar storage.

Nine columns, one file each; every value is fixed-width, so (a) a query reads
only the column files it needs, and (b) row N of a column is at byte offset
N x width — an O(1) seek. Writes are buffered and fsync'd in batches (the
difference between hundreds and tens-of-thousands of packets/sec). Reads go
through a small page cache (a buffer pool). meta.json records the schema version,
row count, and each column's expected size for an integrity check on open.

Per packet on disk: 8 (ts) + 4 + 4 + 2 + 2 + 1 (proto) + 2 (size) + 1 (flags)
+ 1 (ttl) = 25 bytes across 9 files, vs ~60 for a naive row store.
"""

from __future__ import annotations

import json
import os
import struct
from collections import OrderedDict

from packetql.schema import PacketRecord

SCHEMA_VERSION = 1

# (column name, PacketRecord attribute, struct format, width in bytes)
COLUMNS = [
    ("ts", "timestamp", "<d", 8),
    ("src_ip", "src_ip", "<I", 4),
    ("dst_ip", "dst_ip", "<I", 4),
    ("src_port", "src_port", "<H", 2),
    ("dst_port", "dst_port", "<H", 2),
    ("proto", "protocol", "<B", 1),
    ("size", "size", "<H", 2),
    ("flags", "tcp_flags", "<B", 1),
    ("ttl", "ttl", "<B", 1),
]
COLUMN_NAMES = [name for name, *_ in COLUMNS]
WIDTHS = {name: width for name, _attr, _fmt, width in COLUMNS}
_BY_NAME = {name: (attr, fmt, width) for name, attr, fmt, width in COLUMNS}


def _col_path(directory: str, name: str) -> str:
    return os.path.join(directory, name + ".col")


def _meta_path(directory: str) -> str:
    return os.path.join(directory, "meta.json")


# ---------------------------------------------------------------------------
# Write path — batched, fsync'd, append-capable
# ---------------------------------------------------------------------------


class ColumnWriter:
    """Append PacketRecords to a store, flushing all column files per batch."""

    def __init__(self, directory: str, batch_size: int = 1000, append: bool = False) -> None:
        os.makedirs(directory, exist_ok=True)
        self.directory = directory
        self.batch_size = batch_size
        self._structs = {name: struct.Struct(fmt) for name, _, fmt, _ in COLUMNS}
        self._files = {name: open(_col_path(directory, name), "ab" if append else "wb") for name, *_ in COLUMNS}
        self._buf: dict[str, list[bytes]] = {name: [] for name, *_ in COLUMNS}
        self._buffered = 0
        self.row_count = 0
        if append and os.path.exists(_meta_path(directory)):
            with open(_meta_path(directory)) as f:
                self.row_count = json.load(f)["row_count"]
        # Write meta.json up front so the store is always valid/openable — even if
        # zero records are ever appended (e.g. a live capture that sees no traffic).
        # Without this, flush() short-circuits on an empty buffer and never writes
        # meta, leaving a store that can't be opened.
        self._write_meta()

    def append(self, rec: PacketRecord) -> None:
        for name, attr, _, _ in COLUMNS:
            self._buf[name].append(self._structs[name].pack(getattr(rec, attr)))
        self._buffered += 1
        if self._buffered >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if self._buffered == 0:
            return
        for name, *_ in COLUMNS:
            fh = self._files[name]
            fh.write(b"".join(self._buf[name]))
            fh.flush()
            os.fsync(fh.fileno())          # durable per batch
            self._buf[name].clear()
        self.row_count += self._buffered
        self._buffered = 0
        self._write_meta()

    def close(self) -> None:
        self.flush()
        for fh in self._files.values():
            fh.close()

    def __enter__(self) -> "ColumnWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _write_meta(self) -> None:
        cols = {name: {"struct": fmt, "width": width, "bytes": self.row_count * width}
                for name, _, fmt, width in COLUMNS}
        meta = {"schema_version": SCHEMA_VERSION, "row_count": self.row_count, "columns": cols}
        with open(_meta_path(self.directory), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)


def write_store(directory: str, records) -> None:
    """Create a fresh store from an iterable of PacketRecords."""
    with ColumnWriter(directory, append=False) as w:
        for rec in records:
            w.append(rec)


# ---------------------------------------------------------------------------
# A tiny page cache (buffer pool)
# ---------------------------------------------------------------------------


class _PageCache:
    """Fixed-size pages with global LRU eviction — repeated reads hit RAM."""

    PAGE = 64 * 1024

    def __init__(self, capacity_pages: int = 8) -> None:
        self._pages: OrderedDict = OrderedDict()
        self._cap = capacity_pages
        self.hits = 0
        self.misses = 0

    def read(self, fh, path: str, byte_off: int, length: int) -> bytes:
        out = bytearray()
        pos, end = byte_off, byte_off + length
        while pos < end:
            page_no = pos // self.PAGE
            page = self._page(fh, path, page_no)
            within = pos - page_no * self.PAGE
            take = min(self.PAGE - within, end - pos)
            out += page[within:within + take]
            pos += take
        return bytes(out)

    def _page(self, fh, path: str, page_no: int) -> bytes:
        key = (path, page_no)
        cached = self._pages.get(key)
        if cached is not None:
            self.hits += 1
            self._pages.move_to_end(key)
            return cached
        self.misses += 1
        fh.seek(page_no * self.PAGE)
        page = fh.read(self.PAGE)
        self._pages[key] = page
        if len(self._pages) > self._cap:
            self._pages.popitem(last=False)
        return page


# ---------------------------------------------------------------------------
# Read path
# ---------------------------------------------------------------------------


class ColumnStore:
    """Read-side handle: column scans, O(1) random access, batched iteration."""

    def __init__(self, directory: str) -> None:
        self.directory = directory
        with open(_meta_path(directory), encoding="utf-8") as f:
            self.meta = json.load(f)
        if self.meta.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version {self.meta.get('schema_version')}")
        self.row_count = self.meta["row_count"]
        self._verify_integrity()
        self._cache = _PageCache()
        self._fh: dict[str, object] = {}
        self.bytes_read = 0

    def _verify_integrity(self) -> None:
        for name, _, _, width in COLUMNS:
            expected = self.row_count * width
            actual = os.path.getsize(_col_path(self.directory, name))
            if actual != expected:
                raise ValueError(f"column {name!r}: {actual} bytes on disk, expected {expected} "
                                 f"({self.row_count} rows x {width}) — store is corrupt")

    def column_names(self) -> list[str]:
        return list(COLUMN_NAMES)

    def column(self, name: str) -> list:
        """Read and decode a whole column (a full scan of one column file)."""
        _attr, fmt, width = _BY_NAME[name]
        with open(_col_path(self.directory, name), "rb") as f:
            data = f.read()
        self.bytes_read += len(data)
        s = struct.Struct(fmt)
        return [s.unpack_from(data, i)[0] for i in range(0, len(data), width)]

    def iter_column(self, name: str, batch_rows: int = 1024):
        """Yield successive batches of a column's values (for vectorized scans)."""
        _attr, fmt, width = _BY_NAME[name]
        s = struct.Struct(fmt)
        with open(_col_path(self.directory, name), "rb") as f:
            while True:
                chunk = f.read(batch_rows * width)
                if not chunk:
                    return
                self.bytes_read += len(chunk)
                yield [s.unpack_from(chunk, i)[0] for i in range(0, len(chunk), width)]

    def read_rows(self, name: str, row_indices) -> list:
        """Random access: each row index via an O(1) seek through the page cache."""
        _attr, fmt, width = _BY_NAME[name]
        s = struct.Struct(fmt)
        path = _col_path(self.directory, name)
        fh = self._fh.get(name)
        if fh is None:
            fh = open(path, "rb")
            self._fh[name] = fh
        out = []
        for idx in row_indices:
            out.append(s.unpack(self._cache.read(fh, path, idx * width, width))[0])
        return out

    def records(self) -> list[PacketRecord]:
        """Materialise every column back into PacketRecords (for round-trips)."""
        col = {name: self.column(name) for name in COLUMN_NAMES}
        return [
            PacketRecord(
                timestamp=col["ts"][i], src_ip=col["src_ip"][i], dst_ip=col["dst_ip"][i],
                src_port=col["src_port"][i], dst_port=col["dst_port"][i], protocol=col["proto"][i],
                size=col["size"][i], tcp_flags=col["flags"][i], ttl=col["ttl"][i],
            )
            for i in range(self.row_count)
        ]

    @property
    def cache_hits(self) -> int:
        return self._cache.hits

    @property
    def cache_misses(self) -> int:
        return self._cache.misses

    def close(self) -> None:
        for fh in self._fh.values():
            fh.close()
        self._fh.clear()


def store_disk_size(directory: str) -> int:
    return sum(os.path.getsize(_col_path(directory, name)) for name in COLUMN_NAMES)
