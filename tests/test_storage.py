"""Phase 2 tests: fixed-width columnar store — round-trip, batching/append,
integrity, O(1) random access, page cache, selective read."""

import os

import pytest

from packetql.schema import PacketRecord, ip_to_int
from packetql.storage.columnar import (
    COLUMN_NAMES, ColumnStore, ColumnWriter, store_disk_size, write_store,
)


def _records(n):
    out = []
    for i in range(n):
        tcp = i % 2 == 0
        out.append(PacketRecord(
            timestamp=1_700_000_000.0 + i * 0.001,
            src_ip=ip_to_int(f"10.0.{i % 256}.{(i * 7) % 256}"),
            dst_ip=ip_to_int("8.8.8.8"),
            src_port=1024 + (i % 60000),
            dst_port=443 if tcp else 53,
            protocol=6 if tcp else 17,
            size=40 + (i % 1400),
            tcp_flags=0x12 if tcp else 0,
            ttl=64,
        ))
    return out


def test_round_trip_exact(tmp_path):
    recs = _records(2500)                 # > batch_size, exercises batching
    d = str(tmp_path / "s")
    write_store(d, recs)
    store = ColumnStore(d)
    assert store.row_count == 2500
    assert store.records() == recs        # exact: timestamp is a double, rest ints


def test_empty_store_is_valid(tmp_path):
    # Regression: a store with zero records must still write meta.json and open
    # cleanly (e.g. a live capture that sees no traffic). Previously flush()
    # short-circuited on an empty buffer, so meta.json was never written and the
    # store could not be opened.
    from packetql.query.executor import run_query
    d = str(tmp_path / "empty")
    write_store(d, [])
    store = ColumnStore(d)
    assert store.row_count == 0
    assert store.records() == []
    assert run_query(store, "SELECT COUNT(*) FROM packets").rows == [(0,)]


def test_nine_fixed_width_columns(tmp_path):
    d = str(tmp_path / "s")
    write_store(d, _records(10))
    files = sorted(f for f in os.listdir(d) if f.endswith(".col"))
    assert files == sorted(n + ".col" for n in COLUMN_NAMES)
    assert len(COLUMN_NAMES) == 9
    assert os.path.getsize(os.path.join(d, "proto.col")) == 10    # 1 byte/row
    assert os.path.getsize(os.path.join(d, "ts.col")) == 80       # 8 bytes/row
    assert os.path.getsize(os.path.join(d, "size.col")) == 20     # 2 bytes/row


def test_integrity_check_catches_corruption(tmp_path):
    d = str(tmp_path / "s")
    write_store(d, _records(10))
    ColumnStore(d)                        # clean open: fine
    with open(os.path.join(d, "size.col"), "ab") as f:
        f.write(b"\x00\x00")              # one extra row's worth of bytes
    with pytest.raises(ValueError):
        ColumnStore(d)


def test_o1_random_access(tmp_path):
    recs = _records(5000)
    d = str(tmp_path / "s")
    write_store(d, recs)
    store = ColumnStore(d)
    idxs = [0, 1234, 4999, 2500]
    assert store.read_rows("dst_port", idxs) == [recs[i].dst_port for i in idxs]
    assert store.read_rows("src_ip", idxs) == [recs[i].src_ip for i in idxs]


def test_page_cache_serves_repeat_reads(tmp_path):
    d = str(tmp_path / "s")
    write_store(d, _records(5000))
    store = ColumnStore(d)
    store.read_rows("src_ip", list(range(200)))    # warm the pages
    before = store.cache_hits
    store.read_rows("src_ip", list(range(200)))    # same pages -> served from cache
    assert store.cache_hits > before


def test_selective_read(tmp_path):
    d = str(tmp_path / "s")
    write_store(d, _records(1000))
    store = ColumnStore(d)
    store.column("size")
    assert 0 < store.bytes_read < store_disk_size(d)


def test_append_mode(tmp_path):
    d = str(tmp_path / "s")
    with ColumnWriter(d, batch_size=100, append=False) as w:
        for r in _records(150):
            w.append(r)
    with ColumnWriter(d, batch_size=100, append=True) as w:
        for r in _records(50):
            w.append(r)
    assert ColumnStore(d).row_count == 200


def test_vectorized_iteration(tmp_path):
    recs = _records(3000)
    d = str(tmp_path / "s")
    write_store(d, recs)
    store = ColumnStore(d)
    batches = list(store.iter_column("size", batch_rows=1024))
    assert [len(b) for b in batches] == [1024, 1024, 952]      # 3000 rows in 1024 batches
    assert [v for b in batches for v in b] == [r.size for r in recs]
