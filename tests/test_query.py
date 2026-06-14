"""Tests for the SQL-like query engine over the columnar store."""

import pytest

from packetql.capture.parser import Packet
from packetql.query.executor import QueryError, run_query
from packetql.storage.columnar import ColumnStore, store_disk_size, write_store


def _store(tmp_path):
    packets = [
        Packet(1.0, "192.168.1.10", "93.184.216.34", "TCP", 51514, 443, 154, 64),
        Packet(2.0, "192.168.1.20", "10.0.0.5", "TCP", 40001, 80, 1554, 64),
        Packet(3.0, "192.168.1.10", "8.8.8.8", "UDP", 50000, 53, 82, 64),
        Packet(4.0, None, None, "ETH-0x0806", None, None, 42, None),   # ARP: nulls
    ]
    d = str(tmp_path / "store")
    write_store(d, packets)
    return ColumnStore(d)


def test_projection_filter_order(tmp_path):
    res = run_query(_store(tmp_path),
                    "SELECT dst_port, size FROM packets WHERE protocol = 'TCP' ORDER BY size DESC")
    assert res.columns == ["dst_port", "size"]
    assert res.rows == [(80, 1554), (443, 154)]


def test_and_or_not(tmp_path):
    store = _store(tmp_path)
    not_tcp = run_query(store, "SELECT size FROM packets WHERE NOT protocol = 'TCP'")
    assert sorted(r[0] for r in not_tcp.rows) == [42, 82]
    or_q = run_query(store, "SELECT size FROM packets WHERE size > 1000 OR protocol = 'UDP'")
    assert sorted(r[0] for r in or_q.rows) == [82, 1554]


def test_star_and_limit(tmp_path):
    res = run_query(_store(tmp_path), "SELECT * FROM packets LIMIT 2")
    assert len(res.columns) == 8 and len(res.rows) == 2


def test_null_never_matches_comparison(tmp_path):
    # the ARP row has dst_port = NULL, so it must not match dst_port = 80
    res = run_query(_store(tmp_path), "SELECT size FROM packets WHERE dst_port = 80")
    assert res.rows == [(1554,)]


def test_parentheses_precedence(tmp_path):
    store = _store(tmp_path)
    res = run_query(store,
                    "SELECT size FROM packets WHERE protocol = 'TCP' AND (dst_port = 80 OR dst_port = 53)")
    assert res.rows == [(1554,)]   # only the TCP-to-80 packet


def test_unknown_table_and_column(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(QueryError):
        run_query(store, "SELECT size FROM flows")
    with pytest.raises(QueryError):
        run_query(store, "SELECT nope FROM packets")


def test_column_pruning(tmp_path):
    store = _store(tmp_path)
    run_query(store, "SELECT size FROM packets WHERE size > 100")
    assert 0 < store.bytes_read < store_disk_size(store.directory)
