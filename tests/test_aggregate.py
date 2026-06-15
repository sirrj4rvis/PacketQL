"""Tests for analytics SQL: scalar aggregates, GROUP BY, HAVING, DISTINCT, EXPLAIN."""

import pytest

from packetql.index.indexes import PacketIndexes
from packetql.query.executor import run_query
from packetql.query.planner import QueryError
from packetql.schema import PROTO_TCP, PROTO_UDP, PacketRecord, ip_to_int
from packetql.storage.columnar import ColumnStore, write_store


def _store(tmp_path):
    recs = [
        PacketRecord(1.0, ip_to_int("10.0.0.1"), ip_to_int("9.9.9.9"), 1, 443, PROTO_TCP, 100, 0x10, 64),
        PacketRecord(2.0, ip_to_int("10.0.0.1"), ip_to_int("9.9.9.9"), 2, 443, PROTO_TCP, 200, 0x10, 64),
        PacketRecord(3.0, ip_to_int("10.0.0.2"), ip_to_int("8.8.8.8"), 3, 53, PROTO_UDP, 60, 0, 64),
        PacketRecord(4.0, ip_to_int("10.0.0.2"), ip_to_int("8.8.8.8"), 4, 53, PROTO_UDP, 80, 0, 64),
        PacketRecord(5.0, ip_to_int("10.0.0.3"), ip_to_int("1.1.1.1"), 5, 443, PROTO_TCP, 300, 0x10, 64),
    ]
    d = str(tmp_path / "s")
    write_store(d, recs)
    return ColumnStore(d)


def test_scalar_aggregates(tmp_path):
    r = run_query(_store(tmp_path), "SELECT COUNT(*), SUM(size), MIN(size), MAX(size) FROM packets")
    assert r.columns == ["COUNT(*)", "SUM(size)", "MIN(size)", "MAX(size)"]
    assert r.rows == [(5, 740, 60, 300)]


def test_avg_returns_float(tmp_path):
    r = run_query(_store(tmp_path), "SELECT AVG(size) FROM packets")
    assert r.rows == [(148.0,)]                       # 740 / 5


def test_group_by(tmp_path):
    r = run_query(_store(tmp_path),
                  "SELECT dst_port, COUNT(*), SUM(size) FROM packets GROUP BY dst_port ORDER BY dst_port")
    assert r.columns == ["dst_port", "COUNT(*)", "SUM(size)"]
    assert r.rows == [(53, 2, 140), (443, 3, 600)]


def test_having(tmp_path):
    r = run_query(_store(tmp_path),
                  "SELECT dst_port, COUNT(*) FROM packets GROUP BY dst_port HAVING COUNT(*) > 2")
    assert r.rows == [(443, 3)]


def test_group_by_with_where(tmp_path):
    r = run_query(_store(tmp_path),
                  "SELECT dst_port, COUNT(*) FROM packets WHERE proto = 6 GROUP BY dst_port")
    assert r.rows == [(443, 3)]


def test_grouped_order_by_aggregate(tmp_path):
    r = run_query(_store(tmp_path),
                  "SELECT dst_port, COUNT(*) FROM packets GROUP BY dst_port ORDER BY COUNT(*) DESC")
    assert r.rows == [(443, 3), (53, 2)]


def test_distinct(tmp_path):
    r = run_query(_store(tmp_path), "SELECT DISTINCT dst_port FROM packets ORDER BY dst_port")
    assert r.rows == [(53,), (443,)]
    assert len(run_query(_store(tmp_path), "SELECT DISTINCT src_ip FROM packets").rows) == 3


def test_invalid_aggregations_raise(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(QueryError):
        run_query(store, "SELECT dst_port, COUNT(*) FROM packets")          # bare col without GROUP BY
    with pytest.raises(QueryError):
        run_query(store, "SELECT * FROM packets GROUP BY dst_port")          # * with GROUP BY


def test_explain(tmp_path):
    r = run_query(_store(tmp_path),
                  "EXPLAIN SELECT dst_port, COUNT(*) FROM packets WHERE proto = 6 GROUP BY dst_port")
    text = "\n".join(row[0] for row in r.rows)
    assert "HashAggregate" in text and "SeqScan" in text


def test_explain_uses_index(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store)
    text = "\n".join(row[0] for row in
                     run_query(store, "EXPLAIN SELECT size FROM packets WHERE dst_port = 443", indexes=ix).rows)
    assert "IndexScan" in text


def test_aggregate_over_index_matches_scan(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store)
    q = "SELECT dst_port, COUNT(*) FROM packets WHERE proto = 6 GROUP BY dst_port"
    assert sorted(run_query(store, q).rows) == sorted(run_query(store, q, indexes=ix).rows)
