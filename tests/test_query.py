"""Phase 3 tests: the SQL query engine over the new integer schema."""

import pytest

from packetql.query.executor import QueryResult, ip_prefix_range, run_query
from packetql.query.planner import QueryError
from packetql.schema import ACK, PROTO_TCP, PROTO_UDP, SYN, PacketRecord, int_to_ip, ip_to_int
from packetql.storage.columnar import ColumnStore, write_store


def _store(tmp_path):
    recs = [
        PacketRecord(1.0, ip_to_int("192.168.0.2"), ip_to_int("93.184.216.34"), 51000, 443, PROTO_TCP, 1500, SYN | ACK, 64),
        PacketRecord(2.0, ip_to_int("192.168.0.2"), ip_to_int("10.0.0.5"), 51001, 80, PROTO_TCP, 200, ACK, 64),
        PacketRecord(3.0, ip_to_int("192.168.0.9"), ip_to_int("8.8.8.8"), 50000, 53, PROTO_UDP, 80, 0, 64),
        PacketRecord(4.0, ip_to_int("10.0.0.1"), ip_to_int("192.168.0.2"), 22, 55000, PROTO_TCP, 1600, ACK, 60),
    ]
    d = str(tmp_path / "s")
    write_store(d, recs)
    return ColumnStore(d)


def test_projection_filter_order(tmp_path):
    r = run_query(_store(tmp_path),
                  "SELECT dst_port, size FROM packets WHERE proto = 6 AND size > 1000 ORDER BY size DESC")
    assert r.rows == [(55000, 1600), (443, 1500)]


def test_ip_literal_becomes_uint32(tmp_path):
    r = run_query(_store(tmp_path), "SELECT dst_port FROM packets WHERE src_ip = '192.168.0.2'")
    assert sorted(x[0] for x in r.rows) == [80, 443]


def test_ip_like_prefix_range(tmp_path):
    r = run_query(_store(tmp_path), "SELECT src_ip FROM packets WHERE src_ip LIKE '192.168.%'")
    assert len(r.rows) == 3
    assert all(int_to_ip(x[0]).startswith("192.168.") for x in r.rows)


def test_float_literal(tmp_path):
    r = run_query(_store(tmp_path), "SELECT size FROM packets WHERE ts > 2.5")
    assert sorted(x[0] for x in r.rows) == [80, 1600]


def test_or_and_not(tmp_path):
    r = run_query(_store(tmp_path), "SELECT size FROM packets WHERE proto = 17 OR NOT proto = 6")
    assert [x[0] for x in r.rows] == [80]


def test_star_and_limit(tmp_path):
    r = run_query(_store(tmp_path), "SELECT * FROM packets LIMIT 2")
    assert len(r.columns) == 9 and len(r.rows) == 2


def test_top_n_matches_full_order(tmp_path):
    r = run_query(_store(tmp_path), "SELECT size FROM packets ORDER BY size DESC LIMIT 2")
    assert [x[0] for x in r.rows] == [1600, 1500]


def test_parentheses_precedence(tmp_path):
    r = run_query(_store(tmp_path),
                  "SELECT dst_port FROM packets WHERE proto = 6 AND (dst_port = 80 OR dst_port = 53)")
    assert r.rows == [(80,)]


def test_unknown_column_and_table(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(QueryError):
        run_query(store, "SELECT nope FROM packets")
    with pytest.raises(QueryError):
        run_query(store, "SELECT size FROM flows")


def test_plan_label_and_column_pruning(tmp_path):
    r = run_query(_store(tmp_path), "SELECT size FROM packets WHERE proto = 6")
    assert r.plan.startswith("SeqScan")
    assert "reads 2/9 columns" in r.plan       # only size + proto


def test_ip_prefix_range_helper():
    assert ip_prefix_range("192.168.%") == (ip_to_int("192.168.0.0"), ip_to_int("192.168.255.255"))
    assert ip_prefix_range("10.%") == (ip_to_int("10.0.0.0"), ip_to_int("10.255.255.255"))
