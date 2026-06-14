"""Tests for the index structures and the index-aware query planner."""

from packetql.capture.parser import Packet
from packetql.index.hash_index import HashIndex
from packetql.index.indexes import PacketIndexes
from packetql.index.topn import top_n
from packetql.index.trie import IPTrie
from packetql.query.executor import run_query
from packetql.storage.columnar import ColumnStore, write_store


def test_hash_index():
    h = HashIndex([10, 20, 10, None, 30, 20])
    assert h.lookup(10) == [0, 2]
    assert h.lookup(20) == [1, 5]
    assert h.lookup(99) == []
    assert h.distinct_keys == 3


def test_ip_trie_prefix_and_exact():
    t = IPTrie(["10.0.5.1", "10.0.5.9", "10.0.6.1", "192.168.1.1", None])
    assert sorted(t.prefix([10, 0, 5])) == [0, 1]
    assert sorted(t.prefix([10, 0])) == [0, 1, 2]
    assert t.prefix([172]) == []
    assert t.exact("10.0.6.1") == [2]


def test_top_n_matches_sort():
    items = [5, 3, 9, 1, 7, 2, 8]
    assert top_n(items, 3, lambda x: x, largest=True) == sorted(items, reverse=True)[:3]
    assert top_n(items, 3, lambda x: x, largest=False) == sorted(items)[:3]
    assert top_n(items, 100, lambda x: x, largest=True) == sorted(items, reverse=True)


def _store(tmp_path):
    packets = [
        Packet(1.0, "10.0.5.1", "9.9.9.9", "TCP", 1111, 443, 1500, 64),
        Packet(2.0, "10.0.5.2", "9.9.9.9", "UDP", 2222, 53, 80, 64),
        Packet(3.0, "10.0.6.1", "9.9.9.9", "TCP", 3333, 443, 200, 64),
        Packet(4.0, "192.168.1.1", "9.9.9.9", "TCP", 4444, 80, 1400, 64),
    ]
    d = str(tmp_path / "store")
    write_store(d, packets)
    return ColumnStore(d)


def test_indexed_equals_unindexed(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store, hash_columns=["dst_port"], trie_columns=["src_ip"])
    for q in (
        "SELECT src_ip, size FROM packets WHERE dst_port = 443",
        "SELECT src_ip FROM packets WHERE src_ip LIKE '10.0.5.%'",
        "SELECT src_ip, size FROM packets WHERE dst_port = 443 AND size > 1000",
    ):
        assert sorted(run_query(store, q).rows) == sorted(run_query(store, q, indexes=ix).rows)


def test_plan_labels(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store, hash_columns=["dst_port"], trie_columns=["src_ip"])
    assert "HashIndex" in run_query(store, "SELECT size FROM packets WHERE dst_port = 443", indexes=ix).plan
    assert "TrieScan" in run_query(store, "SELECT src_ip FROM packets WHERE src_ip LIKE '10.0.5.%'", indexes=ix).plan
    assert run_query(store, "SELECT size FROM packets WHERE size > 100", indexes=ix).plan.startswith("SeqScan")


def test_like_prefix_without_index(tmp_path):
    store = _store(tmp_path)  # no indexes -> scan path uses string startswith
    res = run_query(store, "SELECT src_ip FROM packets WHERE src_ip LIKE '10.0.5.%'")
    assert sorted(res.rows) == [("10.0.5.1",), ("10.0.5.2",)]


def test_order_limit_uses_heap(tmp_path):
    store = _store(tmp_path)
    res = run_query(store, "SELECT size FROM packets ORDER BY size DESC LIMIT 2")
    assert res.rows == [(1500,), (1400,)]
    assert "Top-2 heap" in res.plan


def test_residual_filter_after_index(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store, hash_columns=["dst_port"], trie_columns=["src_ip"])
    # dst_port=443 -> rows 0 and 2; residual size>1000 keeps only row 0
    res = run_query(store, "SELECT size FROM packets WHERE dst_port = 443 AND size > 1000", indexes=ix)
    assert res.rows == [(1500,)]
    assert "HashIndex" in res.plan
