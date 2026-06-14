"""Phase 4 tests: bit trie, direct-address port hash, protocol bitmap,
persistence, and the planner's index choice + compound pushdown."""

import os

from packetql.index.bitmap import BitmapIndex
from packetql.index.hash_index import PortHash
from packetql.index.indexes import PacketIndexes
from packetql.index.trie import BitTrie
from packetql.query.executor import run_query
from packetql.schema import PROTO_TCP, PROTO_UDP, PacketRecord, ip_to_int
from packetql.storage.columnar import ColumnStore, write_store


def test_bit_trie_prefix_and_exact():
    ips = [ip_to_int(x) for x in ["192.168.0.1", "192.168.0.2", "192.168.5.9", "10.0.0.1"]]
    t = BitTrie(ips)
    assert sorted(t.prefix_rows(ip_to_int("192.168.0.0"), 16)) == [0, 1, 2]   # 192.168.%
    assert t.prefix_count(ip_to_int("192.168.0.0"), 16) == 3
    assert t.exact_rows(ip_to_int("10.0.0.1")) == [3]
    assert t.prefix_rows(ip_to_int("172.0.0.0"), 8) == []


def test_direct_address_port_hash():
    h = PortHash([443, 80, 443, 53])
    assert h.lookup(443) == [0, 2]
    assert h.lookup(80) == [1]
    assert h.lookup(22) == []
    assert h.count(443) == 2


def test_protocol_bitmap():
    b = BitmapIndex([6, 17, 6, 1], 4)
    assert b.rows_for(6) == [0, 2]
    assert b.rows_for(17) == [1]
    assert b.count(6) == 2
    assert (b.bitmap(6) & b.bitmap(1)) == 0       # disjoint protocols


def _store(tmp_path):
    recs = [
        PacketRecord(1.0, ip_to_int("192.168.0.2"), ip_to_int("9.9.9.9"), 1, 443, PROTO_TCP, 1500, 0x10, 64),
        PacketRecord(2.0, ip_to_int("192.168.0.3"), ip_to_int("9.9.9.9"), 2, 80, PROTO_TCP, 200, 0x10, 64),
        PacketRecord(3.0, ip_to_int("192.168.0.2"), ip_to_int("8.8.8.8"), 3, 53, PROTO_UDP, 80, 0, 64),
        PacketRecord(4.0, ip_to_int("10.0.0.1"), ip_to_int("9.9.9.9"), 4, 443, PROTO_UDP, 90, 0, 64),
    ]
    d = str(tmp_path / "s")
    write_store(d, recs)
    return ColumnStore(d)


def test_index_results_match_scan(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store)
    for q in (
        "SELECT size FROM packets WHERE dst_port = 443",
        "SELECT size FROM packets WHERE proto = 6",
        "SELECT size FROM packets WHERE src_ip LIKE '192.168.%'",
        "SELECT size FROM packets WHERE proto = 6 AND dst_port = 443",
        "SELECT size FROM packets WHERE dst_port = 443 AND size > 1000",
    ):
        assert sorted(run_query(store, q).rows) == sorted(run_query(store, q, indexes=ix).rows)


def test_planner_picks_each_index(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store)
    assert "hash dst_port=443" in run_query(store, "SELECT size FROM packets WHERE dst_port = 443", indexes=ix).plan
    assert "bitmap proto=6" in run_query(store, "SELECT size FROM packets WHERE proto = 6", indexes=ix).plan
    assert "trie src_ip" in run_query(store, "SELECT size FROM packets WHERE src_ip LIKE '192.168.%'", indexes=ix).plan


def test_compound_pushdown_intersects(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store)
    r = run_query(store, "SELECT size FROM packets WHERE proto = 6 AND dst_port = 443", indexes=ix)
    assert r.rows == [(1500,)]                                # only the TCP:443 packet
    assert "bitmap proto=6" in r.plan and "hash dst_port=443" in r.plan


def test_residual_filter_after_index(tmp_path):
    store = _store(tmp_path)
    ix = PacketIndexes.build(store)
    r = run_query(store, "SELECT size FROM packets WHERE dst_port = 443 AND size > 1000", indexes=ix)
    assert r.rows == [(1500,)]                                # index dst_port=443 then residual size>1000


def test_persistence_roundtrip(tmp_path):
    store = _store(tmp_path)
    PacketIndexes.load_or_build(store)                        # builds + saves
    assert os.path.exists(os.path.join(store.directory, "indexes.pkl"))
    ix = PacketIndexes.load_or_build(store)                   # reloads (mtimes match)
    assert run_query(store, "SELECT size FROM packets WHERE dst_port = 443", indexes=ix).rows == [(1500,), (90,)]
