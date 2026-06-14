"""Tests for the columnar store: round-trip, null handling, selective reads."""

import math

from packetql.capture.parser import Packet
from packetql.storage.columnar import ColumnStore, store_disk_size, write_store


def _packets():
    return [
        Packet(1.000001, "192.168.1.10", "93.184.216.34", "TCP", 51514, 443, 154, 64),
        Packet(2.5, None, None, "ETH-0x0806", None, None, 42, None),       # ARP: all null but size
        Packet(3.0, "10.0.0.1", "10.0.0.2", "ICMP", None, None, 98, 128),  # null ports only
        Packet(4.25, "8.8.8.8", "192.168.1.10", "UDP", 53, 50000, 162, 57),
    ]


def _equal(a, b):
    return (
        math.isclose(a.timestamp, b.timestamp, abs_tol=1e-6)
        and (a.src_ip, a.dst_ip, a.protocol, a.src_port, a.dst_port, a.size, a.ttl)
        == (b.src_ip, b.dst_ip, b.protocol, b.src_port, b.dst_port, b.size, b.ttl)
    )


def test_round_trip(tmp_path):
    d = str(tmp_path / "store")
    pkts = _packets()
    write_store(d, pkts)
    restored = ColumnStore(d).rows()
    assert len(restored) == len(pkts)
    assert all(_equal(a, b) for a, b in zip(pkts, restored))


def test_nulls_are_preserved(tmp_path):
    d = str(tmp_path / "store")
    write_store(d, _packets())
    store = ColumnStore(d)
    assert store.column("src_ip")[1] is None       # ARP frame has no IP
    assert store.column("dst_ip")[1] is None
    assert store.column("src_port")[2] is None      # ICMP has no ports
    assert store.column("ttl")[1] is None
    assert store.column("src_ip")[0] == "192.168.1.10"  # non-null still intact


def test_dictionary_encoding(tmp_path):
    d = str(tmp_path / "store")
    write_store(d, _packets())
    store = ColumnStore(d)
    assert store.column("protocol") == ["TCP", "ETH-0x0806", "ICMP", "UDP"]


def test_selective_read_touches_one_column(tmp_path):
    d = str(tmp_path / "store")
    write_store(d, _packets())
    store = ColumnStore(d)
    store.column("size")
    assert 0 < store.bytes_read < store_disk_size(d)
