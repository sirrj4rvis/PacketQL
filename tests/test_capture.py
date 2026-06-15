"""Phase 5 tests: ring buffer (preallocated, drop-oldest), capture pipeline,
incremental indexing, adaptive batch sizing."""

import os
import struct
import threading

from packetql.capture.pcap import RawPacket, read_packets
from packetql.capture.pipeline import CapturePipeline, capture_offline
from packetql.capture.ringbuffer import RingBuffer
from packetql.index.indexes import PacketIndexes
from packetql.query.executor import run_query
from packetql.schema import PacketRecord
from packetql.storage.columnar import ColumnStore

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")


def _rec(i):
    return PacketRecord(float(i), i, i, i % 65536, i % 65536, 6, 40, 0, 64)


def _ip_checksum(header):
    total = 0
    for k in range(0, len(header), 2):
        total += (header[k] << 8) | header[k + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frame(i):
    """A valid (correct-checksum) TCP/IPv4 frame, for overload tests."""
    eth = bytes(12) + struct.pack("!H", 0x0800)
    src = bytes([10, 0, (i >> 8) & 255, i & 255])
    hdr0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, src, bytes([8, 8, 8, 8]))
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, _ip_checksum(hdr0), src, bytes([8, 8, 8, 8]))
    tcp = struct.pack("!HHIIBBHHH", 1234, 443, 0, 0, 5 << 4, 0x10, 0, 0, 0)
    return eth + hdr + tcp


def test_ring_buffer_drops_oldest():
    rb = RingBuffer(4)
    for i in range(10):
        rb.put(_rec(i))
    rb.close()
    got = []
    while True:
        b = rb.get_batch(100)
        if not b:
            break
        got.extend(b)
    assert [r.timestamp for r in got] == [6, 7, 8, 9]
    assert rb.dropped == 6 and rb.enqueued == 10


def test_ring_buffer_producer_consumer():
    rb = RingBuffer(8)
    received = []

    def consume():
        while True:
            b = rb.get_batch(3)
            if b:
                received.extend(b)
            elif rb.closed and len(rb) == 0:
                break

    t = threading.Thread(target=consume)
    t.start()
    for i in range(2000):
        rb.put(_rec(i))
    rb.close()
    t.join()
    assert [r.timestamp for r in received] == sorted(r.timestamp for r in received)
    assert rb.dropped + len(received) == 2000


def test_capture_offline_to_store(tmp_path):
    d = str(tmp_path / "s")
    pipe = capture_offline(read_packets(FIXTURE), d, capacity=4096, batch_size=2)
    assert pipe.written == 5            # 5 valid (the bad-checksum frame is discarded)
    assert pipe.dropped == 0
    store = ColumnStore(d)
    assert store.row_count == 5
    r = run_query(store, "SELECT dst_port FROM packets WHERE proto = 6 ORDER BY dst_port")
    assert [x[0] for x in r.rows] == [443, 443, 51000]


def test_incremental_index_matches_scan(tmp_path):
    d = str(tmp_path / "s")
    ix = PacketIndexes.empty()
    capture_offline(read_packets(FIXTURE), d, indexes=ix)
    store = ColumnStore(d)
    for q in ("SELECT dst_port FROM packets WHERE proto = 6",
              "SELECT size FROM packets WHERE src_ip LIKE '192.168.%'"):
        assert sorted(run_query(store, q).rows) == sorted(run_query(store, q, indexes=ix).rows)


def test_adaptive_batch_sizing(tmp_path):
    pipe = CapturePipeline(str(tmp_path / "s"), capacity=4, batch_size=10)
    pipe.ring.enqueued = 100
    pipe.ring.dropped = 20              # a 20% drop rate
    pipe._adapt()
    assert pipe.batch_size == 20        # doubled
    assert pipe._writer.batch_size == 20
    assert pipe.drop_log[-1] == 0.2
    pipe._writer.close()


def test_capture_conserves_under_overload(tmp_path):
    d = str(tmp_path / "s")
    raws = [RawPacket(i, 0, len(f), f) for i, f in ((i, _frame(i)) for i in range(3000))]
    pipe = capture_offline(raws, d, capacity=8, batch_size=4)
    assert pipe.written + pipe.dropped == 3000
    assert ColumnStore(d).row_count == pipe.written
