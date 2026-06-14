"""Tests for the ring buffer and the capture pipeline (no capture device needed)."""

import threading

from packetql.capture.pcap import RawPacket
from packetql.capture.pipeline import capture_offline
from packetql.capture.ringbuffer import CLOSED, RingBuffer
from packetql.query.executor import run_query
from packetql.storage.columnar import ColumnStore
from tools.make_sample_pcap import build


def _raw(i: int) -> RawPacket:
    return RawPacket(i, 0, 1, bytes([i % 256]))


def test_ringbuffer_fifo():
    rb = RingBuffer(10)
    for i in range(5):
        rb.put(_raw(i))
    rb.close()
    got = []
    while (item := rb.get()) is not CLOSED:
        got.append(item.ts_sec)
    assert got == [0, 1, 2, 3, 4]
    assert rb.dropped == 0


def test_ringbuffer_drops_oldest_when_full():
    rb = RingBuffer(4)
    for i in range(10):          # no consumer -> the buffer overflows
        rb.put(_raw(i))
    rb.close()
    kept = []
    while (item := rb.get()) is not CLOSED:
        kept.append(item.ts_sec)
    assert kept == [6, 7, 8, 9]   # only the newest 4 survive
    assert rb.dropped == 6
    assert rb.enqueued == 10


def test_producer_consumer_threads():
    rb = RingBuffer(2)            # a tiny buffer forces a real producer/consumer hand-off
    received = []

    def consume():
        while (item := rb.get()) is not CLOSED:
            received.append(item.ts_sec)

    consumer = threading.Thread(target=consume)
    consumer.start()
    for i in range(2000):
        rb.put(_raw(i))
    rb.close()
    consumer.join()

    assert received == sorted(received)          # kept packets stay in arrival order
    assert rb.dropped + len(received) == 2000    # each packet was either consumed or dropped


def test_capture_offline_end_to_end(tmp_path):
    pipe = capture_offline(build(), capacity=1024)   # 9 synthetic frames
    assert pipe.captured == 9
    assert pipe.dropped == 0
    store_dir = str(tmp_path / "store")
    pipe.flush_to_store(store_dir)
    res = run_query(ColumnStore(store_dir),
                    "SELECT dst_port FROM packets WHERE protocol = 'TCP' ORDER BY dst_port")
    assert [r[0] for r in res.rows] == [80, 80, 443, 443, 55000]
