"""The capture pipeline: a producer (capture) and a writer thread, joined by the
ring buffer.

The producer parses frames and pushes PacketRecords into the ring buffer; the
writer thread pulls them in batches, appends them to the columnar store, and
**updates the indexes incrementally**. Under load it adapts: when the recent drop
rate exceeds 5% it doubles the write batch (fewer fsyncs, faster drain), and it
logs the per-batch drop rate. ``capture_offline`` replays an iterable of frames
(tests / .pcap); ``capture_live`` sniffs with scapy (needs Npcap + admin).
"""

from __future__ import annotations

import threading

from packetql.capture.parser import parse_packet
from packetql.capture.pcap import RawPacket
from packetql.capture.ringbuffer import RingBuffer
from packetql.storage.columnar import ColumnWriter


class CapturePipeline:
    BATCH_CAP = 16384

    def __init__(self, store_dir: str, capacity: int = 4096, batch_size: int = 1000,
                 indexes=None) -> None:
        self.ring = RingBuffer(capacity)
        self._writer = ColumnWriter(store_dir, batch_size=batch_size, append=True)
        self.batch_size = batch_size
        self.indexes = indexes
        self._next_row = self._writer.row_count       # row index of the next appended record
        self.written = 0
        self.drop_log: list[float] = []               # per-batch drop rate samples
        self._last_dropped = 0
        self._last_enqueued = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_writer, daemon=True, name="pktql-writer")
        self._thread.start()

    def _run_writer(self) -> None:
        while True:
            batch = self.ring.get_batch(self.batch_size, timeout=0.2)
            if batch:
                for rec in batch:
                    self._writer.append(rec)
                    if self.indexes is not None:
                        self.indexes.add(rec, self._next_row)
                    self._next_row += 1
                    self.written += 1
                self._adapt()
            elif self.ring.closed and len(self.ring) == 0:
                break
        self._writer.close()

    def _adapt(self) -> None:
        d = self.ring.dropped - self._last_dropped
        e = self.ring.enqueued - self._last_enqueued
        self._last_dropped, self._last_enqueued = self.ring.dropped, self.ring.enqueued
        rate = d / e if e else 0.0
        self.drop_log.append(rate)
        if rate > 0.05 and self.batch_size < self.BATCH_CAP:    # backpressure -> bigger writes
            self.batch_size = min(self.batch_size * 2, self.BATCH_CAP)
            self._writer.batch_size = self.batch_size

    def join(self) -> None:
        if self._thread is not None:
            self._thread.join()

    @property
    def dropped(self) -> int:
        return self.ring.dropped


def capture_offline(raw_packets, store_dir: str, capacity: int = 4096,
                    batch_size: int = 1000, indexes=None) -> CapturePipeline:
    """Replay RawPackets through the pipeline into a store (parse on the producer)."""
    pipe = CapturePipeline(store_dir, capacity, batch_size, indexes)
    pipe.start()
    for raw in raw_packets:
        rec = parse_packet(raw.data, raw.timestamp)
        if rec is not None:
            pipe.ring.put(rec)
    pipe.ring.close()
    pipe.join()
    return pipe


def capture_live(store_dir: str, iface=None, count: int = 0, timeout=None,
                 capacity: int = 4096, batch_size: int = 1000, indexes=None) -> CapturePipeline:
    """Capture live frames with scapy (needs Npcap + Administrator on Windows)."""
    from scapy.all import sniff

    pipe = CapturePipeline(store_dir, capacity, batch_size, indexes)
    pipe.start()

    def on_packet(pkt):
        data = bytes(pkt)
        ts = float(getattr(pkt, "time", 0.0))
        rec = parse_packet(data, ts)
        if rec is not None:
            pipe.ring.put(rec)

    sniff(iface=iface, prn=on_packet, count=count, timeout=timeout, store=False)
    pipe.ring.close()
    pipe.join()
    return pipe
