"""The capture pipeline: producer/consumer threads around the ring buffer.

A *producer* feeds raw frames into the ring buffer; a *consumer* (writer) thread
drains it, parses each frame, and collects the packets (flushed to a columnar
store on demand). The producer can be any iterable of RawPacket — a .pcap replay
or synthetic test data via ``capture_offline`` — or scapy's live sniffer via
``capture_live``. Because the producer is abstracted, the OS/threading core is
fully exercised without a capture device; only ``capture_live`` needs scapy +
Npcap + Administrator rights.
"""

from __future__ import annotations

import threading

from packetql.capture.parser import Packet, parse_packet
from packetql.capture.pcap import RawPacket
from packetql.capture.ringbuffer import CLOSED, RingBuffer
from packetql.storage.columnar import write_store


class CapturePipeline:
    """Owns the ring buffer and the consumer/writer thread."""

    def __init__(self, capacity: int = 1024) -> None:
        self.ring = RingBuffer(capacity)
        self.packets: list[Packet] = []
        self._consumer: threading.Thread | None = None

    def _consume(self) -> None:
        while True:
            raw = self.ring.get()
            if raw is CLOSED:
                return
            self.packets.append(parse_packet(raw))

    def start(self) -> None:
        self._consumer = threading.Thread(target=self._consume, name="packetql-writer", daemon=True)
        self._consumer.start()

    def join(self) -> None:
        if self._consumer is not None:
            self._consumer.join()

    @property
    def captured(self) -> int:
        return len(self.packets)

    @property
    def dropped(self) -> int:
        return self.ring.dropped

    def flush_to_store(self, directory: str) -> None:
        """Write everything captured so far to a columnar store."""
        write_store(directory, self.packets)


def capture_offline(source, capacity: int = 1024) -> CapturePipeline:
    """Run the pipeline over an iterable of RawPacket (a .pcap replay or test data).

    The producer runs on its own thread so the producer/consumer hand-off through
    the ring buffer is real, not simulated.
    """
    pipe = CapturePipeline(capacity)
    pipe.start()

    def produce():
        for raw in source:
            pipe.ring.put(raw)
        pipe.ring.close()

    producer = threading.Thread(target=produce, name="packetql-sniffer")
    producer.start()
    producer.join()
    pipe.join()
    return pipe


def capture_live(iface=None, count: int = 0, timeout=None, capacity: int = 1024) -> CapturePipeline:
    """Capture live frames with scapy into the pipeline.

    Requires scapy installed AND Npcap (on Windows) AND Administrator privileges.
    ``count`` / ``timeout`` bound the capture so it terminates (0 / None means
    unbounded — stop with Ctrl-C). Each sniffed frame is turned into a RawPacket
    and pushed through the same ring buffer the offline path uses, so the parser,
    store, and queries are all identical to the offline pipeline.
    """
    from scapy.all import sniff  # imported lazily: only the live path needs scapy

    pipe = CapturePipeline(capacity)
    pipe.start()

    def on_packet(pkt):
        data = bytes(pkt)
        ts = float(getattr(pkt, "time", 0.0))
        pipe.ring.put(RawPacket(int(ts), int((ts % 1) * 1_000_000), len(data), data))

    sniff(iface=iface, prn=on_packet, count=count, timeout=timeout, store=False)
    pipe.ring.close()
    pipe.join()
    return pipe
