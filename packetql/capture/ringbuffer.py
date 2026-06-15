"""A bounded ring buffer for the capture pipeline — preallocated, head/tail.

Slots are preallocated once (no per-packet allocation on the hot path). A `head`
pointer advances on write, a `tail` pointer on read, both modulo the capacity;
the buffer is full when it holds `capacity` items, at which point the **oldest**
packet is dropped (the tail advances) and `dropped` is incremented — the lossy
behaviour a sniffer needs (you can't ask the wire to slow down). A
`threading.Condition` lets the writer thread sleep when the buffer is empty
rather than spin.

Note on the GIL: each `put`/`get` does its pointer arithmetic under the lock, so
a multi-field PacketRecord is published atomically — without the lock, a reader
could see a half-updated slot.
"""

from __future__ import annotations

import threading


class RingBuffer:
    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._slots: list = [None] * capacity      # preallocated
        self._head = 0
        self._tail = 0
        self._size = 0
        self._cond = threading.Condition()
        self._closed = False
        self.dropped = 0
        self.enqueued = 0

    def put(self, item) -> None:
        with self._cond:
            if self._size == self.capacity:        # full -> drop the oldest
                self._tail = (self._tail + 1) % self.capacity
                self._size -= 1
                self.dropped += 1
            self._slots[self._head] = item
            self._head = (self._head + 1) % self.capacity
            self._size += 1
            self.enqueued += 1
            self._cond.notify()

    def get_batch(self, max_items: int, timeout: float | None = None) -> list:
        """Block until items are available (or closed/timeout); return up to N."""
        with self._cond:
            while self._size == 0 and not self._closed:
                if not self._cond.wait(timeout):
                    return []
            out = []
            while self._size > 0 and len(out) < max_items:
                out.append(self._slots[self._tail])
                self._slots[self._tail] = None
                self._tail = (self._tail + 1) % self.capacity
                self._size -= 1
            return out

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    def __len__(self) -> int:
        with self._cond:
            return self._size
