"""A bounded, thread-safe ring buffer for the capture pipeline (the OS core).

Packets arrive (a producer thread) faster than they can be parsed and stored (a
consumer thread). A fixed-size buffer absorbs bursts; when it is full, the
**oldest** packet is dropped to make room for the newest — the same lossy
behaviour Wireshark/tcpdump use under load (a dropped packet is *counted*, not a
crash). Access is guarded by a Condition (a mutex plus wait/notify): a producer
appends and notifies; the consumer waits while the buffer is empty.

This is the classic bounded-buffer producer/consumer problem; the only twist is
drop-oldest instead of blocking the producer, because a packet sniffer can't ask
the network to slow down.
"""

from __future__ import annotations

import collections
import threading

#: Returned by get() once the buffer is closed and fully drained.
CLOSED = object()


class RingBuffer:
    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._buf: collections.deque = collections.deque()
        self._cond = threading.Condition()
        self._closed = False
        self.dropped = 0    # packets discarded because the buffer was full
        self.enqueued = 0   # packets accepted into the buffer

    def put(self, item) -> None:
        """Add an item; if the buffer is full, drop the oldest to make room."""
        with self._cond:
            if len(self._buf) >= self.capacity:
                self._buf.popleft()      # drop the OLDEST
                self.dropped += 1
            self._buf.append(item)
            self.enqueued += 1
            self._cond.notify()

    def get(self):
        """Block until an item is available; return CLOSED when closed and empty."""
        with self._cond:
            while not self._buf and not self._closed:
                self._cond.wait()
            if self._buf:
                return self._buf.popleft()
            return CLOSED

    def close(self) -> None:
        """Signal that no more items will arrive; wakes a waiting consumer."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def __len__(self) -> int:
        with self._cond:
            return len(self._buf)
