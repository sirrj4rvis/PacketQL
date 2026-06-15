"""Direct-address hash index for ports.

Ports are bounded (0–65535), so the "hash" is a direct-address array of 65536
buckets — the key *is* the index, with no collisions. Each bucket is the list of
row indices having that port, in row order. O(1) exact-port lookup.
"""

from __future__ import annotations

_NUM_PORTS = 65536


class PortHash:
    def __init__(self, values) -> None:
        self.table: list = [None] * _NUM_PORTS
        for row, port in enumerate(values):
            self.add(port, row)

    def add(self, port: int, row: int) -> None:
        bucket = self.table[port]
        if bucket is None:
            bucket = []
            self.table[port] = bucket
        bucket.append(row)

    def lookup(self, port: int) -> list[int]:
        if not 0 <= port < _NUM_PORTS:
            return []
        bucket = self.table[port]
        return list(bucket) if bucket else []

    def count(self, port: int) -> int:
        if not 0 <= port < _NUM_PORTS:
            return 0
        bucket = self.table[port]
        return len(bucket) if bucket else 0
