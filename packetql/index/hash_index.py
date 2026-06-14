"""A hash index: an inverted index from a column value to the row positions that
hold it. Backed by Python's dict (a hash table), it gives expected O(1) equality
lookup — ideal for a bounded key like a port number. Unlike a B+ tree (QueryX)
or the IP trie, it supports only equality, not ranges or prefixes, because
hashing destroys order. NULLs are not indexed (a NULL never equals anything)."""

from __future__ import annotations


class HashIndex:
    def __init__(self, values: list) -> None:
        self._postings: dict = {}
        for row, value in enumerate(values):
            if value is None:
                continue
            self._postings.setdefault(value, []).append(row)

    def lookup(self, value) -> list[int]:
        """Row positions whose value equals ``value`` (empty list if none)."""
        return self._postings.get(value, [])

    @property
    def distinct_keys(self) -> int:
        return len(self._postings)
