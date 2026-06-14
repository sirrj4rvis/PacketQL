"""Bounded top-N selection via a binary heap, for ORDER BY ... LIMIT N.

Rather than sort all m rows (O(m log m)) to keep the top N, we slide a heap of
size N over the rows in O(m log N) — a big win when m is large and N is small.
For "largest N" the heap is a min-heap whose root is the smallest kept item: a
new item beats the root iff it is larger, so it evicts the root. "Smallest N" is
the mirror image (the root is the largest kept item). The heap is hand-written
(sift up/down) rather than calling heapq, to show the structure.
"""

from __future__ import annotations

from typing import Callable


class BoundedTopN:
    def __init__(self, n: int, key: Callable, largest: bool) -> None:
        self.n = n
        self.key = key
        self.largest = largest   # True: keep the N largest; False: keep the N smallest
        self._h: list = []

    def _evictable_above(self, a, b) -> bool:
        """True if ``a`` belongs nearer the root than ``b`` (the root is evicted first)."""
        ka, kb = self.key(a), self.key(b)
        return ka < kb if self.largest else ka > kb

    def _sift_up(self, i: int) -> None:
        while i > 0:
            parent = (i - 1) // 2
            if self._evictable_above(self._h[i], self._h[parent]):
                self._h[i], self._h[parent] = self._h[parent], self._h[i]
                i = parent
            else:
                break

    def _sift_down(self, i: int) -> None:
        size = len(self._h)
        while True:
            top = i
            for child in (2 * i + 1, 2 * i + 2):
                if child < size and self._evictable_above(self._h[child], self._h[top]):
                    top = child
            if top == i:
                break
            self._h[i], self._h[top] = self._h[top], self._h[i]
            i = top

    def push(self, item) -> None:
        if self.n <= 0:
            return
        if len(self._h) < self.n:
            self._h.append(item)
            self._sift_up(len(self._h) - 1)
        else:
            root = self._h[0]
            beats_root = (self.key(item) > self.key(root)) if self.largest else (self.key(item) < self.key(root))
            if beats_root:
                self._h[0] = item
                self._sift_down(0)

    def result(self) -> list:
        """The kept items, ordered as ORDER BY would emit them."""
        return sorted(self._h, key=self.key, reverse=self.largest)


def top_n(items, n: int, key: Callable, largest: bool) -> list:
    heap = BoundedTopN(n, key, largest)
    for item in items:
        heap.push(item)
    return heap.result()
