"""Bit-level IP trie — depth 32, one bit per level.

Because an IPv4 address is a 32-bit integer, the trie branches on one bit at a
time. A prefix (subnet) query like ``src_ip LIKE '192.168.%'`` descends the
known prefix bits and collects the subtree's row indices in O(prefix_bits +
matches) — not O(n). Row indices live at the depth-32 leaves; every node carries
a subtree count so the planner can estimate selectivity without walking it.
"""

from __future__ import annotations


class _Node:
    __slots__ = ("child", "rows", "count")

    def __init__(self) -> None:
        self.child = [None, None]    # child[0], child[1]
        self.rows = None             # list of row indices (only at depth-32 leaves)
        self.count = 0               # rows in this subtree


class BitTrie:
    DEPTH = 32

    def __init__(self, values) -> None:
        self.root = _Node()
        for row, value in enumerate(values):
            self.add(value, row)

    def add(self, value: int, row: int) -> None:
        """Insert one (IP, row) — used both at build time and for live capture."""
        node = self.root
        node.count += 1
        for b in range(self.DEPTH - 1, -1, -1):
            bit = (value >> b) & 1
            nxt = node.child[bit]
            if nxt is None:
                nxt = _Node()
                node.child[bit] = nxt
            node = nxt
            node.count += 1
        if node.rows is None:
            node.rows = []
        node.rows.append(row)

    def _descend(self, prefix_value: int, prefix_bits: int):
        node = self.root
        for b in range(self.DEPTH - 1, self.DEPTH - 1 - prefix_bits, -1):
            node = node.child[(prefix_value >> b) & 1]
            if node is None:
                return None
        return node

    def prefix_rows(self, prefix_value: int, prefix_bits: int) -> list[int]:
        node = self._descend(prefix_value, prefix_bits)
        if node is None:
            return []
        out: list[int] = []
        stack = [node]
        while stack:
            x = stack.pop()
            if x.rows is not None:
                out.extend(x.rows)
            if x.child[0] is not None:
                stack.append(x.child[0])
            if x.child[1] is not None:
                stack.append(x.child[1])
        out.sort()
        return out

    def prefix_count(self, prefix_value: int, prefix_bits: int) -> int:
        node = self._descend(prefix_value, prefix_bits)
        return node.count if node is not None else 0

    def exact_rows(self, value: int) -> list[int]:
        return self.prefix_rows(value, self.DEPTH)
