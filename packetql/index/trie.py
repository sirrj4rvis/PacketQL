"""An IP-address trie for prefix (subnet) lookups.

Each level of the trie is one octet of the dotted IPv4 address, so the path
192 -> 168 -> 1 -> 10 spells out 192.168.1.10. Every node stores the row
positions of all addresses that pass through it (i.e. its whole subtree), so a
prefix query like ``192.168.1.*`` descends three nodes and returns that node's
row list directly — O(k) in the prefix length, independent of how many addresses
are stored. A linear scan of the column would be O(n).

Cost: each address is recorded in 4 nodes (one per octet), so the index is O(n)
space. NULL (non-IPv4) rows are skipped.
"""

from __future__ import annotations


class _Node:
    __slots__ = ("children", "rows")

    def __init__(self) -> None:
        self.children: dict[int, _Node] = {}
        self.rows: list[int] = []


class IPTrie:
    def __init__(self, ip_values: list) -> None:
        self.root = _Node()
        for row, ip in enumerate(ip_values):
            if ip is None:
                continue
            node = self.root
            for octet in self._octets(ip):
                node = node.children.setdefault(octet, _Node())
                node.rows.append(row)  # every node on the path holds its subtree's rows

    @staticmethod
    def _octets(ip: str) -> list[int]:
        return [int(part) for part in ip.split(".")]

    def prefix(self, octets: list[int]) -> list[int]:
        """Row positions of every address whose leading octets match ``octets``."""
        node = self.root
        for o in octets:
            node = node.children.get(o)
            if node is None:
                return []
        return list(node.rows)

    def exact(self, ip: str) -> list[int]:
        """Row positions of an exact address (a full four-octet prefix)."""
        return self.prefix(self._octets(ip))
