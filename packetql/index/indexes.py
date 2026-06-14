"""Build and hold the indexes for a packet store.

A thin container the query planner consults: which columns have a hash index
(equality) and which have an IP trie (prefix). Built explicitly from a store so
indexing is an opt-in cost, not automatic.
"""

from __future__ import annotations

from packetql.index.hash_index import HashIndex
from packetql.index.trie import IPTrie


class PacketIndexes:
    def __init__(self) -> None:
        self.hash: dict[str, HashIndex] = {}
        self.trie: dict[str, IPTrie] = {}

    @classmethod
    def build(cls, store, hash_columns=(), trie_columns=()) -> "PacketIndexes":
        ix = cls()
        for col in hash_columns:
            ix.hash[col] = HashIndex(store.column(col))
        for col in trie_columns:
            ix.trie[col] = IPTrie(store.column(col))
        return ix
