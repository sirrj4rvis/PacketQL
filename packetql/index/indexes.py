"""Build, persist, and choose among the three indexes for a packet store.

`choose` is the planner's hook: it decomposes the top-level ANDs, resolves each
sargable conjunct through the right index (protocol -> bitmap, port -> hash, IP
equality/prefix -> trie), **intersects** the resulting row sets (compound
predicate pushdown), and returns an index access path when it is more selective
than a full scan. Indexes persist to disk and reload only if the column files are
unchanged (mtime); otherwise they rebuild.
"""

from __future__ import annotations

import os
import pickle

from packetql.index.bitmap import BitmapIndex
from packetql.index.hash_index import PortHash
from packetql.index.trie import BitTrie
from packetql.query import ast

_TRIE_COLS = ("src_ip", "dst_ip")
_HASH_COLS = ("src_port", "dst_port")
_BITMAP_COLS = ("proto",)
_INDEX_FILE = "indexes.pkl"


def _like_to_prefix(pattern: str) -> tuple[int, int]:
    """`'192.168.%'` -> (uint32 with the known octets, prefix bit-length)."""
    core = pattern[:-1] if pattern.endswith("%") else pattern
    known = [int(p) for p in core.split(".") if p != ""]
    value = 0
    for k in range(4):
        value = (value << 8) | (known[k] if k < len(known) else 0)
    return value, len(known) * 8


def _col_lit(binop):
    left, right = binop.left, binop.right
    if isinstance(left, ast.ColumnRef) and isinstance(right, ast.Literal):
        return left.name, right.value
    if isinstance(right, ast.ColumnRef) and isinstance(left, ast.Literal):
        return right.name, left.value
    return None, None


def _conjuncts(expr):
    if expr is None:
        return []
    if isinstance(expr, ast.BinaryOp) and expr.op == "AND":
        return _conjuncts(expr.left) + _conjuncts(expr.right)
    return [expr]


def _rebuild_and(conjuncts):
    if not conjuncts:
        return None
    node = conjuncts[0]
    for c in conjuncts[1:]:
        node = ast.BinaryOp("AND", node, c)
    return node


class PacketIndexes:
    def __init__(self, trie, hash_, bitmap, row_count) -> None:
        self.trie = trie
        self.hash = hash_
        self.bitmap = bitmap
        self.row_count = row_count

    @classmethod
    def build(cls, store) -> "PacketIndexes":
        return cls(
            {c: BitTrie(store.column(c)) for c in _TRIE_COLS},
            {c: PortHash(store.column(c)) for c in _HASH_COLS},
            {c: BitmapIndex(store.column(c), store.row_count) for c in _BITMAP_COLS},
            store.row_count,
        )

    # -- persistence --------------------------------------------------------
    @staticmethod
    def _mtimes(directory) -> dict:
        from packetql.storage.columnar import COLUMN_NAMES, _col_path
        return {c: os.path.getmtime(_col_path(directory, c)) for c in COLUMN_NAMES}

    @classmethod
    def load_or_build(cls, store) -> "PacketIndexes":
        path = os.path.join(store.directory, _INDEX_FILE)
        mtimes = cls._mtimes(store.directory)
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    saved = pickle.load(f)
                if saved.get("mtimes") == mtimes and saved.get("row_count") == store.row_count:
                    return saved["indexes"]               # fresh -> reuse
            except Exception:
                pass
        ix = cls.build(store)
        try:
            with open(path, "wb") as f:
                pickle.dump({"mtimes": mtimes, "row_count": store.row_count, "indexes": ix}, f)
        except Exception:
            pass
        return ix

    # -- the planner's chooser ---------------------------------------------
    def choose(self, where, store, scan_cost):
        rowsets, labels, residual = [], [], []
        for conj in _conjuncts(where):
            resolved = self._resolve(conj)
            if resolved is None:
                residual.append(conj)
            else:
                rows, label = resolved
                rowsets.append(rows)
                labels.append(label)
        if not rowsets:
            return None
        candidates = set(rowsets[0])
        for rs in rowsets[1:]:
            candidates &= set(rs)                          # compound pushdown: intersect
        candidates = sorted(candidates)
        if len(candidates) >= store.row_count:
            return None                                    # not selective -> scan is no worse
        access = ("index", candidates, labels)
        desc = (f"IndexScan [{' & '.join(labels)}] -> {len(candidates)} candidate rows "
                f"(vs SeqScan {store.row_count})")
        return access, len(candidates), _rebuild_and(residual), desc

    def _resolve(self, conj):
        if not isinstance(conj, ast.BinaryOp):
            return None
        if conj.op == "=":
            col, lit = _col_lit(conj)
            if col is None:
                return None
            if col in self.bitmap:
                return self.bitmap[col].rows_for(lit), f"bitmap {col}={lit}"
            if col in self.hash:
                return self.hash[col].lookup(lit), f"hash {col}={lit}"
            if col in self.trie:
                return self.trie[col].exact_rows(lit), f"trie {col}={lit}"
        elif conj.op == "LIKE" and isinstance(conj.left, ast.ColumnRef) and conj.left.name in self.trie \
                and isinstance(conj.right, ast.Literal) and isinstance(conj.right.value, str):
            value, bits = _like_to_prefix(conj.right.value)
            return self.trie[conj.left.name].prefix_rows(value, bits), f"trie {conj.left.name} LIKE {conj.right.value!r}"
        return None
