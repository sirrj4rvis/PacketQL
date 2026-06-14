"""Phase 4 demo: indexes accelerate queries.

Builds a larger synthetic store, builds a hash index (dst_port) and an IP trie
(src_ip), and shows the plan + measured speedup of index vs sequential scan. For
top-N it shows correctness and the algorithmic/memory advantage (a pure-Python
heap can't beat CPython's C `sorted()` in raw wall-clock at this size — the win
is O(m log N) time and O(N) memory, which matters at scale).

Run:  python demo_index.py
"""

from __future__ import annotations

import os
import random
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.capture.parser import Packet  # noqa: E402
from packetql.index.indexes import PacketIndexes  # noqa: E402
from packetql.query.executor import run_query  # noqa: E402
from packetql.storage.columnar import ColumnStore, write_store  # noqa: E402


def synthesize(n: int) -> list[Packet]:
    random.seed(42)
    ports = [80, 443, 22, 53, 8080, 3306, 5353, 123]
    packets = []
    for i in range(n):
        src = f"10.0.{random.randint(0, 19)}.{random.randint(1, 254)}"
        dst = f"93.184.{random.randint(0, 255)}.{random.randint(1, 254)}"
        packets.append(Packet(
            1_700_000_000 + i * 0.001, src, dst, random.choice(["TCP", "UDP"]),
            random.randint(1024, 65535), random.choice(ports), random.randint(40, 1514), 64))
    return packets


def bench(fn, reps: int) -> float:
    start = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - start) / reps * 1000.0


def main() -> None:
    n = 20_000
    store_dir = os.path.join(ROOT, "data", "big_store")
    print(f"synthesizing {n:,} packets into a columnar store...")
    write_store(store_dir, synthesize(n))
    store = ColumnStore(store_dir)
    ix = PacketIndexes.build(store, hash_columns=["dst_port"], trie_columns=["src_ip"])
    print("built indexes: HashIndex(dst_port), IPTrie(src_ip)\n")

    cases = [
        ("hash equality", "SELECT src_ip, size FROM packets WHERE dst_port = 443"),
        ("trie prefix", "SELECT src_ip, size FROM packets WHERE src_ip LIKE '10.0.5.%'"),
    ]
    reps = 30
    for label, q in cases:
        scan = run_query(store, q)
        idxd = run_query(store, q, indexes=ix)
        assert sorted(scan.rows) == sorted(idxd.rows), "index and scan disagree!"
        t_scan = bench(lambda: run_query(store, q), reps)
        t_idx = bench(lambda: run_query(store, q, indexes=ix), reps)
        print(f"{label}:  {q}")
        print(f"  matches={len(idxd.rows)}   plan(indexed) = '{idxd.plan}'")
        print(f"  scan : {t_scan:7.3f} ms     index: {t_idx:7.3f} ms     "
              f"-> {t_scan / t_idx:5.1f}x faster\n")

    # top-N: correctness + the advantage (no misleading wall-clock race vs C sort)
    q = "SELECT src_ip, size FROM packets ORDER BY size DESC LIMIT 10"
    top = run_query(store, q, indexes=ix)
    full = run_query(store, "SELECT src_ip, size FROM packets ORDER BY size DESC")
    assert [r[1] for r in top.rows] == [r[1] for r in full.rows[:10]], "top-N disagrees with full sort"
    print(f"top-N:  {q}")
    print(f"  plan = '{top.plan}'")
    print(f"  largest size = {top.rows[0][1]}; keeps a size-10 heap "
          f"(O(m log 10) time, O(10) memory) instead of sorting all {n:,} rows.")


if __name__ == "__main__":
    main()
