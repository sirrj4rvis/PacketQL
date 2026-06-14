"""PacketQL benchmark suite (Phase 7).

Synthesizes a large packet store and measures:
  * capture / replay throughput through the ring-buffer pipeline,
  * index vs sequential scan for an equality (hash) and a prefix (trie) query,
  * columnar selective-read savings (one column vs the whole store).

These are in-process microbenchmarks (warm OS cache, single machine): they show
*relative* behaviour, not production latency, and shift run to run. Running it
writes benchmarks/REPORT.md.

Run:  python benchmarks/benchmark_suite.py
"""

from __future__ import annotations

import os
import random
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from packetql.capture.pcap import RawPacket  # noqa: E402
from packetql.capture.pipeline import capture_offline  # noqa: E402
from packetql.index.indexes import PacketIndexes  # noqa: E402
from packetql.query.executor import run_query  # noqa: E402
from packetql.storage.columnar import ColumnStore, store_disk_size, write_store  # noqa: E402

N = 100_000
_PORTS = [80, 443, 22, 53, 8080, 3306, 5353, 123, 21, 25]
_SRC_MAC = bytes.fromhex("aabbcc000001")
_DST_MAC = bytes.fromhex("aabbcc000002")


def _ip(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _frame(src: str, dst: str, proto: int, dport: int, payload_len: int) -> bytes:
    eth = _DST_MAC + _SRC_MAC + struct.pack("!H", 0x0800)
    if proto == 6:  # TCP
        l4 = struct.pack("!HHIIHHHH", 40000, dport, 0, 0, (5 << 12) | 0x18, 65535, 0, 0)
    else:           # UDP
        l4 = struct.pack("!HHHH", 40000, dport, 8 + payload_len, 0)
    l4 += b"\x00" * payload_len
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, _ip(src), _ip(dst))
    return eth + iph + l4


def synth_raws(n: int) -> list[RawPacket]:
    random.seed(7)
    out = []
    for i in range(n):
        src = f"10.0.{random.randint(0, 49)}.{random.randint(1, 254)}"
        dst = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        proto = random.choice([6, 17])
        frame = _frame(src, dst, proto, random.choice(_PORTS), random.randint(20, 1400))
        out.append(RawPacket(1_700_000_000 + i, 0, len(frame), frame))
    return out


def bench(fn, reps: int) -> float:
    start = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - start) / reps * 1000.0


def run_benchmarks(n: int = N, reps: int = 10, write_report: bool = True, quiet: bool = False) -> dict:
    raws = synth_raws(n)

    t = time.perf_counter()
    pipe = capture_offline(raws, capacity=n + 1)   # big buffer -> measure pure throughput, no drops
    cap_elapsed = time.perf_counter() - t

    store_dir = os.path.join(ROOT, "data", "bench_store")
    write_store(store_dir, pipe.packets)
    store = ColumnStore(store_dir)
    indexes = PacketIndexes.build(store, hash_columns=["dst_port"], trie_columns=["src_ip"])

    q_eq = "SELECT src_ip, size FROM packets WHERE dst_port = 443"
    q_pfx = "SELECT src_ip, size FROM packets WHERE src_ip LIKE '10.0.5.%'"

    res = {
        "n": n,
        "captured": pipe.captured,
        "dropped": pipe.dropped,
        "cap_throughput": n / cap_elapsed,
        "scan_eq": bench(lambda: run_query(store, q_eq), reps),
        "idx_eq": bench(lambda: run_query(store, q_eq, indexes=indexes), reps),
        "scan_pfx": bench(lambda: run_query(store, q_pfx), reps),
        "idx_pfx": bench(lambda: run_query(store, q_pfx, indexes=indexes), reps),
        "matches_eq": len(run_query(store, q_eq, indexes=indexes).rows),
        "matches_pfx": len(run_query(store, q_pfx, indexes=indexes).rows),
    }
    probe = ColumnStore(store_dir)
    probe.column("size")
    res["sel_bytes"] = probe.bytes_read
    res["total_bytes"] = store_disk_size(store_dir)

    if write_report:
        _write_report(res)
    if not quiet:
        _print(res)
    return res


def _write_report(r: dict) -> None:
    path = os.path.join(ROOT, "benchmarks", "REPORT.md")
    text = f"""# PacketQL Benchmark Report

Workload: **N = {r['n']:,}** synthetic packets. In-process microbenchmarks
(warm OS cache, single machine) — they show *relative* behaviour, not production
latency, and shift run to run. Regenerate with
`python benchmarks/benchmark_suite.py`.

## Capture / replay throughput

The ring-buffer pipeline (producer thread -> ring buffer -> writer thread that
parses each frame) processed **{r['cap_throughput']:,.0f} packets/sec**
({r['captured']:,} captured, {r['dropped']} dropped with a buffer large enough to
avoid drops). The pipeline is parse-bound; with a smaller buffer it drops the
oldest packets (Wireshark's behaviour) rather than blocking the sniffer.

## Query: equality — hash index vs sequential scan

`SELECT src_ip, size FROM packets WHERE dst_port = 443`  ({r['matches_eq']:,} matches)

| access path | ms / query |
|---|---:|
| SeqScan | {r['scan_eq']:.2f} |
| HashIndex on dst_port | {r['idx_eq']:.2f} |

Speedup: **{r['scan_eq'] / r['idx_eq']:.1f}x** — the hash lookup replaces a
full-column scan plus a per-row equality test.

## Query: prefix — IP trie vs sequential scan

`SELECT src_ip, size FROM packets WHERE src_ip LIKE '10.0.5.%'`  ({r['matches_pfx']:,} matches)

| access path | ms / query |
|---|---:|
| SeqScan | {r['scan_pfx']:.2f} |
| TrieScan on src_ip | {r['idx_pfx']:.2f} |

Speedup: **{r['scan_pfx'] / r['idx_pfx']:.1f}x** — the trie descends a few octet
nodes instead of testing a string prefix on every row.

## Columnar selective read

`SELECT size` read **{r['sel_bytes']:,} of {r['total_bytes']:,} bytes**
({100.0 * r['sel_bytes'] / r['total_bytes']:.1f}%) off disk — only one of the
eight columns. A row store would have read every field of every packet.

## Honest notes

- The query executor still reads the *full* projected columns, so an index saves
  the per-row predicate work, not the column I/O. A production columnar engine
  skips non-matching blocks with zone maps / late materialization — that is the
  next optimization, not a bug.
- Top-N (`ORDER BY ... LIMIT N`) uses a bounded heap: O(m log N) time and O(N)
  memory. In pure Python it does not beat CPython's C `sorted()` in wall-clock at
  these sizes — its win is asymptotic and for data too large to sort in memory.
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _print(r: dict) -> None:
    print(f"N = {r['n']:,} packets")
    print(f"capture throughput : {r['cap_throughput']:,.0f} packets/sec  "
          f"({r['captured']:,} captured, {r['dropped']} dropped)")
    print(f"equality  dst_port=443  ({r['matches_eq']:,} matches): "
          f"scan {r['scan_eq']:.2f} ms  vs  hash {r['idx_eq']:.2f} ms  "
          f"-> {r['scan_eq'] / r['idx_eq']:.1f}x")
    print(f"prefix    src_ip 10.0.5.%  ({r['matches_pfx']:,} matches): "
          f"scan {r['scan_pfx']:.2f} ms  vs  trie {r['idx_pfx']:.2f} ms  "
          f"-> {r['scan_pfx'] / r['idx_pfx']:.1f}x")
    print(f"selective read  SELECT size: {r['sel_bytes']:,} of {r['total_bytes']:,} bytes "
          f"({100.0 * r['sel_bytes'] / r['total_bytes']:.1f}%)")
    print("wrote benchmarks/REPORT.md")


if __name__ == "__main__":
    run_benchmarks()
