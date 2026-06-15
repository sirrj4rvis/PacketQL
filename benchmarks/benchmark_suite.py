"""PacketQL benchmark suite (Phase 7) — measure everything, report honestly.

Four measurements, all reproducible:
  1. Scan vs index across 100K / 500K / 1M rows (the O(n) vs O(1) curve).
  2. Columnar vs a row-store baseline for a column-selective query.
  3. Write throughput at batch sizes 1 / 100 / 1000 (the fsync effect).
  4. Concurrent query throughput at 1 / 4 / 8 clients (thread-pool server).

In-process microbenchmarks (warm cache, single machine): relative behaviour, not
production latency. Writes benchmarks/REPORT.md.

Run:  python benchmarks/benchmark_suite.py
"""

from __future__ import annotations

import os
import random
import socket
import struct
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from packetql.index.hash_index import PortHash  # noqa: E402
from packetql.schema import PacketRecord  # noqa: E402
from packetql.server import QUERY, QueryServer, recv_frame, send_frame  # noqa: E402
from packetql.storage.columnar import ColumnStore, ColumnWriter, store_disk_size, write_store  # noqa: E402

_PORTS = [80, 443, 22, 53, 8080, 3306, 5353, 123, 21, 25]
_ROW = struct.Struct("<dIIHHBHBB")   # row-store baseline: 25 bytes/row


def synth(n: int) -> list[PacketRecord]:
    random.seed(7)
    out = []
    for i in range(n):
        out.append(PacketRecord(
            1_700_000_000.0 + i * 1e-4,
            (10 << 24) | (random.randint(0, 49) << 8) | random.randint(1, 254),
            (93 << 24) | random.randint(0, 0xFFFFFF),
            random.randint(1024, 65535), random.choice(_PORTS),
            random.choice([6, 17]), random.randint(40, 1400),
            0x10, 64))
    return out


def _bench(fn, reps):
    start = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - start) / reps * 1000.0


# 1. scan vs index across scales --------------------------------------------
def scan_vs_index(scales):
    rows = []
    for n in scales:
        d = os.path.join(ROOT, "data", f"bench_{n}")
        write_store(d, synth(n))
        store = ColumnStore(d)
        col = store.column("dst_port")
        scan_ms = _bench(lambda: sum(1 for v in store.column("dst_port") if v == 443), 3)
        index = PortHash(col)
        idx_ms = _bench(lambda: len(index.lookup(443)), 50)
        rows.append((n, scan_ms, idx_ms, len(index.lookup(443))))
    return rows


# 2. columnar vs row-store baseline -----------------------------------------
def _write_row_store(path, records):
    with open(path, "wb") as f:
        buf = bytearray()
        for r in records:
            buf += _ROW.pack(r.timestamp, r.src_ip, r.dst_ip, r.src_port, r.dst_port,
                             r.protocol, r.size, r.tcp_flags, r.ttl)
            if len(buf) >= (1 << 20):
                f.write(buf); buf.clear()
        f.write(buf)


def _row_store_sum_size(path):
    with open(path, "rb") as f:
        data = f.read()
    return sum(_ROW.unpack_from(data, off)[6] for off in range(0, len(data), _ROW.size))


def columnar_vs_rowstore(n):
    recs = synth(n)
    cdir = os.path.join(ROOT, "data", "bench_col")
    write_store(cdir, recs)
    rpath = os.path.join(ROOT, "data", "bench_row.bin")
    _write_row_store(rpath, recs)
    store = ColumnStore(cdir)
    col_ms = _bench(lambda: sum(store.column("size")), 5)
    row_ms = _bench(lambda: _row_store_sum_size(rpath), 5)
    col_bytes = os.path.getsize(os.path.join(cdir, "size.col"))
    row_bytes = os.path.getsize(rpath)
    return n, col_ms, row_ms, col_bytes, row_bytes


# 3. write throughput vs batch size -----------------------------------------
def write_throughput(n, batch_sizes):
    recs = synth(n)
    bytes_total = n * _ROW.size
    out = []
    for bs in batch_sizes:
        d = os.path.join(ROOT, "data", f"bench_w{bs}")
        start = time.perf_counter()
        with ColumnWriter(d, batch_size=bs, append=False) as w:
            for r in recs:
                w.append(r)
        elapsed = time.perf_counter() - start
        out.append((bs, n / elapsed, bytes_total / elapsed / (1 << 20)))
    return out


# 4. concurrent query throughput --------------------------------------------
def concurrency(n, client_counts, duration=0.5):
    d = os.path.join(ROOT, "data", "bench_conc")
    write_store(d, synth(n))
    server = QueryServer(d, port=0, workers=8)
    server.start()
    sql = b"SELECT dst_port FROM packets WHERE dst_port = 443 LIMIT 5"
    out = []
    try:
        for c in client_counts:
            counter = [0] * c
            stop = threading.Event()

            def worker(idx):
                with socket.create_connection(("127.0.0.1", server.port)) as s:
                    while not stop.is_set():
                        send_frame(s, QUERY, sql)
                        recv_frame(s)
                        counter[idx] += 1

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(c)]
            t0 = time.perf_counter()
            for t in threads:
                t.start()
            time.sleep(duration)
            stop.set()
            for t in threads:
                t.join()
            elapsed = time.perf_counter() - t0
            out.append((c, sum(counter) / elapsed))
    finally:
        server.stop()
    return out


def run_benchmarks(scales=(100_000, 500_000, 1_000_000), write_report=True, quiet=False) -> dict:
    res = {
        "scan_vs_index": scan_vs_index(scales),
        "rowstore": columnar_vs_rowstore(200_000 if max(scales) >= 200_000 else max(scales)),
        "write": write_throughput(2000, [1, 100, 1000]),
        "concurrency": concurrency(5000, [1, 4, 8]),
    }
    if write_report:
        _write_report(res)
    if not quiet:
        _print(res)
    return res


def _write_report(r):
    lines = ["# PacketQL Benchmark Report", "",
             "In-process microbenchmarks (warm cache, single machine) — relative behaviour, not",
             "production latency. Regenerate with `python benchmarks/benchmark_suite.py`.", "",
             "## 1. Scan vs index (equality on `dst_port`)", "",
             "| rows | SeqScan ms | index ms | speedup |", "|---:|---:|---:|---:|"]
    for n, scan_ms, idx_ms, _m in r["scan_vs_index"]:
        lines.append(f"| {n:,} | {scan_ms:.2f} | {idx_ms:.3f} | {scan_ms / idx_ms:,.0f}x |")
    n, col_ms, row_ms, col_b, row_b = r["rowstore"]
    lines += ["", "## 2. Columnar vs row-store (sum a single column)", "",
              f"At {n:,} rows, reading only `size`:", "",
              f"- columnar: {col_ms:.2f} ms, {col_b:,} bytes read",
              f"- row store: {row_ms:.2f} ms, {row_b:,} bytes read",
              f"- columnar reads **{row_b / col_b:.1f}x less data** and runs **{row_ms / col_ms:.1f}x faster**",
              "", "## 3. Write throughput vs batch size (fsync per batch)", "",
              "| batch | packets/s | MB/s |", "|---:|---:|---:|"]
    for bs, pps, mbs in r["write"]:
        lines.append(f"| {bs} | {pps:,.0f} | {mbs:.1f} |")
    lines += ["", "## 4. Concurrent query throughput (thread-pool server)", "",
              "| clients | queries/s |", "|---:|---:|"]
    for c, qps in r["concurrency"]:
        lines.append(f"| {c} | {qps:,.0f} |")
    lines += ["", "_Note: the bit-trie is memory-heavy at very large N (a node per bit); "
              "Python's GIL caps CPU-bound concurrency scaling._", ""]
    with open(os.path.join(ROOT, "benchmarks", "REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _print(r):
    print("scan vs index:")
    for n, scan_ms, idx_ms, _m in r["scan_vs_index"]:
        print(f"  {n:>9,} rows: scan {scan_ms:7.2f} ms  index {idx_ms:6.3f} ms  -> {scan_ms / idx_ms:,.0f}x")
    n, col_ms, row_ms, col_b, row_b = r["rowstore"]
    print(f"columnar vs row-store ({n:,}): columnar {col_ms:.2f} ms / {col_b:,} B  vs  "
          f"row {row_ms:.2f} ms / {row_b:,} B  ({row_b / col_b:.1f}x less data)")
    print("write throughput:")
    for bs, pps, mbs in r["write"]:
        print(f"  batch {bs:>4}: {pps:>10,.0f} pkt/s  {mbs:6.1f} MB/s")
    print("concurrency:")
    for c, qps in r["concurrency"]:
        print(f"  {c} client(s): {qps:,.0f} queries/s")
    print("wrote benchmarks/REPORT.md")


if __name__ == "__main__":
    run_benchmarks()
