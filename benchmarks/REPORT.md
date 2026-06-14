# PacketQL Benchmark Report

Workload: **N = 100,000** synthetic packets. In-process microbenchmarks
(warm OS cache, single machine) — they show *relative* behaviour, not production
latency, and shift run to run. Regenerate with
`python benchmarks/benchmark_suite.py`.

## Capture / replay throughput

The ring-buffer pipeline (producer thread -> ring buffer -> writer thread that
parses each frame) processed **197,511 packets/sec**
(100,000 captured, 0 dropped with a buffer large enough to
avoid drops). The pipeline is parse-bound; with a smaller buffer it drops the
oldest packets (Wireshark's behaviour) rather than blocking the sniffer.

## Query: equality — hash index vs sequential scan

`SELECT src_ip, size FROM packets WHERE dst_port = 443`  (10,162 matches)

| access path | ms / query |
|---|---:|
| SeqScan | 188.41 |
| HashIndex on dst_port | 96.46 |

Speedup: **2.0x** — the hash lookup replaces a
full-column scan plus a per-row equality test.

## Query: prefix — IP trie vs sequential scan

`SELECT src_ip, size FROM packets WHERE src_ip LIKE '10.0.5.%'`  (1,933 matches)

| access path | ms / query |
|---|---:|
| SeqScan | 150.30 |
| TrieScan on src_ip | 102.16 |

Speedup: **1.5x** — the trie descends a few octet
nodes instead of testing a string prefix on every row.

## Columnar selective read

`SELECT size` read **400,000 of 2,762,500 bytes**
(14.5%) off disk — only one of the
eight columns. A row store would have read every field of every packet.

## Honest notes

- The query executor still reads the *full* projected columns, so an index saves
  the per-row predicate work, not the column I/O. A production columnar engine
  skips non-matching blocks with zone maps / late materialization — that is the
  next optimization, not a bug.
- Top-N (`ORDER BY ... LIMIT N`) uses a bounded heap: O(m log N) time and O(N)
  memory. In pure Python it does not beat CPython's C `sorted()` in wall-clock at
  these sizes — its win is asymptotic and for data too large to sort in memory.
