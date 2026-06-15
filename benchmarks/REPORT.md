# PacketQL Benchmark Report

In-process microbenchmarks (warm cache, single machine) — relative behaviour, not
production latency. Regenerate with `python benchmarks/benchmark_suite.py`.

## 1. Scan vs index (equality on `dst_port`)

| rows | SeqScan ms | index ms | speedup |
|---:|---:|---:|---:|
| 100,000 | 10.16 | 0.029 | 356x |
| 500,000 | 103.71 | 0.403 | 258x |
| 1,000,000 | 195.84 | 1.398 | 140x |

## 2. Columnar vs row-store (sum a single column)

At 200,000 rows, reading only `size`:

- columnar: 30.79 ms, 400,000 bytes read
- row store: 58.14 ms, 5,000,000 bytes read
- columnar reads **12.5x less data** and runs **1.9x faster**

## 3. Write throughput vs batch size (fsync per batch)

| batch | packets/s | MB/s |
|---:|---:|---:|
| 1 | 104 | 0.0 |
| 100 | 10,908 | 0.3 |
| 1000 | 91,287 | 2.2 |

## 4. Concurrent query throughput (thread-pool server)

| clients | queries/s |
|---:|---:|
| 1 | 1,097 |
| 4 | 1,190 |
| 8 | 1,060 |

_Note: the bit-trie is memory-heavy at very large N (a node per bit); Python's GIL caps CPU-bound concurrency scaling._
