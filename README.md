# PacketQL

**A live network packet analyzer with a SQL-like query engine — built from scratch in Python.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![tests](https://img.shields.io/badge/tests-49%20passing-success)
![offline](https://img.shields.io/badge/offline%20engine-stdlib%20only-success)

Capture packets off the wire, decode Ethernet → IP → TCP/UDP/ICMP headers **by
hand (with IP-checksum verification)**, store them in a custom **fixed-width
columnar** format, index them three ways, and query the traffic with SQL —
locally or over a binary-protocol TCP server:

```sql
SELECT src_ip, dst_port, size FROM packets
WHERE proto = 6 AND size > 1500
ORDER BY size DESC LIMIT 50;
```

Everything is integer-native: IPs are **uint32**, protocol is the raw IANA
number, plus `tcp_flags` and `ttl` — see the locked
[`PacketRecord` schema](packetql/schema.py) and the per-module
[contracts](CONTRACTS.md). The offline path is **standard-library only**; `scapy`
is needed only for live capture.

---

## Architecture

```
   live NIC (scapy)  ┐
                     ├─► parser ─► ring buffer ─► writer thread ─┐
   .pcap replay      ┘   Ethernet/IP/   preallocated   batched fsync append
                         TCP/UDP/ICMP    head/tail,     + incremental index    ▼
                         + checksum      drop-oldest                       columnar store
                                                                           9 fixed-width cols,
                                                                           O(1) seek, page cache
                                                                                │
   client ──[len][type] over TCP──► thread-pool server ──► query engine ───────┘
            QUERY / PING / STATS     (RWLock-guarded)      lexer → parser → cost planner
                                                           → vectorized executor
                                                           indexes: bit-trie · port-hash · bitmap
```

## Built across four subjects

| Subject | What it demonstrates |
|---|---|
| **Computer Networks** | hand-decoding headers **with IP checksum verification**; a binary-protocol TCP server |
| **Operating Systems** | producer/consumer ring buffer + adaptive backpressure; thread pool; a **readers-writer lock** |
| **Data Structures** | **bit-level depth-32 IP trie**, **direct-address port hash**, **protocol bitmap**, ring buffer, top-N heap |
| **Databases** | fixed-width **columnar store**, a SQL lexer/parser/**cost planner**/**vectorized executor** |

---

## Quickstart (offline — standard library only)

```bash
python tools/make_fixture_pcap.py   # write tests/fixtures/sample.pcap (valid checksums + 1 corrupt)
python demo.py                      # parse -> columnar store -> indexes -> queries (with plans)
python query.py --store data/demo_store "SELECT proto, dst_port, size FROM packets WHERE proto = 6"
pytest                              # 49 tests
python benchmarks/benchmark_suite.py
```

`query.py` with no SQL opens an interactive prompt. IP/protocol/flags columns are
rendered human-readably (`192.168.0.2`, `TCP`, `SYN|ACK`); the engine stores them
as integers.

## Live capture (needs Npcap + Administrator)

```bash
pip install scapy                   # plus Npcap from https://npcap.com (install as Admin)
# in an Administrator terminal:
python -c "from packetql.capture.pipeline import capture_live; p = capture_live('data/live_store', count=50, timeout=20); print('captured', p.written, 'dropped', p.dropped)"
python query.py --store data/live_store
```

## Query over TCP (binary protocol + thread pool)

```bash
python -m packetql.server --store data/demo_store    # thread-pool server, no admin needed
python query_client.py                               # connect; type SQL, '.ping', '.stats'
```
Wire protocol: request `[4-byte length][1-byte type]` (QUERY/PING/STATS), response
`[4-byte length][1-byte status]` with results encoded column-major in binary;
reads loop until the full message arrives (TCP has no message boundaries).

### Query language

`SELECT [cols|*] FROM packets [WHERE expr] [ORDER BY col [ASC|DESC]] [LIMIT n]`;
operators `= != <> < > <= >=` with `AND / OR / NOT` and parentheses; `LIKE
'prefix%'` for IP subnets. Columns: `ts, src_ip, dst_ip, src_port, dst_port,
proto, size, flags, ttl`. IP literals (`src_ip = '192.168.0.2'`) are converted to
uint32 in the parser. The planner picks **bitmap** (protocol), **hash** (port),
or **trie** (IP) and **intersects** them (compound pushdown) when more selective
than a scan.

---

## Benchmarks

In-process microbenchmarks (warm cache, single machine) — *relative* behaviour,
not production latency. Numbers match [benchmarks/REPORT.md](benchmarks/REPORT.md);
regenerate with `python benchmarks/benchmark_suite.py`.

| measurement | result |
|---|---|
| scan vs index, `dst_port = 443` | 100K **356×** · 500K **258×** · 1M **140×** faster |
| columnar vs row-store (one column) | **12.5× less data**, ~1.9× faster (200K rows) |
| write throughput by batch | batch 1: 104 → batch 100: ~11K → batch 1000: ~91K packets/s |
| concurrent clients (1 / 4 / 8) | ~1,100 / ~1,190 / ~1,060 queries/s (GIL-bound) |

*(The index-vs-scan speedup narrows at 1M because a non-unique equality returns
~N/10 matching rows.)*

---

## Scope & honest limitations

- **IPv4 only.** The uint32 schema means IPv6 (and VLAN-tagged) frames are
  **discarded by the parser**, not mis-stored.
- **The bit-trie is memory-heavy at very large N** (a node per address bit); a
  path-compressed/radix trie would be the production answer.
- **Concurrency is GIL-bound** — more clients don't scale CPU-bound query work
  linearly; the thread pool still helps with I/O-bound and bursty load.
- **`LIKE` supports only a trailing-`%` prefix**; the top-N heap's advantage is
  asymptotic (O(m log N) / O(N) memory), not a wall-clock race against C `sorted`.

## Future work

Path-compressed trie, IPv6/VLAN decoding, TCP stream reassembly, BPF capture
filters, richer SQL (aggregates, joins), and the `pcapng` format.

## Documentation

[CLAUDE.md](CLAUDE.md) — architecture and phase plan · [CONTRACTS.md](CONTRACTS.md)
— module contracts · [benchmarks/REPORT.md](benchmarks/REPORT.md) — benchmark report.
