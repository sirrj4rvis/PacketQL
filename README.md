# PacketQL

**A live network packet analyzer with a SQL-like query engine — built from scratch in Python.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![tests](https://img.shields.io/badge/tests-28%20passing-success)
![offline](https://img.shields.io/badge/offline%20engine-stdlib%20only-success)

Capture packets off the wire, parse Ethernet → IP → TCP/UDP headers **by hand**,
store them on disk in a custom **columnar** format, index them, and query the
traffic with SQL — locally or over a TCP server:

```sql
SELECT src_ip, dst_port, size FROM packets
WHERE protocol = 'TCP' AND size > 1500
ORDER BY size DESC LIMIT 50;
```

The query engine **reuses the design of [QueryX](../QueryX)** (lexer →
recursive-descent parser → AST → cost-based planner → volcano executor); the new
work is packet parsing, columnar storage, the producer/consumer capture
pipeline, and a thread-pool server. The **offline path uses only the Python
standard library** — it reads the `.pcap` format and decodes packet bytes
itself. `scapy` is needed only for live capture.

---

## Architecture

```
   live NIC (scapy)  ┐
                     ├─► packet parser ─► ring buffer ─► writer thread ─┐
   .pcap replay      ┘    Ethernet/IP/    producer/        parse +       │
                          TCP/UDP          consumer,        collect       ▼
                          (by hand)        drop-oldest               columnar store
                                                                     1 file / column,
                                                                     null bitmaps,
                                                                     dict-encoded protocol
                                                                          │
   client ──SQL over TCP──► thread-pool query server ──► query engine ────┘
                                                         lexer → parser → planner → executor
                                                         indexes: hash · IP-trie · top-N heap
```

## Built across four subjects

| Subject | What it demonstrates |
|---|---|
| **Computer Networks** | hand-decoding Ethernet/IP/TCP/UDP headers; a TCP query server |
| **Operating Systems** | a producer/consumer ring buffer (capture) and a thread pool (server) |
| **Data Structures** | hash index, IP trie (prefix), bounded top-N heap, ring buffer |
| **Databases** | a columnar store + a SQL lexer / parser / planner / executor |

---

## Quickstart (offline — no admin, standard library only)

```bash
python tools/make_sample_pcap.py   # write a synthetic data/sample.pcap
python demo_offline.py             # parse it (Ethernet/IP/TCP/UDP -> typed rows)
python demo_columnar.py            # store it column-by-column, round-trip + selective read
python demo_query.py               # run SQL over the store
python demo_index.py               # hash / trie / top-N indexes + speedups
python demo_capture.py             # the ring-buffer capture pipeline (offline)
pytest                             # 28 tests
```

Query interactively over any store:

```bash
python query.py --store data/store      # a prompt: type SQL, see boxed results + the plan
```

## Live capture (needs Npcap + Administrator)

```bash
pip install scapy                  # also install Npcap from https://npcap.com (run as Admin)
```
Then, in an **Administrator** terminal:
```bash
python -c "from packetql.capture.pipeline import capture_live; p = capture_live(count=50, timeout=20); p.flush_to_store('data/live_store'); print('captured', p.captured, 'dropped', p.dropped)"
python query.py                    # query the packets you just captured
```

## Query over TCP (a server + client)

```bash
python -m packetql.server          # thread-pool server over data/live_store (no admin needed)
python query_client.py             # connect and type SQL; results come back over the socket
```

### Example queries

```sql
SELECT protocol, dst_ip, dst_port, size FROM packets WHERE protocol = 'TCP' ORDER BY size DESC;
SELECT dst_ip, size FROM packets WHERE dst_port = 443;          -- uses the hash index
SELECT src_ip, dst_ip FROM packets WHERE src_ip LIKE '192.168.%'; -- uses the IP trie
```

Supported: `SELECT [cols|*] FROM packets [WHERE <predicate>] [ORDER BY col [ASC|DESC]] [LIMIT n]`;
operators `= != <> < > <= >=` with `AND / OR / NOT` and parentheses; `LIKE 'prefix%'`.

---

## Benchmarks

In-process microbenchmarks at **N = 100,000** packets (warm cache, single
machine) — *relative* behaviour, not production latency; they shift run to run.
Numbers match [benchmarks/REPORT.md](benchmarks/REPORT.md); regenerate with
`python benchmarks/benchmark_suite.py`.

| measurement | result |
|---|---|
| capture / replay throughput | ~197,500 packets/sec (0 dropped) |
| equality `dst_port = 443` | SeqScan 188 ms → HashIndex 96 ms (**2.0×**) |
| prefix `src_ip LIKE '10.0.5.%'` | SeqScan 150 ms → TrieScan 102 ms (**1.5×**) |
| selective read `SELECT size` | 14.5% of the store (one of eight columns) |

---

## Scope & limitations (honest)

- **IPv6 and 802.1Q VLAN frames are detected, not decoded** — they surface as
  `ETH-0x86dd` / `ETH-0x8100` with `NULL` fields rather than being mis-parsed.
- **The executor reads full projected columns**, so an index saves per-row
  predicate work, not column I/O — hence the modest 1.5–2× speedups. Production
  columnar engines skip non-matching blocks (zone maps / late materialization).
- **Read-only, single table.** PacketQL queries the `packets` stream; it has no
  `INSERT/UPDATE/JOIN/GROUP BY`/aggregates (those live in QueryX).
- **`LIKE` supports only a trailing-`%` prefix**; the top-N heap's win is
  asymptotic (O(m log N) / O(N) memory), not a wall-clock race against C `sorted`.
- Live capture assumes an **Ethernet** link type and needs **Npcap + Administrator**.

## Future work

Zone maps / block skipping, incremental on-disk flush (streaming capture →
queryable store), IPv6/VLAN decoding, richer SQL (aggregates, joins), and the
`pcapng` format.

## Documentation

See [CLAUDE.md](CLAUDE.md) for the architecture, the phase plan, and the design
rationale.
