# PacketQL — Interview Defense Pack

Rehearse **out loud**. For each component: the **question**, your **30-second answer**, the
**follow-up** they push with, and the **trap** to avoid. Every claim traces to the code.

PacketQL is the **sibling to QueryX**: it reuses QueryX's query-engine shape (lexer → parser →
planner → executor) but over a **columnar** store, and adds the genuinely new parts —
**networking** (hand-parsed headers, a TCP server), **OS** (ring buffer, threads, a
readers-writer lock), and **columnar + vectorized** execution. The strongest thing you can say
in an interview: *"I designed a query engine once and re-applied it to a different storage model
— here's what transferred and what didn't."*

Over-prepare: **#3 (columnar)**, **#4 (the three indexes)**, and **#6 (ring buffer/threads)**.

---

## Rapid-fire facts to memorize

| Thing | Value | Where |
|---|---|---|
| Schema | 9 fixed-width integer columns, **uint32 IPs**, raw IANA proto byte | `schema.py`, `storage/columnar.py` |
| Bytes/packet on disk | 25 across 9 column files (vs ~60 row store) | `storage/columnar.py` |
| Random access | row N of a column at byte offset **N × width** → O(1) seek | `storage/columnar.py` `read_rows` |
| Durability | **batched fsync** per write batch (default 1000) | `ColumnWriter.flush` |
| Vectorized batch | **1024 rows** per executor step | `ColumnStore.iter_column` |
| IP index | **bit-level trie, depth 32** (prefix/subnet queries) | `index/trie.py` |
| Port index | **direct-address hash, 65536 buckets** | `index/hash_index.py` |
| Protocol index | **bitmap** (big-int AND/OR, O(n) build) | `index/bitmap.py` |
| Ring buffer | preallocated head/tail, **drop-oldest** on full | `capture/ringbuffer.py` |
| Wire protocol | `[4-byte len][1-byte type]` (QUERY/PING/STATS) | `server.py` |
| Concurrency | thread pool + **writer-preferring RWLock** | `server.py` |
| Test count | 64 passing | `pytest` |

---

## 1. "What is PacketQL, and how does a query flow through it?"

**Answer:** It's a network packet analyzer with a SQL query engine, built from scratch. Two
halves. **Capture:** frames come off the wire (or a `.pcap`), a hand-written parser decodes
Ethernet → IPv4 → TCP/UDP/ICMP into a fixed `PacketRecord`, records flow through a **ring
buffer** to a **writer thread** that appends them to a **columnar store** and updates indexes
incrementally. **Query:** SQL goes through a **lexer → recursive-descent parser → cost-estimating
planner → vectorized executor** that reads only the needed columns, optionally via the bit-trie /
port-hash / bitmap indexes. You can query locally or over a **binary-protocol TCP server** with a
thread pool.

**Trap:** Don't blur it with QueryX. Be crisp: *"QueryX is a general relational engine, row-based
with WAL; PacketQL is an analytics engine, columnar and vectorized, over an append-only packet
stream. Same query-engine architecture, different storage model — chosen to fit the workload."*

---

## 2. "You parse packets by hand. Walk me through it — and the checksum." *(Networks)*

**Answer:** `parse_packet` takes raw frame bytes and decodes the layers by offset: Ethernet (14
bytes) → check the ethertype is IPv4 (`0x0800`) → IPv4 header (read IHL to get its real length)
→ then TCP or UDP ports, or ICMP. Before trusting the IP header I **verify its checksum** with
the **one's-complement sum**: sum all 16-bit words including the checksum field, fold the
carries, and a valid header sums to `0xFFFF`. Frames that are non-IPv4, truncated, or fail the
checksum are **discarded** (`parse_packet` returns `None`) — the same integrity check Wireshark
does.

**Follow-up — "why discard non-IPv4?"** My schema stores IPs as **uint32**, so it's IPv4-only by
design. IPv6 (128-bit) and VLAN-tagged frames don't fit and are dropped at the parser rather than
mis-stored — an honest, documented scope limit, not a silent bug.

**Trap:** Don't hand-wave the checksum as "I check it's valid." Say *one's-complement sum folds
to 0xFFFF* — that specific phrase proves you implemented it. And note you read **IHL** to handle
variable-length IP headers (options), not a hard-coded 20 bytes.

---

## 3. "Why columnar storage? What does it buy you, and what does it cost?" *(DBMS — over-prepare)*

**Answer:** Each of the 9 columns is its own file of **fixed-width** values. Two payoffs: (1)
**column pruning** — a query for `size` reads only `size.col`, not the other 8 columns, so an
analytical scan over one or two columns moves far less data; (2) **O(1) random access** — because
values are fixed-width, row N of a column is at byte offset **N × width**, a single seek, no
scan. On disk a packet is **25 bytes across 9 files vs ~60 in a naive row store**. Writes are
**batched and fsync'd per batch**, which is the difference between hundreds and tens-of-thousands
of packets/sec, and reads go through a small **page-cache buffer pool**. `meta.json` records the
row count and each column's expected size for an **integrity check on open**.

**Follow-up — "when is columnar the wrong choice?"** For **OLTP** — point inserts, updates, and
reconstructing a whole row. Rebuilding one packet means touching all 9 files; a row store keeps
it contiguous. That's the classic row-vs-column trade-off, and exactly why **QueryX (a general
RDBMS) is row-based and PacketQL (analytics) is columnar** — I chose each to fit its workload.

**Follow-up — "how do real columnar stores go further?"** Parquet / ClickHouse / DuckDB add
**compression** (run-length, dictionary, delta) and per-block **min/max zone maps** to skip
blocks. PacketQL is fixed-width and uncompressed — simpler, and an honest simplification.

**Trap:** Don't claim columnar is "just faster." It's faster *for analytical scans of few
columns over many rows*, slower for whole-row OLTP. Naming the trade-off is the whole point.

---

## 4. "You built three different indexes. Why three? Explain each." *(DSA — over-prepare)*

**Answer:** Different columns have different shapes, so each gets the structure that fits:

- **IP columns → a bit-level trie (depth 32).** An IPv4 address is a 32-bit integer, so the trie
  branches one bit at a time, 32 levels deep. The point is **prefix/subnet queries** like
  `src_ip LIKE '192.168.%'`: descend the known prefix bits, then collect the subtree's rows in
  **O(prefix_bits + matches)**, not O(n). Every node carries a **subtree count** so the planner
  can estimate selectivity without walking it.
- **Port columns → a direct-address hash (65536 buckets).** Ports are bounded 0–65535, so I use
  one bucket per possible port — **O(1) lookup with no hashing and no collisions**, because the
  key space is small and fully enumerable.
- **Protocol → a bitmap index.** Protocol is **low-cardinality** (TCP/UDP/ICMP — a handful of
  values). One bitmap per value, bit *r* set iff row *r* has that value, stored as a Python big
  integer so combining predicates is just bitwise `&` / `|`. Built in **O(n)** via a byte buffer
  (repeated big-int OR would be O(n²)).

Then `choose()` does **compound predicate pushdown**: it splits the top-level ANDs, resolves
each conjunct through the right index, and **intersects** the resulting row-sets — only using the
index path when it's more selective than a full scan.

**Follow-up — "why not a hash for IPs too?"** Because you need **subnet/prefix** queries, which a
hash can't do (no order/structure). Same reason QueryX uses a B+ tree over a hash for ordered
queries.

**Follow-up — "where does each break down?"** Honest answers: the **bitmap** explodes for
high-cardinality columns (one bitmap per distinct value) — that's why it's only on `proto`, not
on IPs; production uses **compressed bitmaps (Roaring, WAH/EWAH)**. The **bit-trie** is
**memory-heavy at very large N** (a node per address bit); the production answer is a
**path-compressed / radix trie** (what the Linux kernel uses for routing tables). The
**direct-address hash** only works because ports are bounded.

**Trap:** Don't say "I used a trie because it's fast." Say *why* a trie specifically: bit-level
structure gives you subnet prefix matching that a hash or sorted array can't do cheaply.

---

## 5. "Your executor is vectorized. What does that mean, and how is it different from QueryX?" *(DBMS)*

**Answer:** Instead of pulling one row at a time (the volcano model), the executor processes a
**batch of 1024 rows per step** through a generator pipeline, with predicates evaluated over
whole column batches. That **amortizes per-call and interpreter overhead** — which matters a lot
in Python, where a function call per row is expensive. The planner does **column pruning** (reads
only referenced columns) and **cost estimation** to pick an index path vs a scan.

**Follow-up — "volcano vs vectorized trade-off?"** This is the great tie-in: **QueryX is volcano
(pull, one row); PacketQL is vectorized (batches)** — I built both. Volcano is simpler and
pipelines naturally with early termination (`LIMIT` stops the scan); vectorized amortizes
overhead and wins on analytical scans but materializes a batch at a time. Modern analytical
engines (DuckDB) are vectorized for exactly this reason.

**Trap:** Don't claim vectorized is strictly better. It's better *for analytical scans*; volcano
gives cleaner pipelining and early-out. Knowing both sides is the signal.

---

## 6. "Walk me through the capture pipeline — the ring buffer and threading." *(OS — over-prepare)*

**Answer:** A classic **producer/consumer**. The producer parses frames and `put`s
`PacketRecord`s into a **ring buffer**; a **writer thread** pulls them in batches, appends to the
columnar store, and updates indexes incrementally. The ring buffer is **preallocated** (no
per-packet allocation on the hot path), with a `head` pointer advancing on write and `tail` on
read, both modulo capacity. When it's **full it drops the oldest** packet and counts it — lossy
on purpose, because **you can't ask the wire to slow down**; a passive sniffer can't backpressure
a NIC. A `threading.Condition` lets the writer **sleep when empty** instead of spinning. Under
load it **adapts**: when the recent drop rate exceeds 5%, it doubles the write batch (fewer
fsyncs, faster drain).

**Follow-up — "why a lock if Python has the GIL?"** The GIL makes a single bytecode atomic, but
a multi-field `PacketRecord` publish is several operations — pointer arithmetic plus the slot
write. Doing them **under the lock publishes the record atomically**; without it, a reader could
see a half-updated slot. And honestly, the **GIL caps CPU parallelism** — the real win of the
threads here is **overlapping fsync I/O with capture**, plus clean structure, not CPU
concurrency.

**Trap:** Don't oversell threading as "parallel speedup." Be upfront: GIL-bound, so the benefit
is I/O overlap and backpressure handling. And `drop-oldest` is a *policy choice* (vs drop-newest)
— mention you picked it deliberately.

---

## 7. "Your TCP server uses a custom binary protocol. Why, and how does it work?" *(Networks + OS)*

**Answer:** Request is `[4-byte length][1-byte type][payload]` (type 1=QUERY, 2=PING, 3=STATS);
response is `[4-byte length][1-byte status][payload]`. The length prefix matters because **TCP is
a byte stream with no message boundaries** — a single `recv()` can return a partial message or
two coalesced ones — so every read **loops until exactly `length` bytes arrive** (`recv_exact`).
Results are encoded **column-major in binary**. Concurrency is a **thread pool**: the accept loop
is a producer putting connections on a **bounded queue**, and worker threads are consumers.
Each connection gets its own `ColumnStore` (no shared mutable state); the read-only indexes are
shared, guarded by a **writer-preferring readers-writer lock** so many readers run concurrently
but a writer (if one ever updates indexes live) gets exclusive access without starving.

**Follow-up — "why writer-preferring?"** To prevent **writer starvation**: once a writer is
waiting, new readers block (`writers_waiting > 0`), so a steady stream of readers can't postpone
the writer forever. It's the classic readers-writers synchronization problem.

**Follow-up — "does the thread pool scale?"** Honestly, not for CPU-bound query work — **GIL
again**. My benchmark shows roughly flat throughput at 1/4/8 clients. The pool still helps with
I/O-bound and bursty load and is the right *structure*; true CPU scaling would need processes or
a C extension.

**Trap:** The #1 thing they want to hear is **"TCP has no message boundaries, so I frame with a
length prefix and loop the reads."** Lead with that.

---

## 8. "What SQL does it support?" *(DBMS — ported from QueryX)*

**Answer:** `SELECT [DISTINCT] cols | aggregates | * FROM packets [WHERE ...] [GROUP BY ...
[HAVING ...]] [ORDER BY ...] [LIMIT n]`, plus `EXPLAIN`. Aggregates `COUNT(*) / COUNT / SUM /
AVG / MIN / MAX`, scalar or grouped via a **hash-aggregate**; operators `= != <> < > <= >=` with
`AND / OR / NOT`; `LIKE 'prefix%'` for subnets. The planner picks bitmap/hash/trie and intersects
them when more selective than a scan. This analytics layer was **ported from QueryX's design** —
same hash-aggregate, same EXPLAIN idea.

**Follow-up — "no JOIN?"** Right, and deliberately: PacketQL has a **single, immutable packet
stream**, so a join would be a self-join with no natural key — not a meaningful packet-analytics
operation. QueryX (multi-table) has the two-table INNER JOIN; PacketQL doesn't need it.

**Trap:** Don't list features you don't have. The honest framing — "the analytical SELECT
surface, fully integrated through real indexes and a cost-estimating planner; no DML/DDL because
packets are append-only" — is stronger than overclaiming.

---

## Honest limitations (say these before they ask — it builds credibility)

- **IPv4 only** — the uint32 schema discards IPv6/VLAN frames at the parser.
- **Bit-trie is memory-heavy at very large N** — a path-compressed/radix trie is the production answer.
- **Concurrency is GIL-bound** — threads give I/O overlap and structure, not CPU scaling.
- **`LIKE` supports only a trailing-`%` prefix** (subnet matching), not general patterns.
- **Index persistence uses `pickle`** (with an mtime freshness check) — convenient, but not a
  portable/secure on-disk format; a real system would use a versioned binary layout.
- **No compression / zone maps** — fixed-width columns; real columnar stores compress and skip blocks.

---

## Killer one-liners (drop these to signal depth)

- "**TCP has no message boundaries** — so I length-prefix every message and loop the reads."
- "Columnar is a **workload choice**: great for scanning a few columns over many rows, bad for
  whole-row OLTP — which is exactly why my other engine, QueryX, is row-based."
- "Three indexes because three column shapes: **trie for IP prefixes, direct-address hash for
  bounded ports, bitmap for low-cardinality protocol** — then I intersect their row-sets."
- "You **can't backpressure the wire**, so the ring buffer drops the oldest packet and counts it
  — lossiness is a feature of a sniffer, not a bug."
- "I built **volcano in QueryX and vectorized here**, so I can argue the execution-model
  trade-off from having implemented both."

---

*See also: [README.md](README.md), [CONTRACTS.md](CONTRACTS.md), and
[benchmarks/REPORT.md](benchmarks/REPORT.md). Sibling project: QueryX (relational, row-based, WAL).*
