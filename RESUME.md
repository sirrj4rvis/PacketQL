# PacketQL — Resume Bullets

Factual, defensible bullets. Every claim traces to the code, the benchmark suite
([benchmarks/REPORT.md](benchmarks/REPORT.md)), or the pytest suite (currently 60 tests —
re-check with `pytest` before submitting). PacketQL is the **sibling to QueryX**; see the
combined "portfolio framing" at the bottom for using both together.

## One-line project header

**PacketQL — a network packet analyzer with a SQL query engine, built from scratch in Python**
(hand-parsed packet headers with IP-checksum verification, fixed-width columnar storage, three
index types, a producer/consumer ring-buffer capture pipeline, and a binary-protocol TCP
server). Offline engine is standard-library only.

## Concise bullets (pick 2–4)

- Built a **network packet analyzer with a SQL query engine** from scratch in Python:
  hand-decoded Ethernet/IPv4/TCP/UDP/ICMP headers (with **one's-complement IP-checksum
  verification**), a fixed-width **columnar** store, a cost-estimating planner, and a
  **vectorized (1024-row-batch) executor** — 60-test pytest suite.
- Implemented **three purpose-built indexes** — a bit-level depth-32 **IP trie** (subnet/prefix
  queries), a direct-address **port hash**, and a **protocol bitmap** — with **compound
  predicate pushdown** (intersecting index row-sets); indexed equality runs **100–350× faster
  than a full scan** in microbenchmarks.
- Engineered a **producer/consumer capture pipeline**: a preallocated **ring buffer**
  (drop-oldest under load) feeding a writer thread doing **batched fsync** appends and
  incremental indexing, with **adaptive batch sizing** under backpressure.
- Wrote a **binary-protocol TCP query server** with a **thread pool** and a writer-preferring
  **readers-writer lock**, framing every message with a length prefix (TCP has no message
  boundaries) and looping partial reads.
- Designed a **columnar** on-disk format (9 fixed-width columns, **O(1) row seek** at byte
  offset `N×width`, page-cache buffer pool, integrity check on open) — **~12× less data read**
  for single-column scans than a row store.

## Detailed bullets (for a projects section)

- **PacketQL — packet analyzer + SQL query engine (Python).** Captures frames (offline `.pcap`
  or live via scapy), **hand-parses** Ethernet → IPv4 → TCP/UDP/ICMP with IP-header checksum
  verification, and stores them **column-at-a-time** on disk. Queries run through a hand-written
  lexer + recursive-descent parser, a **cost-estimating planner** with column pruning, and a
  **vectorized executor** over **bit-trie / port-hash / bitmap** indexes with compound pushdown.
  Includes a producer/consumer ring-buffer capture pipeline and a binary-protocol thread-pool TCP
  server with a readers-writer lock. Adds analytics SQL — `GROUP BY`/`HAVING`, `COUNT/SUM/AVG/
  MIN/MAX`, `DISTINCT`, `EXPLAIN` — via a hash-aggregate. 60 pytest cases; charted benchmarks.
- **Spans four subjects in one system:** Computer Networks (header decoding, TCP server),
  Operating Systems (ring buffer + condition variable, thread pool, readers-writer lock), Data
  Structures (trie, hash, bitmap, ring buffer, top-N heap), and Databases (columnar store, SQL
  lexer/parser/planner/executor).

## Skills / keywords (ATS)

Network programming, packet parsing, protocol decoding (Ethernet/IP/TCP/UDP/ICMP), columnar
storage, query engines, SQL parsing, recursive-descent parsing, query optimization, vectorized
execution, tries, hashing, bitmap indexes, ring buffers, producer/consumer, multithreading,
readers-writer locks, TCP servers, binary protocols, data structures, operating systems, Python,
pytest.

---

## Portfolio framing — using QueryX + PacketQL together

If you have room for both, frame them as a **pair that shows range and architectural reuse**:

> Built two from-scratch engines in Python (stdlib only). **QueryX** — a relational database
> engine (paged storage, B+ tree/hash indexes, volcano executor, cost-based optimizer, WAL crash
> recovery; 327 tests). **PacketQL** — a packet analyzer + SQL engine that **reuses QueryX's
> query-engine architecture** over a **columnar** store, adding hand-parsed networking and a
> threaded TCP server (60 tests). Together they demonstrate database internals end-to-end and the
> ability to re-apply a design across two storage models (row vs columnar, volcano vs vectorized).

Lead with **QueryX** (the database-internals depth interviewers probe) and use **PacketQL** as
the breadth + reuse story.
