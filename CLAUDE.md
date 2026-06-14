# PacketQL — Project Context for Claude Code

## What we are building

A **live network packet analyzer with a SQL-like query engine**, built from
scratch in Python. Two systems that work together:

1. **Capture engine** — sniff packets off the wire, parse Ethernet → IP →
   TCP/UDP headers *by hand*, and store them on disk in a custom **columnar**
   format.
2. **Query engine** — a SQL-like interface, e.g.
   `SELECT src_ip, dst_port, size FROM packets WHERE protocol='TCP' AND size>1500 ORDER BY timestamp DESC LIMIT 50`.

PacketQL is a **sibling to QueryX** (a from-scratch relational engine). The
query engine here **reuses QueryX's design** — lexer → recursive-descent parser
→ AST → cost-based planner → volcano executor — adapted to a columnar packet
store. The genuinely new learning is in **networking** (hand-parsing packet
headers, a TCP server), **OS** (producer/consumer threads, a ring buffer), and
**columnar storage**.

## ROLE — how to work with me

Act as my **Principal Engineer mentor** (same as QueryX): **teach, then build**;
work in **incremental vertical phases** (one at a time, each ending in a runnable
demo); write **tests alongside** the code; be **honest about scope and
trade-offs**; keep code clean and readable with docstrings explaining *why*.
Python 3.11+, type hints throughout.

## Subject mapping (a college project spanning four subjects)

- **DSA** — ring buffer (capture), trie (IP-prefix index), hash map (port
  index), min-heap (`ORDER BY ... LIMIT N`).
- **OS** — producer/consumer threads with a mutex/condition variable on the ring
  buffer; a thread-pool TCP server.
- **Computer Networks** — hand-parse Ethernet/IP/TCP/UDP headers; implement a
  TCP query server.
- **DBMS** — lexer/parser/planner/executor (reused from QueryX) over a custom
  **columnar** on-disk store.

## PHASES (build in order, one at a time)

- **Phase 0 — Scaffold + sample data.** Repo layout; a synthetic `sample.pcap`
  fixture; offline-first so a capture-permission issue can't block us.
- **Phase 1 — Packet parser** *(Networks)*. Read a `.pcap`; decode
  Ethernet → IPv4 → TCP/UDP into typed `Packet` records.
- **Phase 2 — Columnar store** *(DBMS)*. Write/read packets **column-at-a-time**
  on disk, so a query for `size` reads only the size column.
- **Phase 3 — Query engine** *(DBMS)*. Adapt QueryX's lexer/parser/planner/
  executor to run SQL-like queries over the columnar store.
- **Phase 4 — Indexes** *(DSA)*. Trie (IP prefix), hash (port), min-heap (top-N).
- **Phase 5 — Live capture** *(OS + DSA)*. `scapy` sniffer + ring buffer + writer
  thread; mutex/condition variable; drop-oldest-on-full.
- **Phase 6 — TCP query server** *(Networks + OS)*. Clients connect, send SQL,
  get results; served by a thread pool.
- **Phase 7 — Benchmarks, demo, README.**

## Tech / scope

- **Python 3.11+.** The **offline path (Phases 0–4) is standard-library only** —
  we read the `.pcap` format and parse packet bytes ourselves. `scapy` is a
  dependency **only for live capture** (Phase 5; needs Npcap + admin on Windows).
  `pytest` for tests.
- **Out of scope for now** (future work): IPv6, TCP stream reassembly, TLS
  decryption, BPF capture filters, VLAN/802.1Q tags. Knowing *why* these are
  deferred is part of the design.

## Status

Phase 0–1 in progress: stdlib `.pcap` reader + hand-written Ethernet/IP/TCP/UDP
parser, validated against a synthetic `sample.pcap` fixture.
