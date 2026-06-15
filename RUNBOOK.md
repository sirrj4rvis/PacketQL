# PacketQL — Runbook

Every command needed to run PacketQL from scratch, in order. Copy-paste friendly
(PowerShell on Windows; the same commands work in any shell).

> **Mental model:** everything except **live capture** is **standard-library only
> and needs no administrator rights**. Live capture is the *only* part that needs
> `scapy` + Npcap + an **Administrator** terminal.

## Contents
1. [Prerequisites](#prerequisites)
2. [Get into the project](#0--get-into-the-project)
3. [Verify the build (tests)](#1--verify-the-build--run-the-tests)
4. [End-to-end offline demo](#2--end-to-end-offline-demo)
5. [Run your own SQL](#3--run-your-own-sql)
6. [Query over the TCP server](#4--query-over-the-tcp-server)
7. [Live capture](#5--live-capture-administrator--scapynpcap)
8. [Benchmarks](#6--benchmarks)

---

## Prerequisites

| Need | For | Install |
|---|---|---|
| **Python 3.11+** | everything | https://python.org |
| **pytest** | running the test suite | `pip install pytest` |
| **scapy + Npcap** | live capture only | `pip install scapy` + [Npcap](https://npcap.com) (install as Admin) |

The offline engine (parsing a `.pcap`, storage, indexes, SQL, the TCP server) uses
**only the Python standard library** — no install step.

---

## 0 · Get into the project

```powershell
cd d:\PacketQL
```

On a fresh machine, clone first:

```powershell
git clone https://github.com/sirrj4rvis/PacketQL.git
cd PacketQL
```

---

## 1 · Verify the build — run the tests
*(no admin, standard library only)*

```powershell
python -m pytest -q
```

**Expect:** `61 passed`. If this passes, the engine is sound end to end.

---

## 2 · End-to-end offline demo
*(no admin, standard library only)*

```powershell
python tools/make_fixture_pcap.py     # writes tests/fixtures/sample.pcap (6 frames, 1 corrupt)
python demo.py                        # parse -> columnar store -> indexes -> queries
```

**Expect:** `parsed + stored 5 packets … (1 bad-checksum frame discarded, 0 dropped)`,
then result tables for a full scan, an `IndexScan [bitmap proto=6]`, a `LIKE` subnet
match, a `GROUP BY proto` with `COUNT(*)`/`SUM(size)`, `DISTINCT`, and an `EXPLAIN`.
This is the showcase: capture → columnar store → indexes → SQL.

---

## 3 · Run your own SQL
*(no admin)*

**One-liner form (foolproof):**

```powershell
python query.py --store data/demo_store "SELECT COUNT(*) FROM packets"
python query.py --store data/demo_store "SELECT proto, COUNT(*), SUM(size) FROM packets GROUP BY proto ORDER BY COUNT(*) DESC"
python query.py --store data/demo_store "SELECT src_ip, dst_ip, dst_port, size, flags FROM packets WHERE proto = 6 ORDER BY size DESC LIMIT 5"
python query.py --store data/demo_store "SELECT src_ip, dst_port FROM packets WHERE src_ip LIKE '192.168.%'"
python query.py --store data/demo_store "EXPLAIN SELECT dst_port, COUNT(*) FROM packets WHERE proto = 6 GROUP BY dst_port"
```

**Interactive shell:**

```powershell
python query.py --store data/demo_store
```

Then at the `pktql>` prompt type **only the SQL** (no `pktql>` prefix, one statement
at a time):

```
SELECT proto, COUNT(*) FROM packets GROUP BY proto;
```

Type `quit` to exit.

### Query language

```
SELECT [DISTINCT] cols | aggregates | * FROM packets
  [WHERE expr] [GROUP BY cols [HAVING expr]] [ORDER BY col [ASC|DESC]] [LIMIT n]
EXPLAIN <select>
```

- Aggregates: `COUNT(*)`, `COUNT/SUM/AVG/MIN/MAX(col)`
- Operators: `= != <> < > <= >=` with `AND / OR / NOT` and parentheses
- `LIKE 'prefix%'` for IP subnets (e.g. `src_ip LIKE '192.168.%'`)
- Columns: `ts, src_ip, dst_ip, src_port, dst_port, proto, size, flags, ttl`
- IP literals like `'192.168.0.2'` are converted to uint32 in the parser

---

## 4 · Query over the TCP server
*(no admin — two terminals)*

**Terminal A** — start the server:

```powershell
cd d:\PacketQL
python -m packetql.server --store data/demo_store
```

**Expect:** `PacketQL server on 127.0.0.1:9999 (4 workers, 5 packets). Ctrl-C to stop.`
Leave it running.

**Terminal B** — connect the client:

```powershell
cd d:\PacketQL
python query_client.py
```

Then at `pktql>`:

```
.ping
.stats
SELECT proto, COUNT(*) FROM packets GROUP BY proto;
quit
```

**Expect:** `.ping` → `pong`; `.stats` → `rows=5 …`; the query returns a table.
Stop the server in Terminal A with **Ctrl-C**.

---

## 5 · Live capture  (⚠ Administrator + scapy/Npcap)

**Terminal A — run PowerShell as Administrator:**

```powershell
cd d:\PacketQL
Remove-Item -Recurse -Force data\live_store -ErrorAction SilentlyContinue
python -c "from packetql.capture.pipeline import capture_live; p = capture_live('data/live_store', count=1000, timeout=60); print('captured', p.written, 'dropped', p.dropped)"
```

**Terminal B (normal) — generate IPv4 traffic immediately** so you capture TCP + UDP + ICMP:

```powershell
ping -n 20 8.8.8.8                 # IPv4 ICMP
nslookup github.com 8.8.8.8        # IPv4 UDP/53 (forced to an IPv4 resolver)
nslookup openai.com 8.8.8.8
curl http://example.com            # IPv4 TCP/80
curl https://www.wikipedia.org     # IPv4 TCP/443
```

When Terminal A prints `captured N dropped 0`, query it *(no admin needed)*:

```powershell
python query.py --store data/live_store "SELECT proto, COUNT(*), SUM(size) FROM packets GROUP BY proto ORDER BY COUNT(*) DESC"
python query.py --store data/live_store "SELECT src_ip, dst_ip, src_port, dst_port, size FROM packets WHERE src_port = 443 OR dst_port = 443 ORDER BY size DESC LIMIT 10"
```

**Expect:** three proto rows (TCP/UDP/ICMP) and your real HTTPS connections.

### Notes & gotchas

- **`written` < `count` is normal** — non-IPv4 frames (IPv6, ARP, multicast) are
  discarded by the parser (PacketQL is IPv4-only by the uint32 schema).
- **No UDP rows?** Your DNS may be going over IPv6 (discarded). Forcing
  `nslookup <host> 8.8.8.8` sends the query over IPv4 UDP so it gets captured.
- **`WHERE dst_port = 443` returns nothing** for inbound traffic: on a
  server→client packet, `443` is the *source* port. Use
  `WHERE src_port = 443 OR dst_port = 443`.
- **`captured 0`** — scapy chose an idle interface. List interfaces and name yours:

  ```powershell
  python -c "from scapy.all import conf; conf.ifaces.show()"
  # then pass the Name from the table, e.g.:
  python -c "from packetql.capture.pipeline import capture_live; p = capture_live('data/live_store', iface='Wi-Fi', count=1000, timeout=60); print('captured', p.written, 'dropped', p.dropped)"
  ```

- An **Npcap / permission error** means the terminal isn't elevated, or Npcap was
  installed without **WinPcap API-compatible Mode** — reinstall Npcap with that box checked.

---

## 6 · Benchmarks
*(no admin, optional — pure Python, no extra dependency)*

```powershell
python benchmarks/benchmark_suite.py
python benchmarks/index_benchmark.py
```

**Expect:** throughput tables (scan vs index, columnar vs row-store, write batching,
concurrent clients) matching [benchmarks/REPORT.md](benchmarks/REPORT.md).

---

## Fastest "does it work?" check

No admin, no scapy — proves the engine end to end in ~20 seconds:

```powershell
cd d:\PacketQL ; python -m pytest -q ; python demo.py
```

---

*More docs:* [README.md](README.md) · [CONTRACTS.md](CONTRACTS.md) (module contracts) ·
[INTERVIEW.md](INTERVIEW.md) (interview defense pack) · [benchmarks/REPORT.md](benchmarks/REPORT.md).
