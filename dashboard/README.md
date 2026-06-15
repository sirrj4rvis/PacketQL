# PacketQL Dashboard

A single-file, dependency-light web dashboard for PacketQL: live stat cards, a
traffic timeline, protocol distribution, top talkers, port activity, and a raw
query console — all over a thin Flask HTTP bridge that speaks PacketQL's binary
wire protocol.

```
browser (index.html, file://)
        │  HTTP + JSON
        ▼
dashboard/bridge.py  (Flask, :5000)
        │  binary wire protocol  [4-byte len][1-byte type]
        ▼
PacketQL TCP server (:9999)  ──►  columnar store on disk
```

- **Frontend:** `index.html` — pure HTML/CSS/vanilla JS, Chart.js from CDN. No build step.
- **Bridge:** `bridge.py` — Flask, ~90 lines, imports PacketQL's own wire-protocol helpers.

## Run it

```bash
pip install -r dashboard/requirements.txt
```

**1 — have a store to query.** Either build the demo store:
```bash
python demo.py                       # creates data/demo_store (5 packets)
```
…or capture live traffic (Administrator terminal, needs Npcap):
```bash
python -c "from packetql.capture.pipeline import capture_live; capture_live('data/live_store', count=2000, timeout=60)"
```

**2 — start the PacketQL TCP server** (point it at your store):
```bash
python -m packetql.server --store data/demo_store      # or data/live_store
```

**3 — start the bridge:**
```bash
python dashboard/bridge.py                             # http://127.0.0.1:5000
```

**4 — open the dashboard:** double-click `dashboard/index.html` (opens as `file://`).
The bridge sends permissive CORS headers so this works without a web server.

> Tip: set `window.PQL_DEBUG = true` in the browser console to see polling logs.

## Live metrics (read this — honest scope)

The dashboard adapts to what the **read-only query server** actually exposes; it does
**not** modify the PacketQL engine.

| Metric | Source | Note |
|---|---|---|
| Total packets | `STATS` row count | real |
| Packets/sec, Bytes/sec | bridge samples `row_count` / `SUM(size)` over time | **non-zero only while a live capture is appending to the served store** |
| Drop rate | — | always `0.0` — drops are a *capture-pipeline* metric; the query server doesn't expose them |
| Uptime | bridge process uptime | real |

So for the **liveliest** dashboard, run a live capture **into the same store the server
is serving** (the server re-reads the store per connection, so it sees the row count
grow). With a static store you still get real totals, protocol mix, top talkers, and
port activity — just with zero rates.

## Query grammar (what the console accepts)

PacketQL's SQL — note `proto` (not `protocol`) and **no `AS` aliases**:

```sql
SELECT [DISTINCT] cols | COUNT(*)|SUM/AVG/MIN/MAX(col) | * FROM packets
  [WHERE expr] [GROUP BY cols [HAVING expr]] [ORDER BY col [ASC|DESC]] [LIMIT n]
EXPLAIN <select>
```
Columns: `ts, src_ip, dst_ip, src_port, dst_port, proto, size, flags, ttl`
(`src_ip`/`dst_ip` are returned as dotted strings by the bridge). Example:
```sql
SELECT src_ip, dst_port, COUNT(*) FROM packets WHERE proto = 6 GROUP BY src_ip, dst_port ORDER BY COUNT(*) DESC LIMIT 20
```

## Endpoints (for reference)

- `GET  /api/stats` → `{total_packets, packets_per_sec, bytes_per_sec, drop_rate_pct, uptime_sec}` (503 if PacketQL is unreachable)
- `GET  /api/timeseries` → `{seconds[], captured[], dropped[]}` (60s rolling window)
- `POST /api/query` `{sql}` → `{columns[], rows[][], row_count, execution_ms}` or `{error}`

## Troubleshooting

- **Status dot is red** — the PacketQL server isn't running on `:9999`, or `bridge.py` isn't running. Start both.
- **All rates are 0** — expected for a static store; run a live capture into the served store (see above).
- **Console error `no such column 'protocol'`** — use `proto`. **`unexpected ... AS`** — PacketQL has no `AS` aliases.
- **Port differs** — edit `PQL_HOST/PQL_PORT` in `bridge.py` (and `API` in `index.html` if you move the bridge).
