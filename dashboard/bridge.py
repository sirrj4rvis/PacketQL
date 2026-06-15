"""HTTP bridge: browser (HTTP/JSON) <-> PacketQL TCP server (binary wire protocol).

Start the PacketQL server first (e.g. `python -m packetql.server --store data/demo_store`),
then `python dashboard/bridge.py`. Serves http://127.0.0.1:5000 with CORS open so
dashboard/index.html works straight from file://.

Honest scope notes (the read-only query server is not modified):
  * STATS exposes only the store's row count, not capture-pipeline drops -> drop_rate_pct
    is always 0.0. packets/sec and bytes/sec are DERIVED by sampling row_count and
    SUM(size) over time, so they are non-zero only while a live capture appends to the
    served store.
  * PacketQL SQL uses `proto` (not `protocol`) and has no `AS` aliases; the dashboard
    queries use the real grammar.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from packetql.schema import int_to_ip  # noqa: E402
from packetql.server import OK, QUERY, STATS, decode_result, recv_frame, send_frame  # noqa: E402

PQL_HOST, PQL_PORT = "127.0.0.1", 9999
IP_COLS = {"src_ip", "dst_ip"}
WINDOW = 65  # seconds of samples to keep

app = Flask(__name__)
_samples: "list[tuple[float, int, int]]" = []   # (epoch, total_packets, total_bytes)
_lock = threading.Lock()
_start = time.time()


class WireError(OSError):
    """Transport-level failure talking to the PacketQL server."""


def _wire(kind: int, payload: bytes = b"") -> "tuple[int, bytes]":
    last = None
    for _ in range(3):                          # small retry: rides over a transient store-write window
        try:
            sock = socket.create_connection((PQL_HOST, PQL_PORT), timeout=3)
            try:
                send_frame(sock, kind, payload)
                return recv_frame(sock)
            finally:
                sock.close()
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise WireError(str(last))


def pql_query(sql: str):
    status, payload = _wire(QUERY, sql.encode())
    if status != OK:
        raise ValueError(payload.decode())          # SQL/engine error (not a transport failure)
    cols, rows = decode_result(payload)
    rows = [[int_to_ip(v) if cols[j] in IP_COLS else v for j, v in enumerate(r)] for r in rows]
    return cols, rows


def pql_total_packets() -> int:
    _, payload = _wire(STATS)                       # "rows=N queries=M workers=W"
    kv = dict(p.split("=", 1) for p in payload.decode().split() if "=" in p)
    return int(kv.get("rows", 0))


def _sampler():
    """Once a second, record (time, total_packets, total_bytes) for rate + timeseries."""
    last_bytes = 0
    while True:
        try:
            rows = pql_total_packets()
            try:
                _, r = pql_query("SELECT SUM(size) FROM packets")
                last_bytes = int(r[0][0]) if r and r[0] and r[0][0] is not None else last_bytes
            except Exception:                       # keep the sample fresh even if SUM hiccups mid-write
                pass
            now = time.time()
            with _lock:
                _samples.append((now, rows, last_bytes))
                while _samples and _samples[0][0] < now - WINDOW:
                    _samples.pop(0)
        except Exception:
            pass                                    # server down -> stop appending; /api/stats goes stale -> 503
        time.sleep(1)


def _rate(field: int) -> float:
    with _lock:
        if len(_samples) < 2:
            return 0.0
        now = time.time()
        recent = [s for s in _samples if s[0] >= now - 5] or _samples[-2:]
        dt = recent[-1][0] - recent[0][0]
        return max(0.0, (recent[-1][field] - recent[0][field]) / dt) if dt > 0 else 0.0


@app.after_request
def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.get("/api/stats")
def api_stats():
    with _lock:
        latest = _samples[-1] if _samples else None
    if latest is None or latest[0] < time.time() - 4:   # no fresh sample -> PacketQL unreachable
        return jsonify(error="PacketQL server unreachable"), 503
    return jsonify(total_packets=latest[1], packets_per_sec=round(_rate(1)),
                   bytes_per_sec=round(_rate(2)), drop_rate_pct=0.0,
                   uptime_sec=int(time.time() - _start))


@app.get("/api/timeseries")
def api_timeseries():
    with _lock:
        s = list(_samples)
    seconds, captured, dropped = [], [], []
    for i in range(1, len(s)):
        seconds.append(int(s[i][0]))
        captured.append(max(0, s[i][1] - s[i - 1][1]))
        dropped.append(0)                           # drops aren't exposed by the query server
    return jsonify(seconds=seconds, captured=captured, dropped=dropped)


@app.route("/api/query", methods=["POST", "OPTIONS"])
def api_query():
    if request.method == "OPTIONS":
        return ("", 204)                            # CORS preflight
    sql = (request.get_json(silent=True) or {}).get("sql", "").strip()
    if not sql:
        return jsonify(error="empty query"), 400
    t0 = time.time()
    try:
        cols, rows = pql_query(sql)
    except WireError as exc:
        return jsonify(error=f"PacketQL unreachable: {exc}"), 503
    except ValueError as exc:
        return jsonify(error=str(exc))              # SQL error -> 200 (connection is fine)
    return jsonify(columns=cols, rows=rows, row_count=len(rows),
                   execution_ms=round((time.time() - t0) * 1000))


if __name__ == "__main__":
    threading.Thread(target=_sampler, daemon=True).start()
    print("PacketQL bridge on http://127.0.0.1:5000  (proxying PacketQL at "
          f"{PQL_HOST}:{PQL_PORT}). Open dashboard/index.html.")
    app.run(host="127.0.0.1", port=5000, threaded=True)
