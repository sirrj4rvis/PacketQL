"""Bridge (HTTP <-> PacketQL TCP) tests, with a focus on the failure paths that an
external runner cannot reach while the backend is up.

The bridge degrades in three documented ways that are easy to assert wrongly:
  * /api/stats -> 503 when no fresh sample exists (PacketQL unreachable / not sampled yet),
  * /api/query -> 503 when the TCP backend is actually down (WireError after retries),
  * /api/query -> 200 *with an error field* for SQL/engine errors (the connection is fine).
And one deliberate asymmetry:
  * /api/timeseries never 503s — it returns empty arrays when there is no data.

These run fully self-contained: a real QueryServer is started on an ephemeral port and
the bridge is pointed at it, so the "backend down" cases are driven by genuinely stopping
the server rather than by mocks.
"""

import os
import time

import pytest

from packetql.capture.pcap import read_packets
from packetql.capture.pipeline import capture_offline
from packetql.server import QueryServer
from dashboard import bridge

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")


def _store(tmp_path) -> str:
    d = str(tmp_path / "s")
    capture_offline(read_packets(FIXTURE), d)
    return d


def _take_sample() -> None:
    """One iteration of bridge._sampler, driven synchronously over the real wire path.

    Proves the live sampling loop works end-to-end; the real _sampler does exactly this
    once a second. After the backend stops, this would raise and append nothing — which
    is how /api/stats naturally goes stale and starts returning 503.
    """
    rows = bridge.pql_total_packets()
    _, r = bridge.pql_query("SELECT SUM(size) FROM packets")
    nbytes = int(r[0][0]) if r and r[0] and r[0][0] is not None else 0
    with bridge._lock:
        bridge._samples.append((time.time(), rows, nbytes))


@pytest.fixture
def live_server(tmp_path):
    """A real PacketQL server the bridge talks to, with bridge state isolated per test."""
    srv = QueryServer(_store(tmp_path), port=0, workers=2)
    srv.start()
    old_port = bridge.PQL_PORT
    bridge.PQL_PORT = srv.port
    with bridge._lock:
        bridge._samples.clear()
    try:
        yield srv
    finally:
        bridge.PQL_PORT = old_port
        srv.stop()
        with bridge._lock:
            bridge._samples.clear()


@pytest.fixture
def client():
    return bridge.app.test_client()


# --- /api/query: happy path, validation, and the 200-vs-503 error distinction ---

def test_query_valid_sql_returns_results(client, live_server):
    resp = client.post("/api/query", json={"sql": "SELECT COUNT(*) FROM packets"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["row_count"] == 1
    assert body["rows"][0][0] == 5          # the fixture pcap has 5 packets
    assert "execution_ms" in body


def test_query_empty_sql_returns_400(client, live_server):
    resp = client.post("/api/query", json={"sql": "   "})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_query_bad_sql_returns_200_with_error(client, live_server):
    # SQL/engine error: the connection is healthy, so the contract is 200 + error field
    # (NOT 503, which is reserved for transport failure). 'protocol' is not a column; the
    # real grammar uses 'proto'.
    resp = client.post("/api/query", json={"sql": "SELECT protocol FROM packets"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "error" in body
    assert "columns" not in body            # no result payload on an engine error


def test_query_503_when_backend_down(client, live_server):
    # Sanity: works while the backend is up...
    assert client.post("/api/query", json={"sql": "SELECT COUNT(*) FROM packets"}).status_code == 200
    # ...then genuinely kill it: _wire exhausts its retries and raises WireError -> 503.
    live_server.stop()
    resp = client.post("/api/query", json={"sql": "SELECT COUNT(*) FROM packets"})
    assert resp.status_code == 503
    assert "unreachable" in resp.get_json()["error"].lower()


# --- /api/stats: 200 with a fresh sample, 503 when stale/missing ---

def test_stats_200_with_fresh_sample(client, live_server):
    _take_sample()
    _take_sample()                          # two samples so the rate calc has a delta
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    body = resp.get_json()
    assert set(body) >= {"total_packets", "packets_per_sec",
                         "bytes_per_sec", "drop_rate_pct", "uptime_sec"}
    assert body["total_packets"] == 5
    assert body["drop_rate_pct"] == 0.0     # drops are not exposed by the read-only server


def test_stats_503_when_no_sample_yet(client, live_server):
    with bridge._lock:
        bridge._samples.clear()             # sampler hasn't produced anything (or backend down)
    resp = client.get("/api/stats")
    assert resp.status_code == 503
    assert "unreachable" in resp.get_json()["error"].lower()


def test_stats_503_when_sample_is_stale(client, live_server):
    # A sample older than the 4s freshness window means the backend stopped responding.
    with bridge._lock:
        bridge._samples.clear()
        bridge._samples.append((time.time() - 10, 5, 1000))
    resp = client.get("/api/stats")
    assert resp.status_code == 503


# --- /api/timeseries: never 503s (the deliberate asymmetry vs /api/stats) ---

def test_timeseries_200_empty_when_no_data(client, live_server):
    with bridge._lock:
        bridge._samples.clear()
    resp = client.get("/api/timeseries")
    assert resp.status_code == 200          # graceful empty, NOT 503
    assert resp.get_json() == {"seconds": [], "captured": [], "dropped": []}


def test_timeseries_returns_consecutive_deltas(client, live_server):
    now = time.time()
    with bridge._lock:
        bridge._samples.clear()
        bridge._samples.extend([(now - 2, 5, 100), (now - 1, 8, 200), (now, 10, 350)])
    body = client.get("/api/timeseries").get_json()
    assert body["captured"] == [3, 2]       # per-second deltas in total_packets
    assert body["dropped"] == [0, 0]        # drops never exposed -> always 0
    assert len(body["seconds"]) == 2
