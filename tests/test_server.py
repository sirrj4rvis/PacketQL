"""Tests for the TCP query server + thread pool (ephemeral localhost port)."""

import socket
import threading

from packetql.capture.pipeline import capture_offline
from packetql.server import END_MARKER, QueryServer
from tools.make_sample_pcap import build


def _make_store(tmp_path) -> str:
    pipe = capture_offline(build())
    directory = str(tmp_path / "store")
    pipe.flush_to_store(directory)
    return directory


def _read_until_end(rfile) -> str:
    lines = []
    for line in rfile:
        if line.rstrip("\n") == END_MARKER:
            break
        lines.append(line.rstrip("\n"))
    return "\n".join(lines)


def _client_query(port: int, sql: str) -> str:
    with socket.create_connection(("127.0.0.1", port)) as sock:
        rfile = sock.makefile("r", encoding="utf-8", newline="\n")
        wfile = sock.makefile("w", encoding="utf-8", newline="\n")
        _read_until_end(rfile)                 # banner
        wfile.write(sql + "\n")
        wfile.flush()
        response = _read_until_end(rfile)
        wfile.write("quit\n")
        wfile.flush()
        return response


def test_server_runs_query_over_tcp(tmp_path):
    server = QueryServer(_make_store(tmp_path), port=0, workers=2)
    server.start()
    try:
        resp = _client_query(
            server.port,
            "SELECT dst_port FROM packets WHERE protocol = 'TCP' ORDER BY dst_port")
        assert "443" in resp and "80" in resp
        assert "rows)" in resp
    finally:
        server.stop()


def test_server_reports_query_errors(tmp_path):
    server = QueryServer(_make_store(tmp_path), port=0, workers=2)
    server.start()
    try:
        assert "Error:" in _client_query(server.port, "SELECT nope FROM packets")
    finally:
        server.stop()


def test_thread_pool_handles_concurrent_clients(tmp_path):
    server = QueryServer(_make_store(tmp_path), port=0, workers=4)
    server.start()
    results: list[str] = []
    lock = threading.Lock()

    def hit():
        resp = _client_query(server.port, "SELECT protocol FROM packets LIMIT 1")
        with lock:
            results.append(resp)

    try:
        threads = [threading.Thread(target=hit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 8
        assert all("rows)" in r for r in results)
    finally:
        server.stop()
