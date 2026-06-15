"""Phase 6 tests: binary wire protocol (incl. partial reads), QUERY/PING/STATS,
the thread pool, and the readers-writer lock."""

import os
import socket
import struct
import threading
import time

from packetql.capture.pcap import read_packets
from packetql.capture.pipeline import capture_offline
from packetql.server import (ERROR, OK, PING, QUERY, STATS, QueryServer, RWLock,
                             decode_result, encode_result, recv_frame, send_frame)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")


def _store(tmp_path) -> str:
    d = str(tmp_path / "s")
    capture_offline(read_packets(FIXTURE), d)
    return d


def test_frame_partial_read_reassembles():
    a, b = socket.socketpair()
    payload = b"SELECT 1"
    raw = struct.pack("!IB", len(payload), QUERY) + payload

    def sender():
        a.sendall(raw[:3])          # split the frame across two sends
        time.sleep(0.05)
        a.sendall(raw[3:])

    t = threading.Thread(target=sender)
    t.start()
    kind, got = recv_frame(b)
    t.join()
    assert kind == QUERY and got == payload
    a.close()
    b.close()


def test_encode_decode_result_roundtrip():
    cols = ["dst_port", "ts", "size"]
    rows = [(443, 1.5, 1500), (80, 2.0, 200)]
    c, r = decode_result(encode_result(cols, rows))
    assert c == cols and r == rows


def _client(port, kind, payload=b""):
    with socket.create_connection(("127.0.0.1", port)) as s:
        send_frame(s, kind, payload)
        return recv_frame(s)


def test_query_ping_stats(tmp_path):
    srv = QueryServer(_store(tmp_path), port=0, workers=2)
    srv.start()
    try:
        assert _client(srv.port, PING) == (OK, b"pong")
        status, payload = _client(srv.port, STATS)
        assert status == OK and b"rows=5" in payload
        status, payload = _client(srv.port, QUERY,
                                  b"SELECT dst_port FROM packets WHERE proto = 6 ORDER BY dst_port")
        assert status == OK
        cols, rows = decode_result(payload)
        assert cols == ["dst_port"] and [r[0] for r in rows] == [443, 443, 51000]
        assert _client(srv.port, QUERY, b"SELECT nope FROM packets")[0] == ERROR
    finally:
        srv.stop()


def test_thread_pool_concurrent_clients(tmp_path):
    srv = QueryServer(_store(tmp_path), port=0, workers=4)
    srv.start()
    results = []
    lock = threading.Lock()

    def hit():
        status, _ = _client(srv.port, QUERY, b"SELECT size FROM packets LIMIT 1")
        with lock:
            results.append(status)

    try:
        threads = [threading.Thread(target=hit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == [OK] * 8
    finally:
        srv.stop()


def test_rwlock_allows_concurrent_readers():
    lock = RWLock()
    lock.acquire_read()
    lock.acquire_read()              # a second reader must not block
    lock.release_read()
    lock.release_read()


def test_rwlock_writer_excludes_readers():
    lock = RWLock()
    lock.acquire_write()
    got = []

    def reader():
        lock.acquire_read()
        got.append(1)
        lock.release_read()

    t = threading.Thread(target=reader)
    t.start()
    t.join(timeout=0.2)
    assert got == []                 # blocked while the writer holds the lock
    lock.release_write()
    t.join(timeout=1)
    assert got == [1]                # proceeds once the writer releases
