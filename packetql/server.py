"""Phase 6 — a TCP query server with a binary wire protocol and a thread pool.

Wire protocol (like PostgreSQL's, simplified):
    request : [4-byte length][1-byte type][payload]   type 1=QUERY 2=PING 3=STATS
    response: [4-byte length][1-byte status][payload]  status 0=OK 1=ERROR
A QUERY's OK payload is the result encoded **column-major in binary** (column
names + row count + per-column typed values). TCP gives no message boundaries,
so every read loops until exactly ``length`` bytes have arrived (recv_exact).

Concurrency: a fixed pool of worker threads pulls accepted connections from a
bounded queue (accept loop = producer, workers = consumers). Each connection
uses its own ColumnStore (no shared mutable state); the indexes are read-only and
shared. A readers-writer lock guards index/store access so that — should a writer
thread ever update them live — readers and the writer can't interleave.
"""

from __future__ import annotations

import queue
import socket
import struct
import threading
import time
from contextlib import contextmanager

from packetql.index.indexes import PacketIndexes
from packetql.query.executor import QueryError, run_query
from packetql.query.lexer import SQLSyntaxError
from packetql.storage.columnar import ColumnStore

# message types / statuses
QUERY, PING, STATS = 1, 2, 3
OK, ERROR = 0, 1
_HEADER = struct.Struct("!IB")     # length, (type | status)


# ---------------------------------------------------------------------------
# Wire protocol
# ---------------------------------------------------------------------------


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes, looping over partial recv()s (TCP has no framing)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf += chunk
    return bytes(buf)


def send_frame(sock: socket.socket, kind: int, payload: bytes = b"") -> None:
    sock.sendall(_HEADER.pack(len(payload), kind) + payload)


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    length, kind = _HEADER.unpack(recv_exact(sock, _HEADER.size))
    return kind, recv_exact(sock, length)


def encode_result(columns, rows) -> bytes:
    """Column-major binary: names, row count, then each column's typed values.

    Per-column type tag: 'f' = double (ts / AVG), 's' = length-prefixed UTF-8
    string (e.g. EXPLAIN's plan text), 'i' = int64 (everything else). The string
    case matters: without it, EXPLAIN's text rows get packed as int64 and raise
    "required argument is not an integer".
    """
    out = bytearray()
    out.append(len(columns))
    for name in columns:
        nb = name.encode()
        out.append(len(nb))
        out += nb
    out += struct.pack("!I", len(rows))
    for j, name in enumerate(columns):
        sample = rows[0][j] if rows else 0
        if name == "ts" or isinstance(sample, float):
            out += b"f"
            packer = struct.Struct("!d")
            for row in rows:
                out += packer.pack(row[j])
        elif isinstance(sample, str):
            out += b"s"
            for row in rows:
                rb = str(row[j]).encode()
                out += struct.pack("!I", len(rb)) + rb
        else:
            out += b"i"
            packer = struct.Struct("!q")
            for row in rows:
                out += packer.pack(row[j])
    return bytes(out)


def decode_result(payload: bytes):
    pos = 0
    ncols = payload[pos]; pos += 1
    columns = []
    for _ in range(ncols):
        ln = payload[pos]; pos += 1
        columns.append(payload[pos:pos + ln].decode()); pos += ln
    (nrows,) = struct.unpack_from("!I", payload, pos); pos += 4
    coldata = []
    for _ in range(ncols):
        typ = payload[pos:pos + 1]; pos += 1
        vals = []
        if typ == b"s":
            for _ in range(nrows):
                (ln,) = struct.unpack_from("!I", payload, pos); pos += 4
                vals.append(payload[pos:pos + ln].decode()); pos += ln
        else:
            unpacker = struct.Struct("!d") if typ == b"f" else struct.Struct("!q")
            for _ in range(nrows):
                vals.append(unpacker.unpack_from(payload, pos)[0]); pos += unpacker.size
        coldata.append(vals)
    rows = [tuple(coldata[j][i] for j in range(ncols)) for i in range(nrows)]
    return columns, rows


# ---------------------------------------------------------------------------
# Readers-writer lock (writer-preferring) — a classic OS synchronization problem
# ---------------------------------------------------------------------------


class RWLock:
    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._readers = 0
        self._writer = False
        self._writers_waiting = 0

    def acquire_read(self) -> None:
        with self._cond:
            while self._writer or self._writers_waiting > 0:
                self._cond.wait()
            self._readers += 1

    def release_read(self) -> None:
        with self._cond:
            self._readers -= 1
            if self._readers == 0:
                self._cond.notify_all()

    def acquire_write(self) -> None:
        with self._cond:
            self._writers_waiting += 1
            while self._writer or self._readers > 0:
                self._cond.wait()
            self._writers_waiting -= 1
            self._writer = True

    def release_write(self) -> None:
        with self._cond:
            self._writer = False
            self._cond.notify_all()

    @contextmanager
    def read_locked(self):
        self.acquire_read()
        try:
            yield
        finally:
            self.release_read()

    @contextmanager
    def write_locked(self):
        self.acquire_write()
        try:
            yield
        finally:
            self.release_write()


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class QueryServer:
    def __init__(self, store_dir: str, host: str = "127.0.0.1", port: int = 9999,
                 workers: int = 4, backlog: int = 64) -> None:
        self.store_dir = store_dir
        self.num_workers = workers
        base = ColumnStore(store_dir)
        self.row_count = base.row_count
        self.indexes = PacketIndexes.load_or_build(base)
        self.lock = RWLock()
        self._queries = 0
        self._stats_lock = threading.Lock()

        self._queue: queue.Queue = queue.Queue(maxsize=backlog)
        self._workers: list[threading.Thread] = []
        self._running = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(backlog)
        self.host, self.port = self._sock.getsockname()

    def start(self) -> None:
        self._running = True
        for _ in range(self.num_workers):
            t = threading.Thread(target=self._worker, daemon=True, name="pktql-worker")
            t.start()
            self._workers.append(t)
        threading.Thread(target=self._accept_loop, daemon=True, name="pktql-accept").start()

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        for _ in self._workers:
            self._queue.put(None)

    def serve_forever(self) -> None:
        self.start()
        print(f"PacketQL server on {self.host}:{self.port} "
              f"({self.num_workers} workers, {self.row_count} packets). Ctrl-C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nstopping...")
        finally:
            self.stop()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            self._queue.put((conn, addr))

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            conn, _addr = item
            try:
                self._serve(conn)
            except Exception:
                # A worker must survive ANY per-connection failure — one bad
                # request (or a store that vanished) must never shrink the pool.
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _serve(self, conn: socket.socket) -> None:
        # The store is opened lazily, per connection (no shared mutable state).
        # Opening can fail if the store directory was removed/rebuilt while the
        # server runs; PING never needs it, and STATS/QUERY then return a clean
        # ERROR frame instead of dropping the socket (a confusing TCP abort).
        store = None
        while True:
            try:
                kind, payload = recv_frame(conn)
            except ConnectionError:
                return
            if kind == PING:
                send_frame(conn, OK, b"pong")
                continue
            if store is None:
                try:
                    store = ColumnStore(self.store_dir)
                except Exception as exc:
                    send_frame(conn, ERROR, f"store unavailable: {exc}".encode())
                    continue
            if kind == STATS:
                with self.lock.read_locked():
                    info = f"rows={store.row_count} queries={self._queries} workers={self.num_workers}"
                send_frame(conn, OK, info.encode())
            elif kind == QUERY:
                try:
                    with self.lock.read_locked():
                        result = run_query(store, payload.decode(), indexes=self.indexes)
                    with self._stats_lock:
                        self._queries += 1
                    send_frame(conn, OK, encode_result(result.columns, result.rows))
                except (QueryError, SQLSyntaxError) as exc:
                    send_frame(conn, ERROR, str(exc).encode())
                except Exception as exc:                  # never let an unexpected error drop the socket
                    send_frame(conn, ERROR, f"internal error: {exc}".encode())
            else:
                send_frame(conn, ERROR, b"unknown message type")


def main(argv=None) -> None:
    import argparse
    import os

    p = argparse.ArgumentParser(description="PacketQL TCP query server")
    p.add_argument("--store", default=os.path.join("data", "live_store"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args(argv)
    if not os.path.exists(os.path.join(args.store, "meta.json")):
        print(f"No store at {args.store!r}. Capture first, or pass --store <dir>.")
        return
    QueryServer(args.store, args.host, args.port, args.workers).serve_forever()


if __name__ == "__main__":
    main()
