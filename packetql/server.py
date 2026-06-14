"""Phase 6 — a TCP query server with a thread pool (the Networks + OS capstone).

Clients connect over TCP and send SQL queries, one per line; the server runs
each against the columnar store and sends the rendered result back. Connections
are handled by a **fixed pool of worker threads** pulling from a bounded queue:
the accept loop is the producer, the workers are the consumers — the same
producer/consumer shape as the capture ring buffer. A fixed pool bounds
concurrency so a burst of clients can't spawn unbounded threads.

Wire protocol (line-oriented, telnet-friendly): the client sends one query line;
the server replies with the rendered table followed by a lone ``[END]`` line as
the response delimiter. ``quit`` (or EOF) closes the connection.

Binding a localhost socket needs no special privileges — only live *capture*
(Phase 5) needs Administrator. So the server runs over whatever store you point
it at (e.g. the one you captured live).
"""

from __future__ import annotations

import queue
import socket
import threading
import time

from packetql.index.indexes import PacketIndexes
from packetql.query.executor import QueryError, QueryResult, run_query
from packetql.query.lexer import SQLSyntaxError
from packetql.storage.columnar import ColumnStore

END_MARKER = "[END]"


def format_table(res: QueryResult) -> str:
    rows = [["NULL" if v is None else str(v) for v in r] for r in res.rows]
    widths = [len(c) for c in res.columns]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(cells):
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    return "\n".join([border, line(list(res.columns)), border] + [line(r) for r in rows] + [border])


class QueryServer:
    """A thread-pool TCP server that answers SQL queries over a packet store."""

    def __init__(self, store_dir: str, host: str = "127.0.0.1", port: int = 9999,
                 workers: int = 4, backlog: int = 64) -> None:
        self.store_dir = store_dir
        self.num_workers = workers
        # Build indexes once at startup; they are read-only and shared by all
        # workers. Each connection opens its own ColumnStore, so there is no
        # shared *mutable* state across threads.
        base = ColumnStore(store_dir)
        self.row_count = base.row_count
        self.indexes = PacketIndexes.build(
            base, hash_columns=["dst_port", "src_port"], trie_columns=["src_ip", "dst_ip"])

        self._queue: queue.Queue = queue.Queue(maxsize=backlog)
        self._workers: list[threading.Thread] = []
        self._running = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(backlog)
        self.host, self.port = self._sock.getsockname()

    # -- lifecycle ----------------------------------------------------------
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
            self._sock.close()           # unblocks the accept loop
        except OSError:
            pass
        for _ in self._workers:
            self._queue.put(None)        # sentinel: wake each worker so it exits

    def serve_forever(self) -> None:
        self.start()
        print(f"PacketQL query server listening on {self.host}:{self.port}  "
              f"({self.num_workers} worker threads, {self.row_count} packets).")
        print("Connect with:  python query_client.py        (Ctrl-C here to stop)")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nstopping...")
        finally:
            self.stop()

    # -- internals ----------------------------------------------------------
    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break                    # socket closed by stop()
            self._queue.put((conn, addr))

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            conn, _addr = item
            try:
                self._handle(conn)
            except Exception:
                pass                     # one bad connection never takes the worker down
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        store = ColumnStore(self.store_dir)   # per-connection: no shared mutable state
        rfile = conn.makefile("r", encoding="utf-8", newline="\n")
        wfile = conn.makefile("w", encoding="utf-8", newline="\n")
        wfile.write(f"PacketQL query server - {store.row_count} packets. "
                    f"Send SQL (one per line); 'quit' to exit.\n{END_MARKER}\n")
        wfile.flush()
        for raw in rfile:
            sql = raw.strip().rstrip(";")
            if not sql or sql.lower() in ("quit", "exit"):
                break
            try:
                res = run_query(store, sql, indexes=self.indexes)
                body = f"{format_table(res)}\n({len(res.rows)} rows)   plan: {res.plan}"
            except (QueryError, SQLSyntaxError) as exc:
                body = f"Error: {exc}"
            wfile.write(f"{body}\n{END_MARKER}\n")
            wfile.flush()


def main(argv=None) -> None:
    import argparse
    import os

    parser = argparse.ArgumentParser(description="PacketQL TCP query server")
    parser.add_argument("--store", default=os.path.join("data", "live_store"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    if not os.path.exists(os.path.join(args.store, "meta.json")):
        print(f"No store at {args.store!r}. Capture first (demo_capture.py / capture_live) "
              f"or pass --store <dir>.")
        return
    QueryServer(args.store, args.host, args.port, args.workers).serve_forever()


if __name__ == "__main__":
    main()
