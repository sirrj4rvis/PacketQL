"""A small query CLI / REPL for PacketQL over a columnar store.

    python query.py                                  # interactive prompt over data/live_store
    python query.py "SELECT ... WHERE protocol='TCP'"  # run one query over data/live_store
    python query.py --store data/store "SELECT ..."  # choose a different store

Passing the SQL as a single double-quoted argument avoids the `python -c`
quoting problems with nested single quotes (e.g. 'TCP').
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.index.indexes import PacketIndexes  # noqa: E402
from packetql.query.executor import QueryError, QueryResult, run_query  # noqa: E402
from packetql.query.lexer import SQLSyntaxError  # noqa: E402
from packetql.storage.columnar import ColumnStore  # noqa: E402


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


def main() -> None:
    args = sys.argv[1:]
    store_dir = os.path.join(ROOT, "data", "live_store")
    if args and args[0] == "--store":
        store_dir = args[1]
        args = args[2:]

    if not os.path.exists(os.path.join(store_dir, "meta.json")):
        print(f"No store at {store_dir!r}. Capture first (see demo_capture.py) "
              f"or pass --store <dir>.")
        return

    store = ColumnStore(store_dir)
    indexes = PacketIndexes.build(
        store, hash_columns=["dst_port", "src_port"], trie_columns=["src_ip", "dst_ip"])

    def run(sql: str) -> None:
        try:
            result = run_query(store, sql, indexes=indexes)
        except (QueryError, SQLSyntaxError) as exc:
            print("Error:", exc)
            return
        print(format_table(result))
        print(f"({len(result.rows)} rows)   plan: {result.plan}")

    sql = " ".join(args).strip()
    if sql:
        run(sql)
        return

    print(f"PacketQL query shell over {os.path.relpath(store_dir, ROOT)}  "
          f"({store.row_count} packets).  Type SQL; blank line or 'quit' to exit.")
    while True:
        try:
            line = input("pktql> ").strip()
        except EOFError:
            break
        if not line or line.lower() in ("quit", "exit", ".quit"):
            break
        run(line.rstrip(";"))


if __name__ == "__main__":
    main()
