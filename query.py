"""Query CLI over a PacketQL store.

    python query.py                          # interactive prompt over data/live_store
    python query.py "SELECT ... "            # one query
    python query.py --store data/demo_store "SELECT ..."

IP / protocol / flags columns are rendered human-readably; the engine stores them
as integers.
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.index.indexes import PacketIndexes  # noqa: E402
from packetql.query.executor import QueryError, run_query  # noqa: E402
from packetql.query.lexer import SQLSyntaxError  # noqa: E402
from packetql.schema import flags_str, int_to_ip, proto_name  # noqa: E402
from packetql.storage.columnar import ColumnStore  # noqa: E402

_IP_COLS = {"src_ip", "dst_ip"}


def _fmt(col, value):
    if col in _IP_COLS:
        return int_to_ip(value)
    if col == "proto":
        return proto_name(value)
    if col == "flags":
        return flags_str(value)
    return str(value)


def format_table(result):
    disp = [[_fmt(c, v) for c, v in zip(result.columns, r)] for r in result.rows]
    widths = [len(c) for c in result.columns]
    for r in disp:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(cells):
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    return "\n".join([border, line(list(result.columns)), border] + [line(r) for r in disp] + [border])


def main() -> None:
    args = sys.argv[1:]
    store_dir = os.path.join(ROOT, "data", "live_store")
    if args and args[0] == "--store":
        store_dir = args[1]
        args = args[2:]
    if not os.path.exists(os.path.join(store_dir, "meta.json")):
        print(f"No store at {store_dir!r}. Capture first, or pass --store <dir>.")
        return

    store = ColumnStore(store_dir)
    indexes = PacketIndexes.load_or_build(store)

    def run(sql):
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

    print(f"PacketQL shell over {os.path.relpath(store_dir, ROOT)}  ({store.row_count} packets). "
          f"Type SQL; 'quit' to exit.")
    while True:
        try:
            line = input("pktql> ").strip()
        except EOFError:
            break
        if not line or line.lower() in ("quit", "exit"):
            break
        run(line.rstrip(";"))


if __name__ == "__main__":
    main()
