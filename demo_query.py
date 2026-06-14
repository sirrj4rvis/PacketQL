"""Phase 3 demo: run SQL-like queries over the columnar packet store.

Run:  python demo_query.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.capture.parser import parse_file  # noqa: E402
from packetql.query.executor import QueryResult, run_query  # noqa: E402
from packetql.storage.columnar import ColumnStore, store_disk_size, write_store  # noqa: E402


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


QUERIES = [
    "SELECT src_ip, dst_port, size FROM packets WHERE protocol = 'TCP' AND size > 1500 ORDER BY size DESC LIMIT 5",
    "SELECT protocol, dst_port, size FROM packets WHERE protocol = 'UDP' ORDER BY size DESC",
    "SELECT src_ip, dst_ip, protocol FROM packets WHERE NOT protocol = 'TCP'",
    "SELECT src_ip, dst_port, size FROM packets WHERE dst_port = 443 OR dst_port = 80 ORDER BY size DESC",
]


def main() -> None:
    pcap = os.path.join(ROOT, "data", "sample.pcap")
    if not os.path.exists(pcap):
        print("data/sample.pcap not found - run: python tools/make_sample_pcap.py")
        return
    store_dir = os.path.join(ROOT, "data", "store")
    write_store(store_dir, parse_file(pcap))
    total = store_disk_size(store_dir)

    for sql in QUERIES:
        store = ColumnStore(store_dir)   # fresh handle to measure bytes read
        result = run_query(store, sql)
        print(sql)
        print(format_table(result))
        print(f"({len(result.rows)} rows; read {store.bytes_read} of {total} bytes "
              f"on disk - only the columns this query names)\n")


if __name__ == "__main__":
    main()
