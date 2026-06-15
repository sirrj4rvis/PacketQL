"""End-to-end offline demo: parse the fixture capture through the pipeline into a
columnar store, build indexes, and run queries (showing the chosen plan).

    python demo.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.capture.pcap import read_packets  # noqa: E402
from packetql.capture.pipeline import capture_offline  # noqa: E402
from packetql.index.indexes import PacketIndexes  # noqa: E402
from packetql.query.executor import run_query  # noqa: E402
from packetql.schema import flags_str, int_to_ip, proto_name  # noqa: E402
from packetql.storage.columnar import ColumnStore  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "sample.pcap")
_IP_COLS = {"src_ip", "dst_ip"}

QUERIES = [
    "SELECT src_ip, dst_ip, proto, dst_port, size, flags FROM packets",
    "SELECT dst_port, size FROM packets WHERE proto = 6 ORDER BY size DESC",
    "SELECT src_ip, dst_port FROM packets WHERE src_ip LIKE '192.168.%'",
    "SELECT size FROM packets WHERE proto = 6 AND dst_port = 443",
    "SELECT proto, COUNT(*), SUM(size) FROM packets GROUP BY proto ORDER BY COUNT(*) DESC",
    "SELECT DISTINCT dst_port FROM packets ORDER BY dst_port",
    "EXPLAIN SELECT dst_port, COUNT(*) FROM packets WHERE proto = 6 GROUP BY dst_port",
]


def _fmt(col, v):
    if col in _IP_COLS:
        return int_to_ip(v)
    if col == "proto":
        return proto_name(v)
    if col == "flags":
        return flags_str(v)
    return str(v)


def table(result):
    disp = [[_fmt(c, v) for c, v in zip(result.columns, r)] for r in result.rows]
    widths = [len(c) for c in result.columns]
    for r in disp:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    line = lambda cells: "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"
    return "\n".join([border, line(list(result.columns)), border] + [line(r) for r in disp] + [border])


def main() -> None:
    if not os.path.exists(FIXTURE):
        print("fixture missing - run: python tools/make_fixture_pcap.py")
        return
    store_dir = os.path.join(ROOT, "data", "demo_store")
    pipe = capture_offline(read_packets(FIXTURE), store_dir)
    print(f"parsed + stored {pipe.written} packets through the capture pipeline "
          f"(1 bad-checksum frame discarded, 0 dropped)")

    store = ColumnStore(store_dir)
    indexes = PacketIndexes.load_or_build(store)
    for sql in QUERIES:
        result = run_query(store, sql, indexes=indexes)
        print("\n" + sql)
        print(table(result))
        print(f"({len(result.rows)} rows)   plan: {result.plan}")


if __name__ == "__main__":
    main()
