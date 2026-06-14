"""Phase 2 demo: store the parsed packets columnar, read them back, and show
that a query for one column reads only that column off disk.

Run:  python demo_columnar.py
(Run tools/make_sample_pcap.py first if data/sample.pcap is missing.)
"""

from __future__ import annotations

import math
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.capture.parser import Packet, parse_file  # noqa: E402
from packetql.storage.columnar import ColumnStore, store_disk_size, write_store  # noqa: E402


def _same(a: Packet, b: Packet) -> bool:
    return (
        math.isclose(a.timestamp, b.timestamp, abs_tol=1e-6)
        and (a.src_ip, a.dst_ip, a.protocol, a.src_port, a.dst_port, a.size, a.ttl)
        == (b.src_ip, b.dst_ip, b.protocol, b.src_port, b.dst_port, b.size, b.ttl)
    )


def main() -> None:
    pcap = os.path.join(ROOT, "data", "sample.pcap")
    if not os.path.exists(pcap):
        print("data/sample.pcap not found — run: python tools/make_sample_pcap.py")
        return

    packets = parse_file(pcap)
    store_dir = os.path.join(ROOT, "data", "store")
    write_store(store_dir, packets)
    print(f"wrote {len(packets)} packets to a columnar store: data/store/")
    print("  files:", ", ".join(sorted(os.listdir(store_dir))))

    # 1) round-trip: read every column back and confirm it equals the input
    store = ColumnStore(store_dir)
    restored = store.rows()
    ok = len(restored) == len(packets) and all(_same(a, b) for a, b in zip(packets, restored))
    print(f"\nround-trip: {'OK - all columns reconstruct the packets exactly' if ok else 'MISMATCH'}")
    assert ok, "columnar round-trip failed"

    # show the reconstructed rows (incl. the ARP frame, which is all-NULL but size)
    cols = f"{'src_ip':<15} {'dst_ip':<15} {'proto':<11} {'sport':>6} {'dport':>6} {'size':>5} {'ttl':>4}"
    print("\n" + cols)
    print("-" * len(cols))
    for p in restored:
        print(f"{str(p.src_ip):<15} {str(p.dst_ip):<15} {p.protocol:<11} "
              f"{str(p.src_port):>6} {str(p.dst_port):>6} {p.size:>5} {str(p.ttl):>4}")

    # 2) selective I/O: a query for just `size` touches only size.col
    fresh = ColumnStore(store_dir)
    fresh.column("size")
    total = store_disk_size(store_dir)
    pct = 100.0 * fresh.bytes_read / total
    print(f"\nselective read - 'SELECT size': read {fresh.bytes_read} bytes "
          f"of {total} on disk ({pct:.0f}% - only the size column).")
    print("A row store would have had to read every field of every packet.")


if __name__ == "__main__":
    main()
