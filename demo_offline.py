"""Offline demo: read data/sample.pcap and print every parsed packet.

Run:  python demo_offline.py
(First run `python tools/make_sample_pcap.py` to create data/sample.pcap.)
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.capture.parser import parse_file  # noqa: E402


def main() -> None:
    path = os.path.join(ROOT, "data", "sample.pcap")
    if not os.path.exists(path):
        print("data/sample.pcap not found — run: python tools/make_sample_pcap.py")
        return
    packets = parse_file(path)

    cols = f"{'time':>12}  {'src_ip':<15} {'dst_ip':<15} {'proto':<6} {'sport':>6} {'dport':>6} {'size':>5} {'ttl':>4}"
    print(cols)
    print("-" * len(cols))
    for p in packets:
        print(f"{p.timestamp:12.2f}  {str(p.src_ip):<15} {str(p.dst_ip):<15} "
              f"{p.protocol:<6} {str(p.src_port):>6} {str(p.dst_port):>6} "
              f"{p.size:>5} {str(p.ttl):>4}")
    print(f"\n{len(packets)} packets parsed from data/sample.pcap")


if __name__ == "__main__":
    main()
