"""Phase 5 demo: the capture pipeline (ring buffer + producer/consumer threads).

Parts [1]-[3] run now with no special privileges; part [4] is the live-capture
command that needs Npcap + Administrator.

Run:  python demo_capture.py
"""

from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from packetql.capture.parser import parse_packet  # noqa: E402
from packetql.capture.pcap import RawPacket, write_packets  # noqa: E402
from packetql.capture.pipeline import capture_offline  # noqa: E402
from packetql.capture.ringbuffer import RingBuffer  # noqa: E402
from packetql.query.executor import run_query  # noqa: E402
from packetql.storage.columnar import ColumnStore  # noqa: E402
from tools.make_sample_pcap import build  # noqa: E402


def main() -> None:
    raws = build()

    print(f"[1] Replaying {len(raws)} packets through the pipeline "
          f"(producer thread -> ring buffer -> writer thread)...")
    pipe = capture_offline(raws, capacity=1024)
    print(f"    captured={pipe.captured}  dropped={pipe.dropped}")
    store_dir = os.path.join(ROOT, "data", "live_store")
    pipe.flush_to_store(store_dir)
    res = run_query(ColumnStore(store_dir),
                    "SELECT protocol, dst_port, size FROM packets ORDER BY size DESC LIMIT 5")
    print("    query the captured store (top 5 by size):")
    for row in res.rows:
        print("      ", row)

    print("\n[2] Drop-oldest under overload (capacity 4, 20 packets pushed, no consumer):")
    rb = RingBuffer(4)
    for i in range(20):
        rb.put(raws[i % len(raws)])
    print(f"    enqueued={rb.enqueued}  dropped={rb.dropped}  kept={len(rb)}  "
          f"-> the buffer holds only the newest 4 (what tcpdump does under load)")

    print("\n[3] scapy bridge check (verifies the live adapter's conversion, offline):")
    try:
        from scapy.all import rdpcap
        tmp = os.path.join(tempfile.gettempdir(), "pktql_bridge.pcap")
        write_packets(tmp, raws)
        scapy_pkts = rdpcap(tmp)
        converted = []
        for p in scapy_pkts:
            data = bytes(p)
            ts = float(getattr(p, "time", 0.0))
            converted.append(parse_packet(RawPacket(int(ts), int((ts % 1) * 1_000_000), len(data), data)))
        direct = [parse_packet(r) for r in raws]
        agree = ([c.protocol for c in converted] == [d.protocol for d in direct]
                 and [c.dst_port for c in converted] == [d.dst_port for d in direct])
        print(f"    scapy read {len(scapy_pkts)} packets; the live path's parse "
              f"agrees with the offline parser: {agree}")
    except ImportError:
        print("    (scapy not importable - skipped)")

    print("\n[4] LIVE capture (needs Npcap + Administrator):")
    print("    1) Install Npcap once:  https://npcap.com  (run the installer as Administrator)")
    print("    2) In an Administrator terminal, from the project root, run:")
    print('       python -c "from packetql.capture.pipeline import capture_live; '
          "p = capture_live(count=50); p.flush_to_store('data/live_store'); "
          "print('captured', p.captured, 'dropped', p.dropped)\"")
    print("    3) Then query data/live_store (see demo_query.py for example queries).")


if __name__ == "__main__":
    main()
