# PacketQL

**A live network packet analyzer with a SQL-like query engine — built from scratch in Python.**

Capture packets off the wire, parse Ethernet → IP → TCP/UDP headers by hand,
store them on disk in a custom columnar format, and query the traffic with SQL:

```sql
SELECT src_ip, dst_port, size FROM packets
WHERE protocol = 'TCP' AND size > 1500
ORDER BY timestamp DESC LIMIT 50;
```

The query engine reuses the design of [QueryX](../QueryX) (lexer →
recursive-descent parser → AST → cost-based planner → volcano executor); the new
work is in packet parsing (Networks), columnar storage (DBMS), and live capture
with a producer/consumer ring buffer (OS).

The **offline path uses only the Python standard library** — it reads the
`.pcap` file format and decodes packet bytes itself. `scapy` is needed only for
live capture.

## Quickstart (offline)

```bash
python tools/make_sample_pcap.py   # write data/sample.pcap (synthetic, stdlib)
python demo_offline.py             # parse it and print the packets
```

See [CLAUDE.md](CLAUDE.md) for the architecture and the phase plan.
