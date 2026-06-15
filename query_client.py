"""Binary-protocol client for the PacketQL query server.

    python query_client.py [host] [port]

Type SQL to run a query; '.ping' / '.stats' send those messages; 'quit' exits.
IP/protocol/flag columns are rendered human-readably for display.
"""

from __future__ import annotations

import socket
import sys

from packetql.schema import flags_str, int_to_ip, proto_name
from packetql.server import OK, PING, QUERY, STATS, decode_result, recv_frame, send_frame

_IP_COLS = {"src_ip", "dst_ip"}


def _fmt(col, value):
    if col in _IP_COLS:
        return int_to_ip(value)
    if col == "proto":
        return proto_name(value)
    if col == "flags":
        return flags_str(value)
    return str(value)


def format_table(columns, rows):
    disp = [[_fmt(c, v) for c, v in zip(columns, r)] for r in rows]
    widths = [len(c) for c in columns]
    for r in disp:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(cells):
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    return "\n".join([border, line(list(columns)), border] + [line(r) for r in disp] + [border])


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    with socket.create_connection((host, port)) as sock:
        print(f"connected to {host}:{port}. Type SQL; '.ping', '.stats', or 'quit'.")
        while True:
            try:
                line = input("pktql> ").strip()
            except EOFError:
                break
            if not line:
                continue
            if line.lower() in ("quit", "exit"):
                break
            if line == ".ping":
                send_frame(sock, PING)
                print(recv_frame(sock)[1].decode())
                continue
            if line == ".stats":
                send_frame(sock, STATS)
                print(recv_frame(sock)[1].decode())
                continue
            send_frame(sock, QUERY, line.rstrip(";").encode())
            status, payload = recv_frame(sock)
            if status == OK:
                cols, rows = decode_result(payload)
                print(format_table(cols, rows))
                print(f"({len(rows)} rows)")
            else:
                print("Error:", payload.decode())


if __name__ == "__main__":
    main()
