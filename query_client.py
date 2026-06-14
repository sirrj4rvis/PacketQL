"""A tiny TCP client for the PacketQL query server (Phase 6).

    python query_client.py [host] [port]

Type SQL at the prompt; results come back from the server. Blank line keeps
going; 'quit' exits.
"""

from __future__ import annotations

import socket
import sys

END_MARKER = "[END]"


def read_response(rfile) -> str:
    lines = []
    for line in rfile:
        if line.rstrip("\n") == END_MARKER:
            break
        lines.append(line.rstrip("\n"))
    return "\n".join(lines)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    with socket.create_connection((host, port)) as sock:
        rfile = sock.makefile("r", encoding="utf-8", newline="\n")
        wfile = sock.makefile("w", encoding="utf-8", newline="\n")
        print(read_response(rfile))      # banner
        while True:
            try:
                sql = input("pktql> ").strip()
            except EOFError:
                break
            if not sql:
                continue
            wfile.write(sql + "\n")
            wfile.flush()
            if sql.lower() in ("quit", "exit"):
                break
            print(read_response(rfile))


if __name__ == "__main__":
    main()
