# PacketQL — Module Contracts

The locked interface each layer accepts, returns, and must never do. The
`PacketRecord` schema ([packetql/schema.py](packetql/schema.py)) is the spine:
everything flows as `PacketRecord` (in memory) or fixed-width columns (on disk).

## schema — `PacketRecord`
- **Is:** a frozen dataclass of integer fields (uint32 IPs, uint8 protocol/flags/ttl,
  uint16 ports/size, float timestamp). The single source of truth for field
  names, order, and widths.
- **Must never:** store IPs as strings or protocols as names — those are
  presentation concerns (`int_to_ip`, `proto_name`, `flags_str`).

## capture/pcap — libpcap file I/O
- **Accepts/returns:** `read_packets(path) -> list[RawPacket]` (raw frame bytes +
  timestamp); `write_packets(path, packets)` for fixtures.
- **Must never:** interpret packet contents — it only frames bytes.

## capture/parser — bytes → PacketRecord
- **Accepts:** `parse_packet(data: bytes, timestamp: float)`.
- **Returns:** a `PacketRecord`, or `None` to **discard** (non-IPv4, truncated,
  or failed IPv4 checksum).
- **Must never:** use scapy, or trust a packet without verifying its IP checksum.

## storage/columnar — fixed-width columnar store
- **Accepts:** `PacketRecord`s (append/batch writer with fsync); reads by column
  and by row index.
- **Returns:** column arrays / row slices; a query reads **only** the columns it
  needs.
- **Must never:** read a column file a query did not request, or use
  variable-width encoding (v1 is fixed-width).

## index — trie / hash / bitmap
- **Accepts:** a built store; predicates from the planner.
- **Returns:** sorted row-index sets (intersectable).
- **Must never:** be silently stale — persisted indexes reload only if the
  column files are unchanged (mtime), else rebuild.

## query — lexer / parser / planner / executor
- **Accepts:** a SQL string + a store (+ indexes).
- **Returns:** result rows; the chosen plan (and its estimated cost) is logged.
- **Must never:** scan a column the SELECT/WHERE doesn't reference, or
  materialize all rows when an index or a bounded top-N heap applies.

## server — thread-pool TCP query server
- **Accepts:** binary framed requests `[len][type][payload]` (QUERY/PING/STATS).
- **Returns:** binary framed responses `[len][status][payload]`.
- **Must never:** assume one `recv()` yields a whole message (loop to
  `message_length`), or let a query thread read an index while the writer mutates
  it without the readers-writer lock.
