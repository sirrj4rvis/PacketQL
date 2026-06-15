"""Phase 1 tests: byte-level parsing + IP checksum verification against the
committed fixture capture (tests/fixtures/sample.pcap)."""

import os

from packetql.capture.parser import parse_file, parse_packet, verify_ip_checksum
from packetql.capture.pcap import read_packets
from packetql.schema import ACK, FIN, PROTO_ICMP, PROTO_TCP, PROTO_UDP, SYN, int_to_ip

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")


def test_fixture_parses_and_bad_checksum_is_discarded():
    recs = parse_file(FIXTURE)
    assert len(recs) == 5            # 6 frames, the corrupt-checksum one is dropped


def test_bad_checksum_returns_none():
    raws = read_packets(FIXTURE)
    assert len(raws) == 6
    parsed = [parse_packet(r.data, r.timestamp) for r in raws]
    assert parsed.count(None) == 1   # exactly the corrupt frame


def test_verify_checksum_flag_keeps_bad_frame_for_live_capture():
    # Live capture passes verify_checksum=False because NIC checksum offload
    # blanks outbound checksums; the fixture's one corrupt-checksum frame is then
    # kept instead of dropped (only the checksum differs — the frame is well-formed).
    raws = read_packets(FIXTURE)
    strict = [parse_packet(r.data, r.timestamp) for r in raws]
    lenient = [parse_packet(r.data, r.timestamp, verify_checksum=False) for r in raws]
    assert strict.count(None) == 1            # corrupt frame discarded (offline default)
    assert lenient.count(None) == 0           # ... but kept when checksums aren't verified


def test_tcp_syn_fields():
    syn = parse_file(FIXTURE)[0]
    assert syn.protocol == PROTO_TCP
    assert int_to_ip(syn.src_ip) == "192.168.0.2"
    assert int_to_ip(syn.dst_ip) == "93.184.216.34"
    assert syn.dst_port == 443 and syn.src_port == 51000
    assert (syn.tcp_flags & SYN) and not (syn.tcp_flags & ACK)
    assert syn.size == 40            # IP total length (20 IP + 20 TCP)
    assert syn.ttl == 64


def test_tcp_flags_combinations():
    recs = parse_file(FIXTURE)
    assert (recs[1].tcp_flags & SYN) and (recs[1].tcp_flags & ACK)   # SYN-ACK
    assert recs[2].size == 140                                       # 20 + 20 + 100 payload


def test_udp_and_icmp():
    recs = parse_file(FIXTURE)
    udp = next(r for r in recs if r.protocol == PROTO_UDP)
    assert udp.src_port == 50000 and udp.dst_port == 53 and udp.tcp_flags == 0
    icmp = next(r for r in recs if r.protocol == PROTO_ICMP)
    assert icmp.src_port == 0 and icmp.dst_port == 0          # ICMP has no ports
    assert int_to_ip(icmp.dst_ip) == "192.168.0.1"


def test_checksum_helper():
    # a header that sums to 0xFFFF is valid; flipping a byte breaks it
    raws = read_packets(FIXTURE)
    good_ip_header = raws[0].data[14:34]
    assert verify_ip_checksum(good_ip_header)
    assert not verify_ip_checksum(good_ip_header[:10] + bytes([good_ip_header[10] ^ 0xFF]) + good_ip_header[11:])
