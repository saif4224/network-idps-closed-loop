import shutil
from pathlib import Path

import pytest

from idps.capture.packet_capture import PacketCapture, parse_tshark_csv

FIXTURE_PCAP = Path(__file__).parent / "fixtures" / "synthetic_scan.pcap"

# Real tshark -T fields output for two packets (captured from a real run - see
# scripts/generate_pcap_fixture.py), used to test the pure CSV-parsing logic
# without needing the tshark binary installed.
SAMPLE_TSHARK_CSV = (
    "1772265600.000000000,10.0.0.5,10.0.0.10,6,40000,20,0x0002,,,54\n"
    "1772265600.010000000,10.0.0.5,10.0.0.10,6,40001,21,0x0002,,,54\n"
)


def test_parse_tshark_csv_extracts_tcp_packets():
    packets = parse_tshark_csv(SAMPLE_TSHARK_CSV)
    assert len(packets) == 2
    assert packets[0].src_ip == "10.0.0.5"
    assert packets[0].dst_port == 20
    assert packets[0].protocol == "TCP"
    assert packets[0].flags == "SYN"


def test_parse_tshark_csv_ignores_blank_lines():
    packets = parse_tshark_csv(SAMPLE_TSHARK_CSV + "\n\n")
    assert len(packets) == 2


def test_parse_tshark_csv_handles_synack_flags():
    csv_line = "1772265600.000000000,10.0.0.10,10.0.0.5,6,80,40000,0x0012,,,60\n"
    packets = parse_tshark_csv(csv_line)
    assert packets[0].flags == "SYN,ACK"


@pytest.mark.skipif(not shutil.which("tshark"), reason="requires the real tshark binary")
def test_read_pcap_file_against_real_tshark():
    packets = PacketCapture().read_pcap_file(FIXTURE_PCAP)
    assert len(packets) == 15
    assert all(p.src_ip == "10.0.0.5" for p in packets)
    assert sorted(p.dst_port for p in packets) == list(range(20, 35))
