import socket

from idps.attacker_client import AttackerClient


def test_trigger_scan_reports_open_and_closed_ports(attacker_controller_url, listening_port):
    # find a genuinely closed port near the open one
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]

    result = AttackerClient(attacker_controller_url).trigger_scan(
        "127.0.0.1", [listening_port, closed_port]
    )

    assert listening_port in result["open_ports"]
    assert closed_port in result["closed_ports"]
