import shutil
from pathlib import Path

import pytest

from idps.detect.suricata_client import SuricataClient

FIXTURE_PCAP = Path(__file__).parent / "fixtures" / "synthetic_scan.pcap"
FIXTURE_EVE_JSON = Path(__file__).parent / "fixtures" / "synthetic_scan_eve.json"


def test_from_eve_json_parses_real_alert_records():
    alerts = SuricataClient().from_eve_json(FIXTURE_EVE_JSON)
    assert len(alerts) == 3
    assert all(a.signature == "IDPS Possible Port Scan (SYN fan-out)" for a in alerts)
    assert all(a.src_ip == "10.0.0.5" for a in alerts)


def test_from_eve_json_missing_file_returns_empty():
    assert SuricataClient().from_eve_json("/nonexistent/eve.json") == []


@pytest.mark.skipif(not shutil.which("suricata"), reason="requires the real suricata binary")
def test_run_against_real_suricata():
    alerts = SuricataClient().run(FIXTURE_PCAP)
    assert len(alerts) >= 1
    assert alerts[0].src_ip == "10.0.0.5"
    assert alerts[0].category
