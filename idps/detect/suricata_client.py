"""Orchestrates the real Suricata IDS engine against a pcap file and
parses its real `eve.json` alert output - a second, independent
detection signal alongside port_scan_detector.py's deterministic
fan-out check.

Uses a small custom ruleset (data/suricata_portscan.rules) rather than
the full Emerging Threats ruleset, so its behavior is deterministic and
doesn't depend on ruleset-version quirks - see that file's header
comment. Requires the real `suricata` binary on PATH for live mode
(`brew install suricata` locally; apt-installed in the sensor
container). Offline/demo mode can also load a fixture eve.json.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from idps.models import SuricataAlert

logger = logging.getLogger(__name__)

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "data" / "suricata_portscan.rules"

# Suricata's eve.json timestamps use a UTC offset with no colon (e.g. "+0000"),
# which datetime.fromisoformat() only started accepting in Python 3.11 - insert
# the colon so this parses identically on 3.10 too.
_OFFSET_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def _parse_suricata_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(_OFFSET_NO_COLON.sub(r"\1:\2", value))


class SuricataClient:
    def __init__(self, suricata_path: str = "suricata", rules_path: str | Path = DEFAULT_RULES_PATH):
        self.suricata_path = suricata_path
        self.rules_path = rules_path

    def run(self, pcap_path: str | Path) -> list[SuricataAlert]:
        with tempfile.TemporaryDirectory() as log_dir:
            cmd = [
                self.suricata_path, "-r", str(pcap_path), "-l", log_dir, "-k", "none", "-S", str(self.rules_path),
            ]
            logger.info("Running: %s", " ".join(cmd))
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            return self.from_eve_json(Path(log_dir) / "eve.json")

    def from_eve_json(self, path: str | Path) -> list[SuricataAlert]:
        path = Path(path)
        if not path.exists():
            return []

        alerts = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue
            alerts.append(
                SuricataAlert(
                    signature=event["alert"]["signature"],
                    category=event["alert"]["category"],
                    severity=event["alert"]["severity"],
                    src_ip=event["src_ip"],
                    dst_ip=event["dest_ip"],
                    dst_port=event.get("dest_port", 0),
                    timestamp=_parse_suricata_timestamp(event["timestamp"]),
                )
            )
        return alerts
