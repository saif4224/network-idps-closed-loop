"""Orchestrates the full closed loop:

    capture -> detect (custom + Suricata) -> block -> re-attack -> re-capture -> verify

Runs inside the sensor container, which shares the victim's network
namespace (`network_mode: service:victim` in docker-compose) - so its
own tshark capture sees the victim's real traffic, and its iptables
calls apply to the victim's real network stack. The attacker IP isn't
hardcoded anywhere; it's discovered from the fan-out detector's own
output, the same way a real IDS would identify it.

The two attack bursts (one to detect/block, one to verify the block)
are both scheduled from a single upfront call to the attacker's
control API - see containers/attacker/controller.py's docstring for
why: once the sensor blocks the attacker's IP, it can no longer reach
that container's API to ask for a second burst.
"""
from __future__ import annotations

import json
import logging
import shutil
import socket
import tempfile
import time
from pathlib import Path

from idps.attacker_client import AttackerClient
from idps.capture.packet_capture import PacketCapture
from idps.detect.port_scan_detector import DEFAULT_PORT_THRESHOLD, DEFAULT_WINDOW_SECONDS, detect_port_scans
from idps.detect.suricata_client import SuricataClient
from idps.report.report_builder import build_incident_report, incident_report_to_dict
from idps.report.visualize import plot_port_fanout, plot_verification_comparison
from idps.respond.firewall import Firewall
from idps.verify import verify_from_capture

logger = logging.getLogger(__name__)

# How long after the first (detected/blocked) burst the attacker fires the
# second (verification) burst - must comfortably exceed capture + detect +
# block time on the sensor side. See run_closed_loop's docstring.
DEFAULT_BURST_GAP_SECONDS = 20


def run_closed_loop(
    target: str,
    attacker_url: str,
    ports: list[int],
    interface: str = "eth0",
    output_dir: str | Path = "output",
    capture_duration: int = 6,
    burst_gap_seconds: int = DEFAULT_BURST_GAP_SECONDS,
    port_threshold: int = DEFAULT_PORT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    firewall: Firewall | None = None,
) -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # dumpcap (the capture helper tshark shells out to) drops root privileges
    # after opening the raw capture socket but *before* opening the output
    # file, as a security hardening measure - so it can fail to write into a
    # root-owned output_dir (e.g. a CI-mounted volume) even though the
    # capturing process itself started as root. Capture straight into /tmp
    # instead - reliably world-writable (mode 1777) on any Linux system,
    # unlike a freshly mkdtemp'd subdirectory (mode 0700, same problem one
    # level down) - then copy the results into output_dir afterwards, a
    # plain file copy done by this (still-root) process, not subject to the
    # same restriction.
    capture_dir = Path(tempfile.gettempdir())

    capture = PacketCapture()
    attacker = AttackerClient(attacker_url)
    firewall = firewall or Firewall()

    # Packets carry real IPs, not the "target" hostname - resolve once so
    # verification can match captured traffic against the actual address.
    target_ip = socket.gethostbyname(target)
    logger.info("Phase 1/2: capturing baseline scan against %s (%s)", target, target_ip)
    before_path = capture_dir / "capture_before.pcap"
    before_proc = capture.capture_to_file(interface, before_path, capture_duration)
    time.sleep(1)  # let tshark attach to the interface before traffic starts
    attacker.trigger_scan(target, ports, repeat_after_seconds=burst_gap_seconds)
    trigger_time = time.time()
    capture.wait_for_capture(before_proc, before_path, timeout=capture_duration + 15)

    before_packets = capture.read_pcap_file(before_path)
    detections = detect_port_scans(before_packets, port_threshold, window_seconds)
    suricata_alerts = SuricataClient().run(before_path)
    logger.info("Detections: %d custom, %d Suricata", len(detections), len(suricata_alerts))

    applied_rule = None
    verification_before = verification_after = None

    if detections:
        attacker_ip = detections[0].src_ip
        verification_before = verify_from_capture(before_packets, "before_block", attacker_ip, target_ip, ports)
        logger.info(
            "Baseline reachability: %d/%d ports reachable", len(verification_before.ports_reachable), len(ports)
        )

        applied_rule = firewall.block_ip(attacker_ip)

        logger.info("Phase 2/2: waiting for the pre-scheduled repeat burst to verify the block")
        second_burst_at = trigger_time + burst_gap_seconds
        capture_start_at = second_burst_at - 2  # start capturing just before the burst is due
        sleep_needed = capture_start_at - time.time()
        if sleep_needed > 0:
            time.sleep(sleep_needed)

        after_path = capture_dir / "capture_after.pcap"
        after_proc = capture.capture_to_file(interface, after_path, capture_duration)
        capture.wait_for_capture(after_proc, after_path, timeout=capture_duration + 15)

        after_packets = capture.read_pcap_file(after_path)
        verification_after = verify_from_capture(after_packets, "after_block", attacker_ip, target_ip, ports)
        logger.info(
            "Post-block reachability: %d/%d ports reachable", len(verification_after.ports_reachable), len(ports)
        )
    else:
        logger.warning("No port scan detected - skipping block/verify phase.")

    report = build_incident_report(
        detections, suricata_alerts, applied_rule, verification_before, verification_after
    )
    report_dict = incident_report_to_dict(report)

    (output_dir / "incident_report.json").write_text(json.dumps(report_dict, indent=2))
    logger.info("closed_loop_confirmed=%s", report.closed_loop_confirmed)

    plot_port_fanout(detections, output_dir / "port_fanout.png")
    plot_verification_comparison(
        verification_before, verification_after, output_dir / "verification_comparison.png"
    )

    for pcap_path in (before_path, after_path if detections else None):
        if pcap_path and pcap_path.exists():
            shutil.copy2(pcap_path, output_dir / pcap_path.name)
            pcap_path.unlink()
            Path(f"{pcap_path}.stderr.log").unlink(missing_ok=True)

    return report_dict
