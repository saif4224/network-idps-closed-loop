"""Command-line entry point - runs inside the sensor container.

Unlike this author's other portfolio pipelines, there's no offline/
fixture-only demo mode here: the entire point of this project is a
live detect -> block -> verify loop across real network traffic, so
"demo" and "live" both drive a real capture against a real target -
"demo" just means the bundled attacker/victim sandbox (see
docker-compose.yml) rather than infrastructure you configure yourself.

    # Demo: against the bundled sandbox (docker compose up)
    python -m idps.cli --demo

    # Live: against your own target/attacker-controller and port list
    python -m idps.cli --live --target 10.0.0.20 --attacker-url http://10.0.0.5:9000 \\
        --ports 20-100 --interface eth0
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from idps.pipeline import run_closed_loop

DEMO_TARGET = "victim"
DEMO_ATTACKER_URL = "http://attacker:9000"
DEMO_PORTS = list(range(20, 40))  # 20 distinct ports - clears the default 10-port fan-out threshold


def _parse_ports(spec: str) -> list[int]:
    if "-" in spec:
        start, end = spec.split("-", 1)
        return list(range(int(start), int(end) + 1))
    return [int(p) for p in spec.split(",")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Network IDPS closed loop: detect -> block -> verify")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Run against the bundled attacker/victim sandbox.")
    mode.add_argument("--live", action="store_true", help="Run against a target/attacker-controller you specify.")

    parser.add_argument("--target", type=str, help="Victim hostname/IP (for --live).")
    parser.add_argument("--attacker-url", type=str, help="Base URL of the attacker control API (for --live).")
    parser.add_argument("--ports", type=str, help="Ports to scan, e.g. '20-100' or '22,80,443' (for --live).")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface to capture on.")
    parser.add_argument("--capture-duration", type=int, default=6, help="Seconds to capture per phase.")
    parser.add_argument("--output-dir", type=str, default="output")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s %(message)s")

    if args.demo:
        target, attacker_url, ports = DEMO_TARGET, DEMO_ATTACKER_URL, DEMO_PORTS
    else:
        if not (args.target and args.attacker_url and args.ports):
            raise SystemExit("--target, --attacker-url, and --ports are all required for --live")
        target, attacker_url, ports = args.target, args.attacker_url, _parse_ports(args.ports)

    report = run_closed_loop(
        target, attacker_url, ports, interface=args.interface, output_dir=args.output_dir,
        capture_duration=args.capture_duration,
    )

    print("\n=== Closed-Loop Summary ===")
    print(f"target: {target}")
    print(f"custom detections: {len(report['detections'])}")
    print(f"suricata alerts: {len(report['suricata_alerts'])}")
    print(f"firewall rule applied: {report['applied_rule'] is not None}")
    if report["verification_before"]:
        n = len(report["verification_before"]["ports_reachable"])
        print(f"before block: {n}/{len(ports)} ports reachable")
    if report["verification_after"]:
        n = len(report["verification_after"]["ports_reachable"])
        print(f"after block:  {n}/{len(ports)} ports reachable")
    print(f"CLOSED LOOP CONFIRMED: {report['closed_loop_confirmed']}")
    print(f"\nFull report: {Path(args.output_dir) / 'incident_report.json'}")

    return 0 if report["closed_loop_confirmed"] else 1


if __name__ == "__main__":
    sys.exit(main())
