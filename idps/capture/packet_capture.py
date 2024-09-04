"""Packet capture via the real `tshark` binary (Wireshark's
command-line component - same dissector engine as the Wireshark GUI).

Shells out to tshark directly (the same pattern as detect/suricata_client.py
for Suricata) rather than going through a Python wrapper library: it's
one less indirection, and it sidesteps real version-fragility we hit
with the `pyshark` package (its asyncio integration depends on
`asyncio.SafeChildWatcher`, which CPython removed in 3.14 - a genuine
compatibility break we found while building this, not a hypothetical
one). Requires the real `tshark` binary on PATH (`brew install
wireshark` on macOS installs the CLI tools without the GUI; already
present via apt in the sensor container).
"""
from __future__ import annotations

import csv
import io
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from idps.models import Packet

logger = logging.getLogger(__name__)

FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "tcp.dstport", "tcp.flags",
    "udp.srcport", "udp.dstport", "frame.len",
]


def _tshark_field_args() -> list[str]:
    args = ["-T", "fields"]
    for field in FIELDS:
        args += ["-e", field]
    args += ["-E", "header=n", "-E", "separator=,", "-E", "quote=n"]
    return args


def parse_tshark_csv(output: str) -> list[Packet]:
    packets = []
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) < len(FIELDS) or not row[0]:
            continue
        time_epoch, src, dst, ip_proto, tcp_sport, tcp_dport, tcp_flags, udp_sport, udp_dport, length = row

        if ip_proto == "6":  # TCP
            protocol, src_port, dst_port = "TCP", tcp_sport, tcp_dport
            flags = _decode_tcp_flags(tcp_flags)
        elif ip_proto == "17":  # UDP
            protocol, src_port, dst_port = "UDP", udp_sport, udp_dport
            flags = ""
        else:
            continue

        if not src or not dst or not src_port or not dst_port:
            continue

        packets.append(
            Packet(
                timestamp=datetime.fromtimestamp(float(time_epoch), tz=timezone.utc),
                src_ip=src,
                dst_ip=dst,
                src_port=int(src_port),
                dst_port=int(dst_port),
                protocol=protocol,
                flags=flags,
                length=int(length) if length else 0,
            )
        )
    return packets


def _decode_tcp_flags(hex_flags: str) -> str:
    if not hex_flags:
        return ""
    value = int(hex_flags, 16)
    names = []
    if value & 0x02:
        names.append("SYN")
    if value & 0x10:
        names.append("ACK")
    if value & 0x01:
        names.append("FIN")
    if value & 0x04:
        names.append("RST")
    if value & 0x08:
        names.append("PSH")
    return ",".join(names)


class PacketCapture:
    def __init__(self, tshark_path: str = "tshark"):
        self.tshark_path = tshark_path

    def read_pcap_file(self, path: str | Path) -> list[Packet]:
        cmd = [self.tshark_path, "-r", str(path), *_tshark_field_args()]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets = parse_tshark_csv(result.stdout)
        logger.info("Parsed %d packet(s) from %s", len(packets), path)
        return packets

    def capture_to_file(self, interface: str, out_path: str | Path, duration_seconds: int) -> subprocess.Popen:
        """Starts a background tshark capture, returns the running process.

        stderr is redirected to `<out_path>.stderr.log` (not swallowed):
        if the capture process dies early - e.g. no permission to open the
        interface - `wait_for_capture` surfaces that log instead of letting
        the caller stumble into a confusing downstream "file not found"
        error from read_pcap_file.
        """
        cmd = [self.tshark_path, "-i", interface, "-a", f"duration:{duration_seconds}", "-w", str(out_path)]
        logger.info("Starting background capture: %s", " ".join(cmd))
        stderr_path = Path(f"{out_path}.stderr.log")
        stderr_file = stderr_path.open("w")
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=stderr_file)

    def wait_for_capture(self, proc: subprocess.Popen, out_path: str | Path, timeout: int) -> None:
        proc.wait(timeout=timeout)
        if proc.returncode != 0:
            stderr_path = Path(f"{out_path}.stderr.log")
            stderr_text = stderr_path.read_text() if stderr_path.exists() else "(no stderr captured)"
            raise RuntimeError(
                f"tshark capture to {out_path} exited with code {proc.returncode}:\n{stderr_text}"
            )
