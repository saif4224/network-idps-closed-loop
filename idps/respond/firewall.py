"""Real iptables orchestration: the automated response half of the
closed loop. Applies an actual DROP rule for a source IP, and can
check whether it's in place and how much traffic it has caught.

The `runner` is injectable (defaults to a real `subprocess.run` call)
so the command-construction logic is unit-testable on any machine -
iptables itself is Linux-only and needs root/NET_ADMIN, which is why
this only ever actually executes inside the sensor container.
"""
from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone

from idps.models import FirewallRule

logger = logging.getLogger(__name__)

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess]


def _real_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


class Firewall:
    def __init__(self, chain: str = "INPUT", runner: CommandRunner | None = None):
        self.chain = chain
        self._runner = runner or _real_runner

    def block_ip(self, src_ip: str) -> FirewallRule:
        cmd = ["iptables", "-I", self.chain, "-s", src_ip, "-j", "DROP"]
        result = self._runner(cmd)
        if result.returncode != 0:
            raise RuntimeError(f"iptables block failed for {src_ip}: {result.stderr}")

        logger.info("Blocked %s via %s", src_ip, " ".join(cmd))
        return FirewallRule(
            src_ip=src_ip, action="DROP", rule_spec=" ".join(cmd), applied_at=datetime.now(timezone.utc)
        )

    def is_blocked(self, src_ip: str) -> bool:
        cmd = ["iptables", "-C", self.chain, "-s", src_ip, "-j", "DROP"]
        result = self._runner(cmd)
        return result.returncode == 0

    def rule_hit_count(self, src_ip: str) -> int | None:
        """Packets matched by this IP's DROP rule so far, parsed from
        `iptables -L <chain> -n -v` - proof the block is actively
        catching real traffic, not just present but inert."""
        cmd = ["iptables", "-L", self.chain, "-n", "-v"]
        result = self._runner(cmd)
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            if src_ip in line and "DROP" in line:
                match = re.match(r"\s*(\d+)\s+(\d+)\s+DROP", line)
                if match:
                    return int(match.group(1))
        return None
