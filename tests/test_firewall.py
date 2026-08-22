import subprocess

from idps.respond.firewall import Firewall


class _FakeRunner:
    """Records every invocation and simulates iptables' real exit-code
    semantics (0 = success / rule exists, 1 = rule not found for -C)."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.blocked_ips: set[str] = set()

    def __call__(self, cmd: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(cmd)
        if cmd[1] == "-I":  # insert: ["iptables", "-I", chain, "-s", ip, "-j", "DROP"]
            self.blocked_ips.add(cmd[4])
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[1] == "-C":  # check: ["iptables", "-C", chain, "-s", ip, "-j", "DROP"]
            code = 0 if cmd[4] in self.blocked_ips else 1
            return subprocess.CompletedProcess(cmd, code, stdout="", stderr="")
        if cmd[1] == "-L":
            stdout = "\n".join(f"  42  3600 DROP  all  --  {ip}  0.0.0.0/0" for ip in self.blocked_ips)
            return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def test_block_ip_issues_correct_iptables_command():
    runner = _FakeRunner()
    fw = Firewall(runner=runner)
    rule = fw.block_ip("203.0.113.42")

    assert runner.calls[-1] == ["iptables", "-I", "INPUT", "-s", "203.0.113.42", "-j", "DROP"]
    assert rule.src_ip == "203.0.113.42"
    assert rule.action == "DROP"


def test_is_blocked_reflects_applied_rule():
    runner = _FakeRunner()
    fw = Firewall(runner=runner)

    assert not fw.is_blocked("203.0.113.42")
    fw.block_ip("203.0.113.42")
    assert fw.is_blocked("203.0.113.42")


def test_rule_hit_count_parses_packet_counter():
    runner = _FakeRunner()
    fw = Firewall(runner=runner)
    fw.block_ip("203.0.113.42")

    assert fw.rule_hit_count("203.0.113.42") == 42


def test_block_ip_raises_on_failure():
    def failing_runner(cmd):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="permission denied")

    fw = Firewall(runner=failing_runner)
    try:
        fw.block_ip("203.0.113.42")
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "permission denied" in str(exc)
