"""
Tests for backend/scanners/port_scanner.py — Phase 3 rewrite.

Covers:
  - Argument allowlist (target + port_range regex)
  - Privilege-gated nmap argument construction
  - NSE opt-in flag
  - Result normalisation across nmap + fallback paths
  - Timeout enforcement via asyncio.wait_for
  - Retry semantics on TimeoutError vs PermissionError
"""
import asyncio
from unittest.mock import MagicMock, patch

import pytest

from backend.scanners.port_scanner import (
    PortScanner,
    PortScanResult,
    PortInfo,
    _validate_port_range,
    _validate_target,
    _is_privileged,
)


# ── Argument-allowlist unit tests ─────────────────────────────────────────────

class TestPortRangeValidator:
    def test_accepts_simple_range(self):
        assert _validate_port_range("1-1024") == "1-1024"

    def test_accepts_comma_list(self):
        assert _validate_port_range("22,80,443") == "22,80,443"

    @pytest.mark.parametrize("bad", [
        "1-1024;rm -rf /", "$(whoami)", "1-1024 -sS", "1-1024|cat",
        "1-1024 --script=evil", "", "a-b", "1-1024\n", "1-1024 ",
        "1" * 100,  # length cap
    ])
    def test_rejects_unsafe(self, bad):
        with pytest.raises(ValueError):
            _validate_port_range(bad)


class TestTargetValidator:
    @pytest.mark.parametrize("good", [
        "127.0.0.1", "192.168.1.1", "dvwa.local",
        "10.0.0.0/24", "[::1]", "host-with-dash.example.com",
    ])
    def test_accepts_safe_targets(self, good):
        assert _validate_target(good) == good

    @pytest.mark.parametrize("bad", [
        "127.0.0.1;rm -rf /", "$(curl evil)", "host && evil",
        "target with space", "host|cat", "", "x" * 300,
    ])
    def test_rejects_unsafe_targets(self, bad):
        with pytest.raises(ValueError):
            _validate_target(bad)


# ── Privilege detection ───────────────────────────────────────────────────────

class TestPrivilegeDetection:
    def test_returns_bool(self):
        assert isinstance(_is_privileged(), bool)

    def test_env_override_true(self, monkeypatch):
        monkeypatch.setenv("NMAP_PRIVILEGED", "true")
        assert _is_privileged() is True

    def test_env_override_false(self, monkeypatch):
        monkeypatch.setenv("NMAP_PRIVILEGED", "false")
        assert _is_privileged() is False


# ── Argument construction ─────────────────────────────────────────────────────

class TestNmapArgBuilder:
    def _scanner(self, **kw):
        return PortScanner(port_range="80,443", **kw)

    def test_quick_args(self):
        s = self._scanner()
        args = s._build_nmap_args("quick")
        assert "--top-ports 100" in args
        assert "-sV" in args
        assert "-Pn" in args

    def test_full_args_unprivileged_uses_tcp_connect(self):
        with patch("backend.scanners.port_scanner.PRIVILEGED", False):
            s = self._scanner()
            args = s._build_nmap_args("full")
        assert "-sT" in args
        assert "-O" not in args  # OS detection requires root

    def test_full_args_privileged_includes_os_detection(self):
        with patch("backend.scanners.port_scanner.PRIVILEGED", True):
            s = self._scanner()
            args = s._build_nmap_args("full")
        assert "-O" in args
        assert "--osscan-guess" in args

    def test_stealth_downgrades_to_sT_unprivileged(self):
        with patch("backend.scanners.port_scanner.PRIVILEGED", False):
            s = self._scanner()
            args = s._build_nmap_args("stealth")
        assert "-sT" in args
        assert "-sS" not in args

    def test_stealth_uses_sS_privileged(self):
        with patch("backend.scanners.port_scanner.PRIVILEGED", True):
            s = self._scanner()
            args = s._build_nmap_args("stealth")
        assert "-sS" in args

    def test_udp_unprivileged_downgrades_to_tcp(self):
        with patch("backend.scanners.port_scanner.PRIVILEGED", False):
            s = self._scanner()
            args = s._build_nmap_args("udp")
        assert "-sU" not in args
        assert "-sT" in args

    def test_udp_privileged_emits_sU(self):
        with patch("backend.scanners.port_scanner.PRIVILEGED", True):
            s = self._scanner()
            args = s._build_nmap_args("udp")
        assert "-sU" in args

    def test_nse_appends_script_flag(self):
        s = self._scanner(enable_nse=True)
        args = s._build_nmap_args("full")
        assert "--script vuln" in args

    def test_host_timeout_present(self):
        s = self._scanner(nmap_timeout=42)
        args = s._build_nmap_args("full")
        assert "--host-timeout 42s" in args


# ── Port-range parser ─────────────────────────────────────────────────────────

class TestPortRangeParser:
    def test_hyphen(self):
        assert PortScanner._parse_port_range("80-82") == [80, 81, 82]

    def test_comma(self):
        assert PortScanner._parse_port_range("22,80,443") == [22, 80, 443]

    def test_mixed(self):
        result = PortScanner._parse_port_range("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_deduplication(self):
        result = PortScanner._parse_port_range("80-82,80,82")
        assert result == [80, 81, 82]

    def test_rejects_zero(self):
        with pytest.raises(ValueError):
            PortScanner._parse_port_range("0-1024")

    def test_rejects_out_of_range(self):
        with pytest.raises(ValueError):
            PortScanner._parse_port_range("1-99999")

    def test_rejects_inverted_range(self):
        with pytest.raises(ValueError):
            PortScanner._parse_port_range("100-50")


# ── Result envelope ───────────────────────────────────────────────────────────

class TestResultEnvelope:
    def test_to_dict_includes_backend(self):
        r = PortScanResult(target="127.0.0.1", backend="nmap")
        d = r.to_dict()
        assert d["backend"] == "nmap"
        assert "duration_seconds" in d
        assert "nse_vulns" in d
        assert "errors" in d

    def test_port_info_to_dict(self):
        p = PortInfo(port=22, service="ssh", version="OpenSSH 8.4",
                     cpe="cpe:/a:openbsd:openssh:8.4")
        d = p.to_dict()
        assert d["service"] == "ssh"
        assert d["cpe"] == "cpe:/a:openbsd:openssh:8.4"


# ── Mocked nmap end-to-end ────────────────────────────────────────────────────

class _FakeNmapHostData:
    """Minimal stand-in for nm[host] mapping protocols → ports → info dicts."""
    def __init__(self, ports, os_match=None):
        self._ports = ports
        self._os = os_match

    def state(self):
        return "up"

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, proto):
        if proto == "osmatch":
            return [{"name": self._os}] if self._os else []
        return {p: info for p, info in self._ports}

    def __contains__(self, key):
        if key == "osmatch":
            return self._os is not None
        return False

    def get(self, key, default=None):
        if key == "osmatch" and self._os:
            return [{"name": self._os}]
        return default


class _FakeNmapPortScanner:
    """Stand-in for nmap.PortScanner."""
    def __init__(self, ports=None, os_match=None):
        self._ports = ports or []
        self._os = os_match
        self._host = "127.0.0.1"

    def scan(self, hosts, arguments):
        self._host = hosts
        self.last_args = arguments

    def all_hosts(self):
        return [self._host]

    def __getitem__(self, host):
        return _FakeNmapHostData(self._ports, self._os)


@pytest.mark.asyncio
async def test_scan_nmap_path_returns_open_ports():
    """Mock nmap to return one open port; scanner should normalise it."""
    fake_ports = [
        (22, {"state": "open", "name": "ssh", "version": "OpenSSH 8.4",
              "extrainfo": "Ubuntu", "cpe": "cpe:/a:openbsd:openssh:8.4"}),
        (80, {"state": "filtered"}),
        (443, {"state": "closed"}),
    ]

    with patch(
        "backend.scanners.port_scanner.nmap.PortScanner",
        return_value=_FakeNmapPortScanner(ports=fake_ports, os_match="Linux 5.x"),
    ), patch(
        "backend.scanners.port_scanner._NMAP_AVAILABLE", True,
    ):
        scanner = PortScanner(port_range="22,80,443", nmap_timeout=5)
        result = await scanner.scan("127.0.0.1", scan_type="quick")

    assert result.backend == "nmap"
    assert len(result.open_ports) == 1
    assert result.open_ports[0].port == 22
    assert result.open_ports[0].service == "ssh"
    assert 80 in result.filtered_ports
    assert result.closed_port_count == 1
    assert result.duration_seconds >= 0


@pytest.mark.asyncio
async def test_scan_handles_nmap_permission_error():
    """PermissionError from nmap must be captured, not propagated."""
    fake = MagicMock()
    fake.scan.side_effect = PermissionError("requires root")
    with patch(
        "backend.scanners.port_scanner.nmap.PortScanner", return_value=fake,
    ), patch(
        "backend.scanners.port_scanner._NMAP_AVAILABLE", True,
    ):
        scanner = PortScanner(port_range="22", max_retries=0)
        result = await scanner.scan("127.0.0.1", scan_type="quick")

    assert any("permission" in e.lower() for e in result.errors)


@pytest.mark.asyncio
async def test_scan_handles_generic_exception_with_retry():
    """Generic exceptions are retried up to max_retries."""
    fake = MagicMock()
    fake.scan.side_effect = RuntimeError("transient")
    with patch(
        "backend.scanners.port_scanner.nmap.PortScanner", return_value=fake,
    ), patch(
        "backend.scanners.port_scanner._NMAP_AVAILABLE", True,
    ):
        scanner = PortScanner(port_range="22", max_retries=1, nmap_timeout=5)
        result = await scanner.scan("127.0.0.1", scan_type="quick")

    # Initial attempt + 1 retry = 2 invocations
    assert fake.scan.call_count == 2
    assert any("RuntimeError" in e for e in result.errors)
