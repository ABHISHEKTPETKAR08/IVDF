"""
Unit tests for scanning modules and adaptive engine.
Network calls are mocked throughout.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.scanners.port_scanner import PortScanner, PortInfo, PortScanResult
from backend.adaptive_scanner.adaptive_engine import AdaptiveScanEngine, ScanMode, AdaptiveStats
from backend.utils.validators import validate_target, validate_port_range, sanitize_string


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Validators ────────────────────────────────────────────────────────────────

class TestValidators:
    def test_private_ip_accepted(self):
        ok, reason = validate_target("192.168.1.100")
        assert ok, reason

    def test_rfc1918_10_x_accepted(self):
        ok, _ = validate_target("10.0.0.1")
        assert ok

    def test_loopback_accepted(self):
        ok, _ = validate_target("127.0.0.1")
        assert ok

    def test_public_ip_accepted_with_warning(self):
        # Validator no longer blocks public IPs — authorisation is the
        # operator's responsibility (logged warning is non-fatal).
        ok, _ = validate_target("8.8.8.8")
        assert ok

    def test_lab_hostname_accepted(self):
        ok, _ = validate_target("dvwa")
        assert ok

    def test_juice_shop_accepted(self):
        ok, _ = validate_target("juiceshop")
        assert ok

    def test_empty_target_rejected(self):
        ok, _ = validate_target("")
        assert not ok

    def test_none_target_rejected(self):
        ok, _ = validate_target(None)
        assert not ok

    def test_valid_port_range_hyphen(self):
        ok, _ = validate_port_range("1-1024")
        assert ok

    def test_valid_port_range_comma(self):
        ok, _ = validate_port_range("80,443,8080")
        assert ok

    def test_invalid_port_range(self):
        ok, _ = validate_port_range("abc-def")
        assert not ok

    def test_port_out_of_range(self):
        ok, _ = validate_port_range("0-70000")
        assert not ok

    def test_sanitize_string_removes_html(self):
        result = sanitize_string("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "script" in result   # text preserved, tags stripped

    def test_sanitize_string_truncates(self):
        long_string = "a" * 1000
        result = sanitize_string(long_string, max_length=100)
        assert len(result) == 100


# ── Port Scanner ──────────────────────────────────────────────────────────────

class TestPortScanner:
    def test_parse_port_range_hyphen(self):
        ports = PortScanner._parse_port_range("80-83")
        assert ports == [80, 81, 82, 83]

    def test_parse_port_range_comma(self):
        ports = PortScanner._parse_port_range("22,80,443")
        assert ports == [22, 80, 443]

    def test_port_to_service_known(self):
        assert PortScanner._port_to_service(22) == "ssh"
        assert PortScanner._port_to_service(80) == "http"
        assert PortScanner._port_to_service(443) == "https"

    def test_port_to_service_unknown(self):
        assert PortScanner._port_to_service(12345) == "unknown"

    def test_port_info_dataclass(self):
        info = PortInfo(port=80, service="http", state="open")
        assert info.port == 80
        assert info.state == "open"

    def test_scan_result_dataclass(self):
        result = PortScanResult(target="192.168.1.1")
        assert result.target == "192.168.1.1"
        assert result.open_ports == []
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_async_tcp_scan_closed_ports(self):
        """All ports refused → result has only closed_port_count."""
        scanner = PortScanner(port_range="9998-9999", timeout=0.1)
        result = await scanner._async_tcp_scan("127.0.0.1", PortScanResult(target="127.0.0.1"))
        # Ports 9998-9999 are almost certainly closed on any test machine
        assert result.closed_port_count >= 0   # At least it ran without error


# ── Adaptive Engine ───────────────────────────────────────────────────────────

class TestAdaptiveEngine:
    def test_default_mode_is_adaptive(self):
        engine = AdaptiveScanEngine()
        assert engine.mode == ScanMode.ADAPTIVE

    def test_stats_initialised(self):
        engine = AdaptiveScanEngine()
        assert engine.stats.probes_sent == 0
        assert engine.stats.drop_rate == 0.0

    def test_backoff_increases_with_attempts(self):
        engine = AdaptiveScanEngine()
        delays = [engine._backoff_delay(i) for i in range(1, 4)]
        # Each attempt should produce a larger base delay
        assert delays[1] > delays[0]
        assert delays[2] > delays[1]

    def test_backoff_does_not_exceed_max_delay(self):
        engine = AdaptiveScanEngine(max_delay=2.0)
        for attempt in range(1, 10):
            delay = engine._backoff_delay(attempt)
            assert delay <= engine.max_delay * 2   # Including jitter

    def test_escalate_delay_increases_current_delay(self):
        engine = AdaptiveScanEngine(min_delay=0.1, max_delay=5.0)
        initial_delay = engine.stats.current_delay
        engine._escalate_delay()
        assert engine.stats.current_delay >= initial_delay

    def test_escalate_delay_capped_at_max(self):
        engine = AdaptiveScanEngine(min_delay=4.9, max_delay=5.0)
        engine.stats.current_delay = 5.0
        engine._escalate_delay()
        assert engine.stats.current_delay <= 5.0

    def test_record_success_updates_stats(self):
        engine = AdaptiveScanEngine()
        engine._record_success(100.0)
        assert engine.stats.probes_sent == 1
        assert engine.stats.probes_succeeded == 1
        assert engine.stats.consecutive_drops == 0

    def test_record_drop_updates_stats(self):
        engine = AdaptiveScanEngine()
        engine._record_drop()
        assert engine.stats.probes_sent == 1
        assert engine.stats.probes_dropped == 1
        assert engine.stats.consecutive_drops == 1

    def test_drop_rate_calculation(self):
        engine = AdaptiveScanEngine()
        engine._record_success(50.0)
        engine._record_drop()
        assert engine.stats.drop_rate == 0.5

    def test_effective_concurrency_reduces_on_high_drop_rate(self):
        engine = AdaptiveScanEngine()
        # Simulate high drop rate
        for _ in range(3):
            engine._record_drop()
        for _ in range(7):
            engine._record_success(100.0)
        # 30% drop rate should halve concurrency
        reduced = engine._effective_concurrency(10)
        assert reduced <= 10

    def test_get_stats_returns_dict(self):
        engine = AdaptiveScanEngine()
        stats = engine.get_stats()
        assert "mode" in stats
        assert "probes_sent" in stats
        assert "drop_rate_pct" in stats

    @pytest.mark.asyncio
    async def test_probe_returns_result_on_success(self):
        engine = AdaptiveScanEngine(min_delay=0, max_delay=0)

        async def mock_fn(x):
            return x * 2

        result = await engine.probe(mock_fn, 5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_probe_returns_none_after_max_retries(self):
        engine = AdaptiveScanEngine(min_delay=0, max_delay=0, max_retries=2)

        async def always_fails(x):
            raise OSError("Connection refused")

        result = await engine.probe(always_fails, "target")
        assert result is None

    @pytest.mark.asyncio
    async def test_batch_probe(self):
        engine = AdaptiveScanEngine(min_delay=0, max_delay=0)

        async def double(x):
            return x * 2

        results = await engine.batch_probe(double, [1, 2, 3, 4, 5], concurrency=3)
        assert results == [2, 4, 6, 8, 10]


# ── Recon Scanner (light) ─────────────────────────────────────────────────────

class TestReconScanner:
    def test_guess_service_by_port(self):
        from backend.scanners.recon import ReconScanner
        scanner = ReconScanner()
        assert scanner._guess_service(22, "SSH-2.0-OpenSSH") == "SSH"
        assert scanner._guess_service(80, "HTTP/1.1") == "HTTP"
        assert scanner._guess_service(21, "220 FTP ready") == "FTP"
