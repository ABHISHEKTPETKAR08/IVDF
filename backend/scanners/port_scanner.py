"""
Port scanning module — stabilised Phase 3 refactor.

Goals (per SCANNER_REVIEW.md):
  • Async-safe wrapper around python-nmap with hard timeout, retry, and
    graceful degradation to a pure-Python asyncio TCP fallback.
  • Privilege-aware: SYN scan (-sS) and OS detection (-O) are silently
    downgraded to TCP-connect (-sT) when the process is not privileged.
  • NSE vulnerability scripting (--script vuln) gated behind an opt-in flag.
  • UDP scan support (-sU) for `udp` and `full` scan types.
  • Strict argument allowlist — no shell, no f-string interpolation of
    untrusted strings into the nmap command line.
  • Stable, normalised result shape across both nmap and fallback paths.
"""
from __future__ import annotations

import asyncio
import ctypes
import os
import platform
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import nmap  # type: ignore
    _NMAP_AVAILABLE = True
except ImportError:
    _NMAP_AVAILABLE = False
    nmap = None  # type: ignore
    logger.warning("python-nmap not installed; using pure-Python fallback scanner.")


# ── Port range / argument validation ──────────────────────────────────────────

_PORT_RANGE_RE = re.compile(r"^[0-9,\-]+$")


def _validate_port_range(port_range: str) -> str:
    """Reject any character outside [0-9,-]; reject lengths > 64."""
    if not port_range or len(port_range) > 64 or not _PORT_RANGE_RE.match(port_range):
        raise ValueError(f"Unsafe port_range: {port_range!r}")
    return port_range


_TARGET_RE = re.compile(r"^[A-Za-z0-9_.\-:\[\]/]+$")


def _validate_target(target: str) -> str:
    """Reject characters that could escape into the nmap command line."""
    if not target or len(target) > 256 or not _TARGET_RE.match(target):
        raise ValueError(f"Unsafe target: {target!r}")
    return target


# ── Privilege detection ───────────────────────────────────────────────────────

def _is_privileged() -> bool:
    """
    Return True iff the current process can perform raw-socket operations.

    Resolution order:
      1. NMAP_PRIVILEGED env var explicitly set to 'true' / 'false' wins.
         Use this in Docker when nmap has been granted CAP_NET_RAW via setcap
         but the container itself runs as a non-root user.
      2. Linux / macOS — EUID == 0.
      3. Windows — token is elevated (admin).
    """
    env_override = os.environ.get("NMAP_PRIVILEGED", "").strip().lower()
    if env_override in ("1", "true", "yes"):
        return True
    if env_override in ("0", "false", "no"):
        return False
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


PRIVILEGED = _is_privileged()
if not PRIVILEGED:
    logger.info(
        "Process is not privileged — SYN scan (-sS) and OS detection (-O) "
        "will be downgraded to TCP-connect (-sT)."
    )


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    """Information about a single open port."""
    port: int
    protocol: str = "tcp"           # tcp | udp
    state: str = "open"             # open | filtered | open|filtered
    service: str = "unknown"
    version: str = ""
    extra_info: str = ""
    cpe: str = ""                   # Common Platform Enumeration when available

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
        }


@dataclass
class PortScanResult:
    """Normalised result returned by both the nmap and asyncio paths."""
    target: str
    resolved_ip: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: List[PortInfo] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    closed_port_count: int = 0
    scan_type: str = "tcp"
    backend: str = "fallback"        # "nmap" or "fallback"
    duration_seconds: float = 0.0
    nse_vulns: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "os_guess": self.os_guess,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "filtered_ports": self.filtered_ports,
            "closed_port_count": self.closed_port_count,
            "scan_type": self.scan_type,
            "backend": self.backend,
            "duration_seconds": round(self.duration_seconds, 2),
            "nse_vulns": self.nse_vulns,
            "errors": self.errors,
        }


# ── Public scanner ────────────────────────────────────────────────────────────

class PortScanner:
    """
    High-level port scanner.

    Args:
        port_range:     '1-1024' or '80,443,8080' (validated)
        timeout:        per-port connect timeout for the asyncio fallback
        max_concurrent: concurrency cap for the asyncio fallback
        nmap_timeout:   hard timeout (s) for the entire nmap subprocess
        max_retries:    number of nmap retries on timeout / transient failure
        enable_nse:     run `--script vuln` for richer vulnerability data
                        (requires nmap >= 7.x; opt-in due to extra runtime)
    """

    def __init__(
        self,
        port_range: str = "1-1024",
        timeout: float = 2.0,
        max_concurrent: int = 200,
        nmap_timeout: int = 180,
        max_retries: int = 2,
        enable_nse: bool = False,
    ):
        self.port_range = _validate_port_range(port_range)
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.nmap_timeout = nmap_timeout
        self.max_retries = max(0, max_retries)
        self.enable_nse = enable_nse

    # ── Entry-point ───────────────────────────────────────────────────────────

    async def scan(self, target: str, scan_type: str = "full") -> PortScanResult:
        """
        Scan *target* for open ports.

        scan_type options:
          "full"    — TCP + service version detection (+ OS detection if privileged)
          "quick"   — top-100 TCP ports only
          "stealth" — SYN scan if privileged, else TCP connect with timing -T2
          "udp"     — UDP scan (privileged only; falls through to TCP otherwise)
        """
        target = _validate_target(target)
        result = PortScanResult(target=target, scan_type=scan_type)
        loop = asyncio.get_running_loop()
        t0 = loop.time()

        if _NMAP_AVAILABLE:
            await self._nmap_scan(target, scan_type, result)
            # Fallback if nmap completely failed (e.g., binary missing despite
            # the python-nmap package being importable).
            if not result.open_ports and not result.filtered_ports and result.errors:
                logger.info(
                    "nmap returned no usable data (%s) — running asyncio fallback.",
                    result.errors[-1],
                )
                result.backend = "fallback"
                await self._async_tcp_scan(target, result)
        else:
            await self._async_tcp_scan(target, result)

        result.duration_seconds = loop.time() - t0
        logger.info(
            "Port scan complete: target=%s backend=%s open=%d filtered=%d duration=%.2fs",
            target, result.backend, len(result.open_ports),
            len(result.filtered_ports), result.duration_seconds,
        )
        return result

    # ── Nmap backend ──────────────────────────────────────────────────────────

    async def _nmap_scan(
        self, target: str, scan_type: str, result: PortScanResult
    ) -> None:
        """Run nmap in a worker thread, with timeout and retries."""
        for attempt in range(1, self.max_retries + 2):  # initial + retries
            try:
                # asyncio.to_thread is the modern idiom (Py 3.9+).
                await asyncio.wait_for(
                    asyncio.to_thread(self._run_nmap_sync, target, scan_type, result),
                    timeout=self.nmap_timeout,
                )
                # Mark backend on success
                result.backend = "nmap"
                return
            except asyncio.TimeoutError:
                msg = (
                    f"nmap timed out after {self.nmap_timeout}s "
                    f"(attempt {attempt}/{self.max_retries + 1})"
                )
                logger.warning(msg)
                result.errors.append(msg)
                if attempt > self.max_retries:
                    return
                await asyncio.sleep(min(2 * attempt, 10))
            except PermissionError as exc:
                msg = f"nmap permission error: {exc}"
                logger.warning(msg)
                result.errors.append(msg)
                return
            except Exception as exc:
                msg = f"nmap error (attempt {attempt}): {type(exc).__name__}: {exc}"
                logger.error(msg)
                result.errors.append(msg)
                if attempt > self.max_retries:
                    return
                await asyncio.sleep(min(2 * attempt, 10))

    def _build_nmap_args(self, scan_type: str) -> str:
        """
        Build the nmap argument string from a strict allowlist.

        Privileged-only flags (-sS, -sU, -O) are downgraded to safe equivalents
        when running unprivileged.
        """
        # Defensive: re-validate the (already-validated) port range before
        # interpolating it — defence in depth.
        port_range = _validate_port_range(self.port_range)

        if scan_type == "quick":
            args = "--top-ports 100 -T3 -sV -Pn"
        elif scan_type == "stealth":
            base = "-sS" if PRIVILEGED else "-sT"
            args = f"-p {port_range} -T2 {base} --max-retries 1 -Pn"
        elif scan_type == "udp":
            # UDP scan requires privilege; fall back to TCP connect otherwise.
            if PRIVILEGED:
                args = f"-p {port_range} -sU -T3 --max-retries 1 -Pn"
            else:
                logger.info("UDP scan requested but unprivileged — downgrading to TCP.")
                args = f"-p {port_range} -sT -T3 -sV -Pn"
        else:  # full / normal — default
            tcp_flag = "-sT"     # TCP connect (works unprivileged)
            os_flag = " -O --osscan-guess" if PRIVILEGED else ""
            args = f"-p {port_range} {tcp_flag} -sV{os_flag} -T3 -Pn"

        if self.enable_nse:
            # `vuln` is the curated NSE script category for known CVEs.
            args += " --script vuln --script-timeout 60s"

        # Hard-cap host-timeout so a single bad target can't burn through
        # the per-task soft time-limit.
        args += f" --host-timeout {self.nmap_timeout}s"
        return args

    def _run_nmap_sync(
        self, target: str, scan_type: str, result: PortScanResult
    ) -> None:
        """Blocking nmap call — runs inside a worker thread via to_thread()."""
        nm = nmap.PortScanner()
        args = self._build_nmap_args(scan_type)
        logger.debug("nmap %s %s", target, args)
        nm.scan(hosts=target, arguments=args)

        hosts = nm.all_hosts()
        if not hosts:
            result.errors.append("nmap returned no hosts (target unreachable?)")
            return

        # Use the first responding host as the canonical result identity.
        primary = hosts[0]
        result.resolved_ip = primary

        for host in hosts:
            host_data = nm[host]

            # OS guess — only the highest-accuracy match from the primary host.
            if host == primary and "osmatch" in host_data and host_data["osmatch"]:
                top = host_data["osmatch"][0]
                result.os_guess = top.get("name") or "Unknown"

            for proto in host_data.all_protocols():
                for port, info in host_data[proto].items():
                    state = info.get("state", "")
                    if state == "open":
                        result.open_ports.append(
                            PortInfo(
                                port=int(port),
                                protocol=proto,
                                state=state,
                                service=info.get("name") or "unknown",
                                version=info.get("version") or "",
                                extra_info=info.get("extrainfo") or "",
                                cpe=info.get("cpe") or "",
                            )
                        )
                    elif state == "filtered":
                        result.filtered_ports.append(int(port))
                    else:
                        result.closed_port_count += 1

                    # NSE vulnerability script output is attached to each port.
                    script_data = info.get("script") or {}
                    if self.enable_nse and script_data:
                        for script_name, script_out in script_data.items():
                            if "VULNERABLE" in (script_out or "").upper():
                                result.nse_vulns.append({
                                    "port": int(port),
                                    "protocol": proto,
                                    "script": script_name,
                                    "output": (script_out or "")[:1000],
                                })

    # ── Pure-Python asyncio fallback ──────────────────────────────────────────

    async def _async_tcp_scan(self, target: str, result: PortScanResult) -> None:
        """Asyncio TCP-connect scan when nmap is unavailable / failed."""
        try:
            ports = self._parse_port_range(self.port_range)
        except ValueError as exc:
            result.errors.append(f"invalid port_range: {exc}")
            return

        # Lock to coordinate appends from many coroutines — safer than relying
        # on GIL atomicity of list.append.
        sem = asyncio.Semaphore(self.max_concurrent)
        lock = asyncio.Lock()

        async def _probe(port: int) -> None:
            async with sem:
                try:
                    conn = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    pi = PortInfo(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=self._port_to_service(port),
                    )
                    async with lock:
                        result.open_ports.append(pi)
                except asyncio.TimeoutError:
                    async with lock:
                        result.filtered_ports.append(port)
                except (OSError, ConnectionRefusedError):
                    async with lock:
                        result.closed_port_count += 1

        await asyncio.gather(*(_probe(p) for p in ports), return_exceptions=True)
        result.backend = "fallback"

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_port_range(port_range: str) -> List[int]:
        """Convert '1-1024' or '80,443,8080' to a deduplicated, sorted list."""
        ports: set[int] = set()
        for segment in port_range.split(","):
            segment = segment.strip()
            if "-" in segment:
                start, end = segment.split("-", 1)
                s, e = int(start), int(end)
                if not (1 <= s <= 65535 and 1 <= e <= 65535) or s > e:
                    raise ValueError(f"invalid range segment: {segment!r}")
                if e - s > 65535:
                    raise ValueError(f"port range too wide: {segment!r}")
                ports.update(range(s, e + 1))
            elif segment:
                v = int(segment)
                if not 1 <= v <= 65535:
                    raise ValueError(f"port out of range: {segment!r}")
                ports.add(v)
        return sorted(ports)

    @staticmethod
    def _port_to_service(port: int) -> str:
        _svc = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
            8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
        }
        return _svc.get(port, "unknown")
