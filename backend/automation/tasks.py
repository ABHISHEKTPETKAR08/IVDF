"""
Celery background tasks for scan orchestration.

Tasks are enqueued by the FastAPI routes and executed by Celery workers.
When Celery / Redis is unavailable the FastAPI route falls back to running
_orchestrate_scan directly via asyncio (see routes/scan.py).
"""
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from celery.utils.log import get_task_logger
from sqlalchemy import select

from backend.automation.celery_app import celery_app
from backend.utils import metrics
from backend.utils.audit import (
    audit_scan_started,
    audit_scan_completed,
    audit_scan_failed,
)

logger = get_task_logger(__name__)


def _utcnow() -> datetime:
    """Timezone-aware UTC — replaces deprecated _utcnow()."""
    return datetime.now(timezone.utc)

# Map our logical scan_type → nmap / scanner behaviour strings
_SCAN_TYPE_MAP: Dict[str, str] = {
    "normal":  "full",     # standard TCP + version detection
    "safe":    "quick",    # fast TCP, no aggressive probes
    "stealth": "stealth",  # SYN scan (privileged) or TCP connect (unprivileged)
    "udp":     "udp",      # UDP scan (privileged only — falls back to TCP)
    # legacy aliases (backward-compat)
    "full":    "full",
    "quick":   "quick",
}


def _run_async(coro):
    """Run an async coroutine inside a Celery (sync) worker thread."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True, name="tasks.run_scan", max_retries=2)
def run_scan_task(
    self, scan_id: str, target: str, scan_config: Dict[str, Any]
) -> Dict:
    """
    Celery entry-point — orchestrate a full vulnerability scan.

    Args:
        scan_id:     UUID of the Scan database record.
        target:      IP / hostname / URL to scan.
        scan_config: Dict with port_range, scan_type, adaptive_mode.
    """
    logger.info("Celery scan task started: scan_id=%s target=%s", scan_id, target)
    self.update_state(state="STARTED", meta={"scan_id": scan_id, "target": target})
    try:
        result = _run_async(_orchestrate_scan(scan_id, target, scan_config))
        logger.info("Celery scan task completed: scan_id=%s", scan_id)
        return result
    except Exception as exc:
        logger.error("Celery scan task error: scan_id=%s error=%s", scan_id, exc)
        self.retry(exc=exc, countdown=30)


# ── Core async pipeline ───────────────────────────────────────────────────────

async def _orchestrate_scan(
    scan_id: str, target: str, scan_config: Dict[str, Any]
) -> Dict:
    """
    Full async scan pipeline — called by both the Celery task and the asyncio
    background-task fallback in routes/scan.py.

    Pipeline phases:
      1. Mark scan RUNNING in the database
      2. Reconnaissance (DNS, WHOIS, banner grab, SSL info)
      3. Port scanning   (nmap or pure-Python fallback)
      4. Vulnerability detection (8 HTTP/network detectors)
      5. Explanation + remediation enrichment
      6. Database persistence + COMPLETED status
    """
    from backend.scanners.recon import ReconScanner
    from backend.scanners.port_scanner import PortScanner
    from backend.detectors.sql_injection import SQLInjectionDetector
    from backend.detectors.xss import XSSDetector
    from backend.detectors.header_checker import HeaderChecker
    from backend.detectors.ssl_checker import SSLChecker
    from backend.detectors.port_checker import DangerousPortChecker
    from backend.detectors.ssh_checker import SSHChecker
    from backend.detectors.directory_traversal import DirectoryTraversalDetector
    from backend.detectors.http_methods import HTTPMethodChecker
    from backend.ai_explanations.explainer import VulnerabilityExplainer
    from backend.remediation.remediation_engine import RemediationEngine
    from backend.adaptive_scanner.adaptive_engine import AdaptiveScanEngine, ScanMode

    port_range  = scan_config.get("port_range", "1-1024")
    scan_type   = scan_config.get("scan_type", "normal")
    adaptive    = scan_config.get("adaptive_mode", False)
    nmap_mode   = _SCAN_TYPE_MAP.get(scan_type, "full")

    # ── Extract hostname and build base URL ──────────────────────────────────
    if target.startswith(("http://", "https://")):
        parsed      = urlparse(target)
        target_host = parsed.hostname or target
        scheme      = parsed.scheme
        port_part   = f":{parsed.port}" if parsed.port else ""
        base_url    = f"{scheme}://{target_host}{port_part}"
    else:
        # Strip optional `host:port` while preserving IPv6 literals "[::1]:80".
        if target.startswith("[") and "]" in target:
            target_host = target.split("]")[0].lstrip("[")
        elif target.count(":") == 1:
            target_host = target.rsplit(":", 1)[0]
        else:
            target_host = target
        base_url    = f"http://{target_host}"

    logger.info(
        "[%s] Scan pipeline starting: target=%s host=%s base_url=%s mode=%s",
        scan_id, target, target_host, base_url, scan_type,
    )

    adaptive_engine = AdaptiveScanEngine(
        mode=ScanMode.STEALTH if (adaptive or scan_type == "stealth") else ScanMode.NORMAL
    )
    all_findings: List[Any] = []
    started_at  = _utcnow()
    open_ports: List[int] = []
    os_guess: Optional[str] = None

    # ── Phase 1: Mark RUNNING ────────────────────────────────────────────────
    await _mark_running(scan_id, started_at)
    audit_scan_started(scan_id, target)
    metrics.ACTIVE_SCANS.inc()

    # ── Phase 2: Reconnaissance ───────────────────────────────────────────────
    logger.info("[%s] Phase 2: Reconnaissance", scan_id)
    recon_result = None
    try:
        recon = ReconScanner()
        recon_result = await recon.run(target_host)
        logger.info("[%s] Recon complete: ip=%s", scan_id, recon_result.resolved_ip)
    except Exception as exc:
        logger.warning("[%s] Recon failed (non-fatal): %s", scan_id, exc)

    # ── Phase 3: Port Scanning ────────────────────────────────────────────────
    # Skip port scan for 'safe' mode or when the target is a public URL that
    # would require root privileges for SYN scan.
    port_result = None
    if scan_type != "safe":
        logger.info("[%s] Phase 3: Port Scanning (%s)", scan_id, nmap_mode)
        try:
            # Enable NSE vulnerability scripting for full / stealth modes; the
            # quick mode keeps it off so dashboards stay snappy.
            enable_nse = nmap_mode in ("full", "stealth")
            port_scanner = PortScanner(port_range=port_range, enable_nse=enable_nse)
            port_result  = await port_scanner.scan(target_host, scan_type=nmap_mode)
            open_ports   = [p.port for p in port_result.open_ports]
            os_guess     = port_result.os_guess
            logger.info(
                "[%s] Port scan done: backend=%s open=%d filtered=%d nse_vulns=%d",
                scan_id, port_result.backend, len(open_ports),
                len(port_result.filtered_ports), len(port_result.nse_vulns),
            )
        except Exception as exc:
            logger.warning(
                "[%s] Port scan failed (non-fatal, continuing with HTTP checks): %s",
                scan_id, exc,
            )
    else:
        logger.info("[%s] Phase 3: Port scan skipped (safe mode)", scan_id)

    # ── Phase 4: Vulnerability Detection ─────────────────────────────────────
    logger.info("[%s] Phase 4: Vulnerability Detection", scan_id)

    detection_coros = []

    # Port-based checks (sync, instant)
    try:
        port_checker = DangerousPortChecker()
        all_findings.extend(port_checker.detect(open_ports))
    except Exception as exc:
        logger.warning("[%s] Port checker error: %s", scan_id, exc)

    # Per-service informational findings from nmap's service/version detection.
    # Lets the dashboard say "We found Apache 2.4.49 on port 80" in plain English
    # even for ports that aren't on the dangerous-port list.
    if port_result and port_result.open_ports:
        from backend.detectors.base import Severity, VulnerabilityFinding
        from backend.detectors.port_checker import _PORT_MAP as _DANGEROUS_PORT_MAP
        for pi in port_result.open_ports:
            if pi.port in _DANGEROUS_PORT_MAP:
                # Already reported by DangerousPortChecker — skip to avoid dupes.
                continue
            svc = pi.service or "unknown"
            ver = (f" {pi.version}" if pi.version else "")
            all_findings.append(
                VulnerabilityFinding(
                    name=f"Service detected: {svc}{ver} on port {pi.port}",
                    vuln_type="Open Service Detected",
                    severity=Severity.INFO,
                    explanation=(
                        f"Nmap identified `{svc}{ver}` listening on "
                        f"port {pi.port}/{pi.protocol}."
                    ),
                    technical_description=(
                        f"service={svc} version={pi.version!r} "
                        f"cpe={pi.cpe!r} extra_info={pi.extra_info!r}"
                    ),
                    impact=(
                        "Informational. Confirm this service is intended to be "
                        "reachable from this network. If not, close the port or "
                        "restrict access with a firewall."
                    ),
                    fix=[
                        "Confirm the service is required on this host.",
                        "If not required, stop and disable the service.",
                        "If required, restrict access to trusted IPs via firewall.",
                        "Keep the service patched to the latest stable version.",
                    ],
                    owasp_mapping="A05:2021 – Security Misconfiguration",
                    cvss_score=0.0,
                    affected_port=pi.port,
                )
            )

    # NSE vulnerability script output → findings
    if port_result and port_result.nse_vulns:
        from backend.detectors.base import Severity, VulnerabilityFinding
        for v in port_result.nse_vulns:
            all_findings.append(
                VulnerabilityFinding(
                    name=f"NSE vulnerability detected on port {v['port']}",
                    vuln_type="NSE Vulnerability",
                    severity=Severity.HIGH,
                    explanation=(
                        f"Nmap NSE script `{v['script']}` flagged port "
                        f"{v['port']}/{v['protocol']} as VULNERABLE."
                    ),
                    technical_description=v["output"],
                    impact=(
                        "An NSE vuln script matched a known signature. "
                        "Review the script output to identify the specific CVE / "
                        "weakness and apply the corresponding patch."
                    ),
                    fix=[
                        "Identify the CVE referenced in the NSE output.",
                        "Apply the vendor patch or upgrade the service.",
                        "If patch unavailable, restrict network exposure to the affected port.",
                    ],
                    owasp_mapping="A06:2021 – Vulnerable and Outdated Components",
                    cvss_score=7.5,
                    affected_port=v["port"],
                    response_snippet=v["output"][:300],
                )
            )

    # Network-layer checks — only when the relevant port was found open
    if 22 in open_ports:
        detection_coros.append(_safe_detect("SSH", SSHChecker().detect(target_host, 22), scan_id))
    if 443 in open_ports or target.startswith("https"):
        detection_coros.append(
            _safe_detect("SSL", SSLChecker().detect(target_host, 443), scan_id)
        )

    # HTTP-layer checks — only when an HTTP service was found OR when the
    # target itself is an http(s):// URL. Skipping when no web port is open
    # saves 30-90 s per scan against IP-only targets with nothing listening
    # on a web port (each detector otherwise burns its full connect timeout).
    _HTTP_PORTS = {80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000}
    has_http = (
        bool(_HTTP_PORTS.intersection(open_ports))
        or target.startswith(("http://", "https://"))
        # If we never ran a port scan (safe mode), assume HTTP and probe.
        or scan_type == "safe"
    )
    if has_http:
        http_checks = [
            ("Headers",       HeaderChecker().detect(base_url)),
            ("SQLi",          SQLInjectionDetector().detect(base_url)),
            ("XSS",           XSSDetector().detect(base_url)),
            ("DirTraversal",  DirectoryTraversalDetector().detect(base_url)),
            ("HTTPMethods",   HTTPMethodChecker().detect(base_url)),
        ]
        for name, coro in http_checks:
            detection_coros.append(_safe_detect(name, coro, scan_id))
    else:
        logger.info(
            "[%s] No HTTP service detected on %s — skipping HTTP-layer detectors.",
            scan_id, target_host,
        )

    results = await asyncio.gather(*detection_coros, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)

    logger.info("[%s] Detection complete: %d raw findings", scan_id, len(all_findings))

    # ── Phase 5: Enrich findings ──────────────────────────────────────────────
    logger.info("[%s] Phase 5: Enrichment", scan_id)
    try:
        remediation = RemediationEngine()
        for finding in all_findings:
            remediation.enrich_finding(finding)
    except Exception as exc:
        logger.warning("[%s] Remediation enrichment error: %s", scan_id, exc)

    explainer = VulnerabilityExplainer()
    try:
        explained        = explainer.explain_batch(all_findings)
        severity_summary = explainer.severity_summary(all_findings)
        risk_score       = explainer.risk_score(all_findings)
    except Exception as exc:
        logger.warning("[%s] Explainer error: %s", scan_id, exc)
        explained        = [f.to_dict() for f in all_findings]
        severity_summary = {}
        risk_score       = 0.0

    completed_at = _utcnow()
    duration     = (completed_at - started_at).total_seconds()

    scan_data = {
        "metadata": {
            "scan_id":      scan_id,
            "target":       target,
            "target_host":  target_host,
            "scan_type":    scan_type,
            "port_range":   port_range,
            "adaptive_mode": adaptive,
            "started_at":   started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration":     f"{duration:.1f}s",
            "risk_score":   risk_score,
            "open_ports":   open_ports,
            "os_guess":     os_guess,
        },
        "severity_summary": severity_summary,
        "vulnerabilities":  explained,
        "recon": {
            "resolved_ip":  recon_result.resolved_ip  if recon_result else None,
            "reverse_dns":  recon_result.reverse_dns  if recon_result else None,
            "open_banners": {str(k): v for k, v in recon_result.open_banners.items()} if recon_result else {},
            "ssl_info":     recon_result.ssl_info      if recon_result else None,
        },
        "port_scan": port_result.to_dict() if port_result else None,
        "adaptive_stats": adaptive_engine.get_stats(),
    }

    # ── Phase 6: Persist ──────────────────────────────────────────────────────
    logger.info("[%s] Phase 6: Persisting %d findings", scan_id, len(all_findings))
    await _persist_results(scan_id, all_findings, scan_data, completed_at, duration)
    audit_scan_completed(scan_id, target, len(all_findings), duration)

    # Metrics: per-scan duration + per-finding label counters.
    metrics.ACTIVE_SCANS.dec()
    metrics.SCANS_COMPLETED.labels(scan_type=scan_type, status="completed").inc()
    metrics.SCAN_DURATION.labels(scan_type=scan_type).observe(duration)
    for f in all_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        metrics.DETECTOR_FINDINGS.labels(vuln_type=f.vuln_type, severity=sev).inc()

    logger.info(
        "[%s] Scan pipeline finished: %d findings in %.1fs",
        scan_id, len(all_findings), duration,
    )
    return scan_data


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _safe_detect(name: str, coro, scan_id: str) -> List[Any]:
    """Wrap a detector coroutine so one failure never stops the others."""
    try:
        result = await coro
        logger.debug("[%s] %s detector returned %d finding(s)", scan_id, name, len(result or []))
        return result or []
    except Exception as exc:
        logger.warning("[%s] %s detector raised (non-fatal): %s", scan_id, name, exc)
        return []


async def _mark_running(scan_id: str, started_at: datetime) -> None:
    """Transition the Scan record to RUNNING in the database."""
    from backend.database.db import get_db_session
    from backend.database.models import Scan, ScanStatus
    try:
        async with get_db_session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan and scan.status == ScanStatus.PENDING:
                scan.status = ScanStatus.RUNNING
                scan.started_at = started_at
    except Exception as exc:
        logger.warning("Could not mark scan RUNNING: %s", exc)


async def _persist_results(
    scan_id: str,
    findings: List[Any],
    scan_data: dict,
    completed_at: datetime,
    duration: float,
) -> None:
    """Write scan results and vulnerability records to the database."""
    from backend.database.db import get_db_session
    from backend.database.models import (
        Scan, Target, Vulnerability, ScanStatus, SeverityLevel,
    )
    from sqlalchemy import select as sa_select

    try:
        async with get_db_session() as session:
            result = await session.execute(sa_select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            # Stamp the parent Target with completion time so the RescanScheduler
            # can compute "due for rescan" without crawling the Scan table.
            if scan and scan.target_id:
                t_result = await session.execute(
                    sa_select(Target).where(Target.id == scan.target_id)
                )
                target = t_result.scalar_one_or_none()
                if target:
                    target.last_scanned_at = completed_at
            if scan:
                scan.status       = ScanStatus.COMPLETED
                scan.completed_at = completed_at
                # Persist the full structured payload (metadata + recon + port_scan
                # + adaptive stats). Required so /results/{id} can return
                # raw_results for forensic / debugging use.
                scan.raw_results = {
                    "metadata":       scan_data.get("metadata"),
                    "recon":          scan_data.get("recon"),
                    "port_scan":      scan_data.get("port_scan"),
                    "adaptive_stats": scan_data.get("adaptive_stats"),
                }
                try:
                    scan.duration_seconds = duration
                except Exception:
                    pass

            for finding in findings:
                try:
                    sev_value = (
                        finding.severity.value
                        if hasattr(finding.severity, "value")
                        else str(finding.severity)
                    )
                    vuln = Vulnerability(
                        scan_id              = scan_id,
                        name                 = finding.name,
                        vuln_type            = finding.vuln_type,
                        severity             = SeverityLevel(sev_value),
                        cvss_score           = finding.cvss_score,
                        explanation          = finding.explanation,
                        technical_description= finding.technical_description,
                        impact               = finding.impact,
                        fix                  = finding.fix,
                        owasp_mapping        = finding.owasp_mapping,
                        cve_references       = finding.cve_references,
                        affected_url         = finding.affected_url,
                        affected_port        = finding.affected_port,
                        payload_used         = finding.payload_used,
                        response_snippet     = finding.response_snippet,
                    )
                    session.add(vuln)
                except Exception as exc:
                    logger.warning("Could not persist finding '%s': %s", getattr(finding, "name", "?"), exc)

    except Exception as exc:
        logger.error("Failed to persist scan results for %s: %s", scan_id, exc, exc_info=True)
