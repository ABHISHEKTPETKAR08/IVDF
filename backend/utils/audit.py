"""
Structured audit logging.

These helpers emit a single-line, machine-parseable record to the dedicated
`audit` logger. The audit log is intended for the operator's records: who
asked for what, what target, and what outcome. It is intentionally separate
from the application log to make tamper-detection and forensic queries
straightforward (e.g. ship to a WORM bucket).

Usage:
    from backend.utils.audit import audit_scan_started, audit_scan_completed
    audit_scan_started(scan_id, target, scan_type, client_ip)
    audit_scan_completed(scan_id, target, num_findings, duration_s)
"""
import logging
import logging.handlers
import os
from pathlib import Path
from typing import Any, Optional

# Dedicated logger — parent loggers' handlers are NOT inherited because
# audit lines should not be drowned in DEBUG noise.
_audit = logging.getLogger("ivdaf.audit")
_audit.propagate = False
if not _audit.handlers:
    formatter = logging.Formatter(
        "%(asctime)s | AUDIT | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    # Always go to stderr for container log collectors.
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    _audit.addHandler(stream)

    # Also persist to a rotating file in LOGS_DIR/audit.log so a forensic
    # query (`grep event=scan_failed`) survives container restarts.
    try:
        logs_dir = os.environ.get("LOGS_DIR", "./logs")
        Path(logs_dir).mkdir(parents=True, exist_ok=True)
        audit_file = Path(logs_dir) / "audit.log"
        fh = logging.handlers.RotatingFileHandler(
            audit_file, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
        )
        fh.setFormatter(formatter)
        _audit.addHandler(fh)
    except Exception:
        # Never block startup on log-file setup
        pass

    _audit.setLevel(logging.INFO)


def _kv(**fields: Any) -> str:
    """Serialise key=value pairs in a stable, grep-friendly order."""
    return " ".join(f"{k}={v!r}" if isinstance(v, str) else f"{k}={v}"
                    for k, v in fields.items() if v is not None)


def audit_scan_requested(
    scan_id: str, target: str, scan_type: str,
    client_ip: Optional[str] = None,
) -> None:
    _audit.info("event=scan_requested " + _kv(
        scan_id=scan_id, target=target, scan_type=scan_type, client_ip=client_ip,
    ))


def audit_scan_started(scan_id: str, target: str) -> None:
    _audit.info("event=scan_started " + _kv(scan_id=scan_id, target=target))


def audit_scan_completed(
    scan_id: str, target: str, num_findings: int, duration_s: float,
) -> None:
    _audit.info("event=scan_completed " + _kv(
        scan_id=scan_id, target=target,
        findings=num_findings, duration_s=round(duration_s, 2),
    ))


def audit_scan_failed(scan_id: str, target: str, error: str) -> None:
    _audit.warning("event=scan_failed " + _kv(
        scan_id=scan_id, target=target, error=error[:200],
    ))


def audit_report_generated(scan_id: str, fmt: str, file_path: str) -> None:
    _audit.info("event=report_generated " + _kv(
        scan_id=scan_id, fmt=fmt, path=file_path,
    ))
