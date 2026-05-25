"""
Centralised logging configuration with request-ID propagation.

Features:
- Console + rotating file handler
- Optional JSON output (LOG_JSON=true)
- Per-request ID injected via contextvars (set in app middleware)
- Suppresses noisy third-party loggers in production
"""
import json
import logging
import logging.handlers
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Request-ID context variable ───────────────────────────────────────────────
# Set by the HTTP middleware; propagates automatically through async tasks
# running in the same context (asyncio coroutines, NOT Celery tasks).
_request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def set_request_id(rid: str) -> None:
    _request_id_var.set(rid)


def get_request_id() -> Optional[str]:
    return _request_id_var.get()


# ── Formatters ────────────────────────────────────────────────────────────────

class _TextFormatter(logging.Formatter):
    """Human-readable format: timestamp | level | [req-id] | name | message"""

    def format(self, record: logging.LogRecord) -> str:
        rid = _request_id_var.get()
        rid_part = f" [{rid[:8]}]" if rid else ""
        record.msg = f"{rid_part} {record.getMessage()}" if rid else record.getMessage()
        record.args = ()  # prevent double-formatting

        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        return (
            f"{ts} | {record.levelname:<8} | {record.name}{rid_part} | "
            f"{record.getMessage()}"
        )


class _JsonFormatter(logging.Formatter):
    """Structured JSON log lines — suitable for Loki / ELK / CloudWatch."""

    def format(self, record: logging.LogRecord) -> str:
        rid = _request_id_var.get()
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if rid:
            payload["request_id"] = rid
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# ── Noisy third-party loggers to silence in production ───────────────────────
# When Redis is intentionally down (single-host lab mode), Celery's result
# backend pool retries up to 20 times per task; the resulting "Connection to
# Redis lost" log spam is cosmetic and is silenced here.
_QUIET_LOGGERS = [
    "httpx", "httpcore", "urllib3", "asyncio",
    "celery.utils.functional", "kombu",
    "celery.backends.redis", "celery.app.trace", "celery.worker",
    "celery.app.builtins", "celery.bootsteps",
]


def setup_logging(
    log_level: str = "INFO",
    log_file: str = "./logs/vuln_scanner.log",
    json_logs: bool = False,
) -> None:
    """Configure root logger with console + rotating-file handlers."""
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    formatter: logging.Formatter = (
        _JsonFormatter() if json_logs else _TextFormatter()
    )

    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove any handlers added by earlier calls or third-party libs
    root.handlers.clear()

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # Rotating file (10 MB × 5 backups)
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(formatter)
    root.addHandler(fh)

    # Silence noisy libraries in non-DEBUG mode
    if log_level.upper() != "DEBUG":
        for name in _QUIET_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger."""
    return logging.getLogger(name)
