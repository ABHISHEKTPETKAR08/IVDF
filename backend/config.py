"""
Configuration management — Intelligent Vulnerability Detection Framework.

All values can be overridden via environment variables or a .env file.
Pydantic-settings handles type coercion and validation automatically.
"""
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application-wide configuration loaded from environment / .env."""

    # ── Application ───────────────────────────────────────────────────────────
    APP_NAME: str = "Intelligent Vulnerability Detection and Analysis Framework"
    APP_VERSION: str = "1.0.0"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    DEBUG: bool = False

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./vuln_scanner.db",
        description="Async-compatible SQLAlchemy URL. Use sqlite+aiosqlite for dev, "
                    "postgresql+asyncpg for production.",
    )

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Full Redis URL including DB index.",
    )
    REDIS_MAX_CONNECTIONS: int = Field(
        default=20,
        description="Maximum connections in the async Redis connection pool.",
    )

    # ── Celery ────────────────────────────────────────────────────────────────
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Celery broker transport URL.",
    )
    CELERY_RESULT_BACKEND: str = Field(
        default="redis://localhost:6379/1",
        description="Celery result backend URL (separate DB index from broker).",
    )
    CELERY_TASK_ALWAYS_EAGER: bool = Field(
        default=False,
        description="Run tasks synchronously inline. Set True only for testing.",
    )
    WORKER_CONCURRENCY: int = Field(
        default=4,
        description="Number of Celery worker processes / greenlets.",
    )
    CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP: bool = Field(
        default=True,
        description="Retry broker connection on worker startup instead of failing.",
    )

    # ── Health checks ─────────────────────────────────────────────────────────
    HEALTHCHECK_TIMEOUT: float = Field(
        default=3.0,
        description="Per-subsystem timeout (seconds) for /health/full checks.",
    )

    # When True, /health/full reports 'unhealthy' (and returns HTTP 503 if
    # REDIS_REQUIRED_RETURNS_503 is also True) when Redis or Celery is
    # unreachable. Set False for single-host lab use where the asyncio fallback
    # is acceptable.
    REDIS_REQUIRED: bool = Field(
        default=False,
        description="Treat Redis/Celery as mandatory in /health/full status.",
    )
    REDIS_REQUIRED_RETURNS_503: bool = Field(
        default=False,
        description="When True, /health/full returns HTTP 503 (not 200) when "
                    "subsystems are unhealthy. Useful for load-balancer probes.",
    )

    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(
        default="CHANGE-ME-use-a-long-random-string-in-production",
        description="HMAC secret for internal tokens. MUST be changed in production.",
    )
    API_KEY_HEADER: str = "X-API-Key"

    # ── Rate limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_REQUESTS: int = 100   # max requests per window
    RATE_LIMIT_PERIOD: int = 60      # window duration in seconds

    # ── Scanning ──────────────────────────────────────────────────────────────
    SCAN_TIMEOUT: int = 30           # seconds per individual probe
    MAX_CONCURRENT_SCANS: int = 5
    DEFAULT_PORT_RANGE: str = "1-1024"
    ADAPTIVE_SCAN_DELAY_MIN: float = 0.5
    ADAPTIVE_SCAN_DELAY_MAX: float = 3.0
    MAX_RETRIES: int = 3

    # ── Continuous monitoring (auto-rescan) ───────────────────────────────────
    # When enabled, the backend periodically re-runs the scan pipeline on
    # every Target whose `auto_rescan` flag is True. Combined with the nmap
    # service-version detection, this turns IVDAF into a passive monitor that
    # surfaces newly-discovered vulnerabilities without manual intervention.
    RESCAN_ENABLED: bool = Field(
        default=True,
        description="Periodically re-scan known targets to detect drift.",
    )
    RESCAN_INTERVAL_MINUTES: int = Field(
        default=360,
        description="Minutes between rescans of the same target (default 6 h).",
    )
    RESCAN_TICK_SECONDS: int = Field(
        default=300,
        description="How often the scheduler checks for due targets (default 5 min).",
    )
    RESCAN_DEFAULT_PORT_RANGE: str = Field(
        default="1-1024",
        description="Port range used by auto-rescans (per-target override TBD).",
    )
    RESCAN_DEFAULT_SCAN_TYPE: str = Field(
        default="normal",
        description="Scan type used by auto-rescans (normal|safe|stealth|udp).",
    )

    # ── Storage / Logging ─────────────────────────────────────────────────────
    REPORTS_DIR: str = "./reports"
    LOGS_DIR: str = "./logs"
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/vuln_scanner.log"
    LOG_JSON: bool = Field(
        default=False,
        description="Emit logs as JSON (useful for log aggregators like Loki/ELK).",
    )

    # ── Allowed target prefixes (educational / lab use) ───────────────────────
    ALLOWED_TARGET_PREFIXES: List[str] = [
        "192.168.", "10.", "172.16.", "127.", "localhost",
        "dvwa", "juiceshop", "metasploitable",
    ]

    # ── CORS ──────────────────────────────────────────────────────────────────
    # Comma-separated list of allowed origins. Overridable via env:
    #   CORS_ORIGINS=http://localhost:8501,http://frontend:8501,http://localhost:3000
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:8501",
            "http://127.0.0.1:8501",
            "http://localhost:3000",
            "http://frontend:8501",   # Docker compose service name
        ],
        description="Allowed CORS origins for the frontend dashboard.",
    )

    # ── Reverse proxy trust ───────────────────────────────────────────────────
    # When False, X-Forwarded-For is ignored (default safe behaviour).
    TRUST_PROXY_HEADERS: bool = Field(
        default=False,
        description="Set True only when behind a trusted reverse proxy.",
    )

    @field_validator("LOG_LEVEL")
    @classmethod
    def _upper_log_level(cls, v: str) -> str:
        return v.upper()

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors(cls, v):
        # Allow comma-separated env-var input: "http://a:8501,http://b:8501"
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @field_validator("REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND")
    @classmethod
    def _validate_redis_url(cls, v: str) -> str:
        if not v.startswith(("redis://", "rediss://", "unix://")):
            raise ValueError(f"Invalid Redis URL: {v!r}")
        return v

    @field_validator("SECRET_KEY")
    @classmethod
    def _validate_secret_key(cls, v: str) -> str:
        # In production (DEBUG=false), refuse the placeholder default.
        # We do NOT raise — that would block dev startup — but we log loud
        # at first use via __init__ side-effect in the app lifespan.
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()
