"""
FastAPI Application Entry-Point.

Registers all routers, middleware, startup/shutdown hooks, and provides
health-check and API documentation endpoints.
"""
import os
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from backend.config import settings
from backend.database.db import init_db
from backend.middleware.rate_limiter import RateLimitMiddleware
#from backend.routes import scan, results, targets, vulnerabilities
from backend.routes import scan, results, reports, targets, vulnerabilities
from backend.utils import metrics
from backend.utils.logger import get_logger, set_request_id, setup_logging

# ── Initialise logging before anything else ───────────────────────────────────
setup_logging(settings.LOG_LEVEL, settings.LOG_FILE, json_logs=settings.LOG_JSON)
logger = get_logger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    logger.info("  Database : %s", settings.DATABASE_URL.split("///")[-1])
    logger.info("  Redis    : %s", settings.REDIS_URL)
    logger.info("  Debug    : %s", settings.DEBUG)
    logger.info("=" * 60)

    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs(settings.LOGS_DIR, exist_ok=True)

    await init_db()
    logger.info("Database initialised.")

    # Non-fatal startup checks
    from backend.utils.nmap_check import log_nmap_status
    log_nmap_status()

    # Production secret-key guard — warns (does not crash) when the default
    # placeholder is still in use with DEBUG=false.
    if not settings.DEBUG and "CHANGE-ME" in settings.SECRET_KEY:
        logger.error(
            "SECURITY WARNING: SECRET_KEY is the default placeholder. "
            "Set SECRET_KEY in your .env / environment to a long random string."
        )

    # ── Continuous-monitoring scheduler ──────────────────────────────────────
    # Periodically re-scans every Target whose auto_rescan flag is True so
    # newly-introduced vulnerabilities are surfaced without manual action.
    from backend.automation.rescan_scheduler import get_scheduler
    scheduler = get_scheduler()
    await scheduler.start()

    yield

    logger.info("Shutting down %s.", settings.APP_NAME)
    await scheduler.stop()


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "**Intelligent Vulnerability Detection and Analysis Framework**\n\n"
            "A production-grade Python cybersecurity assessment platform.\n\n"
            "> **Educational / Lab use only.** Only scan targets you own or have "
            "explicit written authorisation to test."
        ),
        contact={"name": "Security Team", "email": "security@lab.local"},
        license_info={"name": "MIT"},
        lifespan=lifespan,
    )

    # ── Request ID + timing middleware ────────────────────────────────────────
    # Body buffering is gated on DEBUG to avoid memory churn for large POSTs
    # (e.g. future PDF / file uploads). The previous version buffered every
    # POST unconditionally, which is wasteful in production.
    @app.middleware("http")
    async def _request_middleware(request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        set_request_id(rid)
        t0 = time.perf_counter()

        if settings.DEBUG and request.method == "POST":
            body = await request.body()
            # Replay the body so the downstream handler can still read it.
            async def _receive():
                return {"type": "http.request", "body": body, "more_body": False}

            request = Request(request.scope, _receive)
            logger.debug(
                "REQ  %s %s ct=%s body=%s",
                request.method,
                request.url.path,
                request.headers.get("content-type", ""),
                body[:500].decode("utf-8", errors="replace"),
            )

        try:
            response = await call_next(request)
        except Exception:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.exception(
                "Unhandled exception in %s %s after %.0f ms",
                request.method, request.url.path, elapsed_ms,
            )
            # Centralised error envelope so the frontend always sees JSON.
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_server_error",
                    "detail": "An unexpected error occurred. See server logs.",
                    "request_id": rid,
                },
                headers={"X-Request-ID": rid},
            )
        elapsed_ms = (time.perf_counter() - t0) * 1000

        response.headers["X-Request-ID"] = rid
        response.headers["X-Response-Time"] = f"{elapsed_ms:.1f}ms"

        # Prometheus metrics — keyed on the *route template* (request.url.path
        # is the realised path; for /scan/{id} we collapse to /scan/{id} to
        # bound cardinality).
        try:
            path_label = request.scope.get("route").path if request.scope.get("route") else request.url.path  # type: ignore[union-attr]
        except Exception:
            path_label = request.url.path
        metrics.HTTP_REQUESTS.labels(
            method=request.method, path=path_label, status=str(response.status_code),
        ).inc()
        metrics.HTTP_LATENCY.labels(
            method=request.method, path=path_label,
        ).observe(elapsed_ms / 1000.0)

        level = logger.warning if response.status_code >= 400 else logger.debug
        level(
            "RESP %s %s → %d (%.0f ms)",
            request.method, request.url.path, response.status_code, elapsed_ms,
        )
        return response

    # ── CORS ──────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Response-Time"],
    )

    # ── Rate limiting ─────────────────────────────────────────────────────────
    app.add_middleware(RateLimitMiddleware)

    # ── Centralised exception handlers ────────────────────────────────────────
    # Pydantic validation → 422 with structured detail
    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        logger.warning(
            "422 validation error on %s %s: %s",
            request.method, request.url.path, exc.errors(),
        )
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "detail": exc.errors(),
                "request_id": request.headers.get("X-Request-ID"),
            },
        )

    # HTTPException → consistent JSON envelope
    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "detail": exc.detail,
                "status_code": exc.status_code,
            },
            headers=getattr(exc, "headers", None) or {},
        )

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(scan.router)
    app.include_router(results.router)
    app.include_router(reports.router)
    app.include_router(targets.router)
    app.include_router(vulnerabilities.router)

    # ── Root ──────────────────────────────────────────────────────────────────
    @app.get("/", tags=["Root"], include_in_schema=False)
    async def root():
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "docs": "/docs",
            "health": "/health",
            "health_full": "/health/full",
        }

    # ── Fast liveness probe ───────────────────────────────────────────────────
    @app.get("/health", tags=["Health"], summary="Liveness probe")
    async def health():
        """
        Instant liveness check — always responds in < 1 ms.
        Used by load balancers, Streamlit dashboard, and Docker HEALTHCHECK.
        """
        return {"status": "ok", "version": settings.APP_VERSION}

    # ── Prometheus metrics ────────────────────────────────────────────────────
    @app.get("/metrics", tags=["Observability"], include_in_schema=False)
    async def prometheus_metrics():
        """Prometheus scrape endpoint. Excluded from OpenAPI schema."""
        return Response(
            content=metrics.render(),
            media_type=metrics.CONTENT_TYPE_LATEST,
        )

    # ── Deep readiness probe ──────────────────────────────────────────────────
    @app.get("/health/full", tags=["Health"], summary="Full readiness check")
    async def health_full():
        """
        Deep diagnostics: checks DB, Redis, and Celery worker availability.
        Each subsystem check is timeout-protected and non-blocking.
        Suitable for monitoring dashboards and CI readiness gates.
        """
        import asyncio
        timeout = settings.HEALTHCHECK_TIMEOUT
        checks: dict = {"api": "healthy", "version": settings.APP_VERSION}

        # ── Database ──────────────────────────────────────────────────────────
        try:
            from sqlalchemy import text as _text
            from backend.database.db import get_db_session
            async with get_db_session() as session:
                await asyncio.wait_for(session.execute(_text("SELECT 1")), timeout=timeout)
            checks["database"] = "connected"
        except asyncio.TimeoutError:
            checks["database"] = "timeout"
        except Exception as exc:
            checks["database"] = f"error:{type(exc).__name__}"

        # ── Redis ─────────────────────────────────────────────────────────────
        try:
            import redis.asyncio as _aioredis
            _r = _aioredis.from_url(
                settings.REDIS_URL,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
            await asyncio.wait_for(_r.ping(), timeout=timeout)
            await _r.aclose()
            checks["redis"] = "connected"
        except asyncio.TimeoutError:
            checks["redis"] = "timeout"
        except Exception:
            checks["redis"] = "unavailable"

        # ── Celery — inspected in a thread to avoid blocking the event loop ───
        def _inspect_celery() -> str:
            try:
                from backend.automation.celery_app import celery_app as _app
                result = _app.control.inspect(timeout=1.5).ping()
                return "running" if result else "no workers"
            except Exception:
                return "unavailable"

        try:
            checks["celery"] = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, _inspect_celery),
                timeout=timeout + 1,
            )
        except asyncio.TimeoutError:
            checks["celery"] = "timeout"

        # ── Overall status ────────────────────────────────────────────────────
        core_ok = all(
            checks.get(k) in ("healthy", "connected")
            for k in ("api", "database")
        )
        redis_ok  = checks.get("redis")  == "connected"
        celery_ok = checks.get("celery") == "running"

        if not core_ok:
            checks["status"] = "unhealthy"
        elif settings.REDIS_REQUIRED and not (redis_ok and celery_ok):
            # Production-mode contract: Redis + Celery are mandatory.
            checks["status"] = "unhealthy"
        elif redis_ok and celery_ok:
            checks["status"] = "healthy"
        else:
            # Single-host lab mode (REDIS_REQUIRED=False) — asyncio fallback is OK.
            checks["status"] = "degraded"

        # Optional: return HTTP 503 so load-balancers / Kubernetes readiness
        # probes mark the pod as not-ready when Redis/DB are unreachable.
        if (
            settings.REDIS_REQUIRED_RETURNS_503
            and checks["status"] == "unhealthy"
        ):
            return JSONResponse(status_code=503, content=checks)

        return checks

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
