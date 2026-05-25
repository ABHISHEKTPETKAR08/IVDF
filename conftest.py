"""
Root conftest.py.

Three responsibilities:

1. Sys.path bootstrap — pytest inserts the directory containing this file
   into sys.path automatically (rootdir detection), so both `backend` and
   `frontend` packages are importable in all tests without any extra setup.
   pyproject.toml also declares `[tool.pytest.ini_options] pythonpath = ["."]`
   as a belt-and-suspenders guarantee for pytest >= 7.

2. Force in-memory SQLite for the test session BEFORE backend.app or
   backend.database.db is imported. Without this, tests would silently
   run against the developer's local vuln_scanner.db file.

3. Disable Celery eager mode and ensure DEBUG is off so the body-buffering
   middleware path is not exercised under test.
"""
import os

# ── Hard-set environment BEFORE pytest collects / imports backend.* ──────────
# pytest reads conftest.py before any test module, so settings.* below picks
# these values up at first import.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "False")
os.environ.setdefault("DEBUG", "False")
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("RATE_LIMIT_REQUESTS", "10000")  # never trip in tests
