# ── IVDAF — convenience targets ───────────────────────────────────────────────
# Run from the vulnerability-scanner/ directory.

PYTHON   := python3
VENV     := .venv
PIP      := $(VENV)/bin/pip
PYTEST   := $(VENV)/bin/pytest
UVICORN  := $(VENV)/bin/uvicorn
STREAMLIT := $(VENV)/bin/streamlit
CELERY   := $(VENV)/bin/celery

.PHONY: install install-dev api frontend worker beat test lint docker-up docker-down clean

## ── Setup ────────────────────────────────────────────────────────────────────

install:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt
	$(PIP) install streamlit plotly pandas
	# Editable install — adds project root to sys.path permanently.
	# After this, `streamlit run frontend/dashboard.py` works without PYTHONPATH.
	$(PIP) install -e .

install-dev: install
	$(PIP) install pytest pytest-asyncio pytest-cov httpx ruff

## ── Run services ─────────────────────────────────────────────────────────────

api:
	$(UVICORN) backend.app:app --host 0.0.0.0 --port 8000 --reload

frontend:
	# PYTHONPATH=. ensures project root is on the path.
	# If you ran `make install`, this is redundant but harmless.
	PYTHONPATH=. $(STREAMLIT) run frontend/dashboard.py \
		--server.port 8501 --server.address 0.0.0.0

worker:
	$(CELERY) -A backend.automation.celery_app worker --loglevel=info --concurrency=4

beat:
	$(CELERY) -A backend.automation.celery_app beat --loglevel=info

## ── Testing ──────────────────────────────────────────────────────────────────

test:
	$(PYTEST) tests/ -v --asyncio-mode=auto

test-cov:
	$(PYTEST) tests/ -v --asyncio-mode=auto --cov=backend --cov-report=term-missing

## ── Docker ───────────────────────────────────────────────────────────────────

docker-up:
	docker-compose up --build

docker-down:
	docker-compose down -v

## ── Clean ────────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .coverage
