# IVDAF Backend Dockerfile - production-grade, multi-stage.
# nmap runs unprivileged thanks to setcap; image runs as the `scanner` user.

FROM python:3.11-slim AS base

# OS dependencies: nmap binary + NSE scripts, libpcap (raw sockets),
# libcap2-bin (provides `setcap`), build chain for any wheels needing it,
# curl for the container healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libpcap-dev \
        libcap2-bin \
        gcc \
        libssl-dev \
        libffi-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # Grant nmap CAP_NET_RAW etc so unprivileged users can run SYN / OS / UDP
    # scans. The Python PortScanner reads NMAP_PRIVILEGED below and emits
    # the matching nmap flags.
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /app

# ── Dependency layer (cached unless requirements.txt changes) ────────────────
FROM base AS deps

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Application layer ────────────────────────────────────────────────────────
FROM deps AS app

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY pyproject.toml ./
COPY README.md ./
RUN pip install --no-cache-dir -e .

RUN mkdir -p /app/reports /app/logs \
    && groupadd -r scanner && useradd -r -g scanner scanner \
    && chown -R scanner:scanner /app

USER scanner

# Tells PortScanner that nmap has CAP_NET_RAW even though the python process
# is non-root - so it emits -sS / -O / -sU instead of degrading to -sT.
ENV NMAP_PRIVILEGED=true

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# --proxy-headers + --forwarded-allow-ips '*' lets the backend read
# X-Forwarded-* when behind a reverse proxy. Combined with TRUST_PROXY_HEADERS=true
# (env) this gives accurate client IPs to the rate limiter + audit log.
CMD ["uvicorn", "backend.app:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
