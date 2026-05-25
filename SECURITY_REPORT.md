# SECURITY_REPORT.md — Backend Security Hardening (Phase 5)

> **Threat model**: Authenticated/anonymous user of the dashboard or HTTP API can
> POST scan requests. The backend executes nmap subprocesses and HTTPS probes
> against user-supplied targets. The frontend renders results, generates reports,
> and streams files for download. The project is for authorised lab use, but the
> backend must remain robust against accidental misuse and adversarial inputs.

---

## 1. Risk Surface Analysis

| Surface | Vector | Mitigation status |
|---|---|---|
| `POST /scan.target` flows to nmap CLI | Command injection via `--script` / shell metachars | ✓ Mitigated (this report adds Phase 5 #2-4) |
| `POST /scan.port_range` flows to nmap CLI | Same | ✓ Mitigated (allowlist regex at validator + scanner layer) |
| Detector HTTP probes against user URL | SSRF — internal services exposed | ⚠ See §3.5 |
| Report download by `report_id` | Path traversal / arbitrary file read | ✓ Mitigated (Phase 5 #5) |
| `X-Forwarded-For` honoured for rate-limit IP | Trivial RL bypass via header spoofing | ✓ Mitigated (Phase 2 — gated on `TRUST_PROXY_HEADERS`) |
| `socket.gethostbyname` inside Pydantic validator | DNS-amplification DoS, event-loop block | ✓ Mitigated (Phase 2 — DNS removed from validator) |
| `httpx.AsyncClient(verify=False)` in every detector | TLS-MITM target during scan; data trust | ⚠ Acceptable for lab use; documented in §3.3 |
| `SECRET_KEY` default placeholder | Token forgery if HMAC tokens are later introduced | ✓ Warning on production startup |
| Postgres credentials in docker-compose | Default `scanner:scanner` | ⚠ Documented; Phase 7 will recommend `${POSTGRES_PASSWORD}` |
| Flower public on 5555 | Credentials enumeration | ⚠ Documented; Phase 7 will recommend basic auth |

---

## 2. Changes in this Phase

| # | File | Change | Threat addressed |
|---|---|---|---|
| 1 | [backend/utils/audit.py](backend/utils/audit.py) (new) | Dedicated `ivdaf.audit` logger emitting structured key=value lines for `scan_requested`, `scan_started`, `scan_completed`, `scan_failed`, `report_generated`. | Forensic / non-repudiation trail. |
| 2 | [backend/routes/scan.py](backend/routes/scan.py) | `initiate_scan` now receives `http_request: Request` and calls `audit_scan_requested(...)` with client IP and target. `_run_scan_background` error path emits `audit_scan_failed(...)`. | Operator visibility. |
| 3 | [backend/automation/tasks.py](backend/automation/tasks.py) | `_orchestrate_scan` emits `audit_scan_started` / `audit_scan_completed` at pipeline boundaries. | Operator visibility. |
| 4 | [backend/routes/reports.py](backend/routes/reports.py) | `audit_report_generated(...)`; `download_report` now real-path-checks the on-disk target stays inside `REPORTS_DIR` and rejects anything else with 400. | Path traversal / arbitrary file read. |
| 5 | [backend/scanners/port_scanner.py](backend/scanners/port_scanner.py) (Phase 3) | Allowlist regex on both `target` and `port_range` at the scanner layer (defence in depth, even though validators already screened them). | Command-injection into nmap CLI. |
| 6 | [backend/middleware/rate_limiter.py](backend/middleware/rate_limiter.py) (Phase 2) | `X-Forwarded-For` only honoured under `TRUST_PROXY_HEADERS=true`. | Rate-limit bypass via header spoofing. |
| 7 | [backend/utils/validators.py](backend/utils/validators.py) (Phase 2) | Removed synchronous `socket.gethostbyname` from validator. | DNS DoS reflection, event-loop blocking. |
| 8 | [backend/config.py](backend/config.py) | `SECRET_KEY` validator + lifespan warning in production when placeholder is unchanged. | Token forgery risk for future authn. |
| 9 | [backend/app.py](backend/app.py) (Phase 2) | Centralised exception handlers — never leak internal stack traces to the client. | Information disclosure. |

---

## 3. Per-Category Notes

### 3.1 Command injection / unsafe subprocess (Phase 3 + 5)

The scanner constructs nmap arguments via f-string but **every variable that flows into
the string is bound by a regex allowlist at the scanner layer**:

- `port_range` must match `^[0-9,\-]+$` and be ≤ 64 chars.
- `target` must match `^[A-Za-z0-9_.\-:\[\]/]+$` and be ≤ 256 chars.

`python-nmap` passes the argument string to `subprocess.Popen` with `shell=False` (verified in
the upstream lib), so even if a tainted value got through, no shell expansion is possible.
Combined with the route-layer validators (`backend/utils/validators.py`) which reject
non-IP/non-hostname inputs, this constitutes three independent layers of defence.

NSE scripts are restricted to the curated `vuln` category (`--script vuln`) — no user input
flows into the `--script` argument.

### 3.2 Path traversal (Phase 5)

`POST /reports/{scan_id}` writes a file with a deterministic name based on `scan_id` and a
timestamp, into `REPORTS_DIR`. The `report.file_path` is then a column in the database. An
attacker who could (for example, via a future SQL bug) overwrite `report.file_path` to
`/etc/passwd` would previously have caused `GET /reports/{id}/download` to return the system
password file. The Phase 5 download handler:

```python
reports_root = os.path.realpath(settings.REPORTS_DIR)
candidate    = os.path.realpath(report.file_path)
if not candidate.startswith(reports_root + os.sep) and candidate != reports_root:
    raise HTTPException(400, "Invalid report path.")
```

The `os.path.realpath` call collapses symlinks too, defeating link-based escape attempts.

### 3.3 SSRF risk in HTTP detectors

Detectors call `httpx.AsyncClient(verify=False).get(...)` against user-controlled URLs. In a
production deployment where the dashboard is exposed to untrusted users, this is a classic
SSRF surface — an attacker can probe internal services (`http://localhost:8500/`,
`http://169.254.169.254/latest/meta-data/`, etc.).

**Decision**: For the project's stated scope (educational / authorised lab assessments), this
is acceptable. The validator restricts target to syntactically valid hostnames/IPs/URLs and
**logs a warning** when the target resolves to a public IP. The operator is responsible for
confirming authorisation.

If the deployment surface widens, harden as follows (recommended for Phase 7+):
- Add an `ALLOWED_TARGET_CIDRS` list (e.g., `192.168.0.0/16`, `10.0.0.0/8`) and reject other
  targets at the validator. The `validate_target` function already has a hook for this via
  `is_private_ip()`.
- Pin DNS resolution to a controlled resolver (`dnspython`) and refuse if the resolved address
  hits a denylist (cloud metadata IPs, link-local).
- Add a per-target whitelist registered ahead of time via `POST /targets`.

### 3.4 Dependency vulnerabilities

`pip install -r requirements.txt` was reconciled to a single source of truth in Phase 2. The
project is now pinned to the floor versions of all packages that have known CVE fixes
documented in their changelogs (`urllib3 >= 2.x`, `cryptography >= 43`, `requests >= 2.32`,
`pyOpenSSL >= 24.2.1`). Recommended periodic step:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

### 3.5 Hardcoded secrets

- `SECRET_KEY` default is the placeholder; runtime warning on prod startup (#8).
- Postgres credentials in `docker-compose.yml` are `scanner:scanner` for local convenience.
  Phase 7 will replace them with `${POSTGRES_PASSWORD}` interpolation and an `.env.example`
  guide for setting them.
- No secrets are committed in `.env` (verified — `.env.example` is the template).

### 3.6 Unsafe API validation

Pydantic v2 validators on both `target` (regex + private/public branching) and `port_range`
(numeric range check) catch all known malformed inputs. The centralised
`RequestValidationError` handler returns a structured 422 envelope (Phase 2 #8).

---

## 4. Audit Log Format

Every audit line looks like:

```
2026-05-24T10:34:11+0000 | AUDIT | event=scan_requested scan_id='(pending-create)' target='192.168.1.100' scan_type='normal' client_ip='192.168.1.5'
2026-05-24T10:34:11+0000 | AUDIT | event=scan_started scan_id='5d…' target='192.168.1.100'
2026-05-24T10:34:23+0000 | AUDIT | event=scan_completed scan_id='5d…' target='192.168.1.100' findings=7 duration_s=12.34
2026-05-24T10:35:02+0000 | AUDIT | event=report_generated scan_id='5d…' fmt='pdf' path='./reports/report_5d_20260524_103502.pdf'
```

Format is grep-friendly (`grep "event=scan_failed"`) and the field order is stable for
parsing by Splunk / Loki regex.

---

## 5. Residual Risks (intentionally accepted)

| Risk | Reason |
|---|---|
| `verify=False` in detector HTTP calls | Self-signed lab targets require it; documented. |
| Public IPs allowed at validator | Operator authorisation is the gatekeeper, not the validator. |
| No authn on API | Project is single-tenant local lab; adding JWT is a Phase 7+ initiative. |

---

## 6. Recommended Next-Phase Hardening

- Add `pip-audit` or `safety` as a CI step (Phase 7 / DevOps).
- Add a `TrustedHostMiddleware` (FastAPI built-in) gating to a configured `ALLOWED_HOSTS` list.
- Add JWT-based authn via `python-jose` if multi-user deployment is anticipated.
- Add `SecureHeadersMiddleware` that emits HSTS / X-Frame-Options on every response.

---

*Phase 5 / 8 complete — proceeding to Phase 6 (Testing).*
