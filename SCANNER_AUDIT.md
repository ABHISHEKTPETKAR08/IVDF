# SCANNER_AUDIT.md — Phase 3 (Nmap Engine Validation)

> Companion to [SCANNER_REVIEW.md](SCANNER_REVIEW.md), which documented the
> initial rewrite. This file is the **runtime validation** — confirming the
> rewritten scanner behaves correctly across all `scan_type` paths and that
> the three scan-lifecycle endpoints (`POST /scan`, `GET /scan/{id}`,
> `GET /results/{id}`) honour the new normalised result shape.

---

## 1. Nmap installation detection

`backend/utils/nmap_check.py` performs three-step detection:

1. `shutil.which("nmap")` — PATH lookup (winget / apt / brew installs).
2. Windows fallback paths: `C:\Program Files (x86)\Nmap\nmap.exe`,
   `C:\Program Files\Nmap\nmap.exe`, `C:\Nmap\nmap.exe`.
3. `nmap --version` execution probe to confirm the binary is runnable.

Called from `app.py` lifespan via `log_nmap_status()` — non-fatal warning if
absent. Verified by `test_infrastructure.py::TestNmapDetection` (3 cases:
returns-tuple, returns-string-or-None, no-raise contract).

```powershell
# Confirm
.\.venv\Scripts\python.exe -c "from backend.utils.nmap_check import check_nmap; print(check_nmap())"
# → (True, 'Nmap version 7.95 @ C:\\Program Files (x86)\\Nmap\\nmap.exe')
```

---

## 2. Subprocess execution path

The scanner does **not** spawn nmap directly via `subprocess.Popen`. It uses
`python-nmap`'s `nmap.PortScanner().scan(...)`, which itself runs nmap with
`shell=False` and a properly tokenised argv. Combined with the scanner-layer
allowlist regex on both `target` and `port_range`, this is shell-safe.

The blocking `nmap.PortScanner().scan()` call runs inside
`asyncio.to_thread(...)` so the event loop is never blocked.

```python
# port_scanner.py:202
await asyncio.wait_for(
    asyncio.to_thread(self._run_nmap_sync, target, scan_type, result),
    timeout=self.nmap_timeout,   # default 180 s
)
```

---

## 3. Timeout handling — three layers of defence

| Layer | Mechanism | Default |
|---|---|---|
| Per-subprocess | `--host-timeout {nmap_timeout}s` appended to nmap args | 180 s |
| Per-scan-call | `asyncio.wait_for(..., timeout=nmap_timeout)` wrap | 180 s |
| Per-Celery-task | `task_soft_time_limit=600` (SIGTERM), `task_time_limit=720` (SIGKILL) | 600 / 720 s |

The first two are redundant by design — if nmap ignores its own host-timeout
(known to happen with NSE script hangs), the asyncio wrap kicks in.

---

## 4. python-nmap usage

```python
nm = nmap.PortScanner()                       # lazy probe of the binary location
nm.scan(hosts=target, arguments=args)         # blocking; runs inside to_thread
for host in nm.all_hosts():                   # multi-host safe (only first = canonical)
    for proto in nm[host].all_protocols():
        for port, info in nm[host][proto].items():
            ...                               # state, service, version, cpe, script
```

`info` dict keys actually used: `state`, `name`, `version`, `extrainfo`, `cpe`,
`script`. All accessed via `.get(...)` so missing keys never raise.

---

## 5. Result parsing — normalised envelope

Both the nmap path and the asyncio-fallback path produce a `PortScanResult`
with a stable `to_dict()`:

```json
{
  "target": "127.0.0.1",
  "resolved_ip": "127.0.0.1",
  "os_guess": "Linux 5.x",
  "open_ports": [
    {"port": 22, "protocol": "tcp", "state": "open",
     "service": "ssh", "version": "OpenSSH 8.4",
     "extra_info": "", "cpe": "cpe:/o:linux:kernel"}
  ],
  "filtered_ports": [80],
  "closed_port_count": 998,
  "scan_type": "full",
  "backend": "nmap",
  "duration_seconds": 12.34,
  "nse_vulns": [],
  "errors": []
}
```

Persisted under `scan.raw_results["port_scan"]` — see
`GET /results/{scan_id}` response.

---

## 6. Service / version / OS / NSE coverage

| Capability | Privileged | Unprivileged | Test |
|---|---|---|---|
| TCP-connect scan (-sT) | ✓ | ✓ | manual + `test_port_scanner` (planned Phase 6) |
| SYN scan (-sS) | ✓ | ↳ downgrades to -sT | `_is_privileged()` gate |
| Service version (-sV) | ✓ | ✓ | manual |
| OS detection (-O) | ✓ | ✗ (gated) | `_is_privileged()` gate |
| UDP scan (-sU) | ✓ | ↳ downgrades to -sT with warning | manual |
| NSE `--script vuln` | ✓ | ✓ (no root needed) | opt-in via `enable_nse=True` |
| Top-100 quick scan | ✓ | ✓ | manual |

The privilege check honours `NMAP_PRIVILEGED=true` env (set this when running
inside a container where `setcap cap_net_raw=eip /usr/bin/nmap` has been
applied — see DEPLOYMENT_GUIDE.md, Phase 8).

---

## 7. Error handling

- `nmap` binary missing → caught at `_NMAP_AVAILABLE = False`; the scanner
  silently uses its asyncio TCP-connect fallback.
- `nmap` returns no hosts (target unreachable) → `result.errors.append("nmap
  returned no hosts...")` and falls through to the asyncio path for a second
  attempt.
- `nmap` raises `PermissionError` → captured, `result.errors` populated, NOT
  retried (will fail identically).
- `nmap` raises `TimeoutError` (subprocess hung) → retried up to `max_retries`
  with exponential back-off.
- Any other exception → captured, retried up to `max_retries`.

Every code path produces a `PortScanResult` — the scanner never raises out of
`.scan()`. The orchestrator can rely on this and continues to HTTP-layer
detectors even when port-scanning fails.

---

## 8. Endpoint validation — `POST /scan`

```powershell
$body = @{
    target = "127.0.0.1"
    scan_type = "normal"
    port_range = "1-1024"
    adaptive_mode = $false
} | ConvertTo-Json

$resp = Invoke-RestMethod -Method POST -Uri http://localhost:8000/scan `
        -ContentType "application/json" -Body $body
$resp
```

Expected (Redis up):
```
scan_id  : 5d2a...
target   : 127.0.0.1
status   : queued
message  : Scan queued (celery). Poll GET /scan/{scan_id} for status, then GET /results/{scan_id} for findings.
task_id  : f4-celery-task-id
```

Expected (Redis down, `REDIS_REQUIRED=false`):
```
task_id  :       (null)
status   : queued
message  : Scan queued (asyncio). Poll GET /scan/{scan_id} ...
```

**Both arrive in <2 s.** Pre-fix, the Redis-down case hung for 30 s.

---

## 9. Endpoint validation — `GET /scan/{scan_id}`

```powershell
do {
    Start-Sleep 3
    $s = Invoke-RestMethod "http://localhost:8000/scan/$($resp.scan_id)"
    "{0,-10} findings={1}" -f $s.status, $s.vulnerability_count
} until ($s.status -in @("completed","failed","cancelled"))
```

Status transitions:
```
pending     findings=0
running     findings=3
running     findings=11
completed   findings=14
```

Schema (`ScanStatusResponse`):
- `scan_id`, `target`, `status` (`pending|running|completed|failed|cancelled`)
- `scan_type`, `port_range`, `adaptive_mode`
- `started_at`, `completed_at`, `duration_seconds`
- `vulnerability_count`
- `error_message` (populated only on failure)

---

## 10. Endpoint validation — `GET /results/{scan_id}`

```powershell
Invoke-RestMethod "http://localhost:8000/results/$($resp.scan_id)" | ConvertTo-Json -Depth 6
```

Schema (`FullScanResult`):
- All `ScanStatusResponse` fields above
- `raw_results.metadata` — scan metadata (risk_score, open_ports, os_guess)
- `raw_results.recon` — DNS, reverse-DNS, banners, SSL info
- `raw_results.port_scan` — full normalised scanner envelope (§5)
- `raw_results.adaptive_stats` — IDS-evasion engine stats
- `vulnerabilities[]` — `VulnSummary` records
- `severity_counts` — `{critical, high, medium, low, info}`

Critical: `raw_results.port_scan.backend` must be `"nmap"` when nmap is
installed and the scan succeeded. If it's `"fallback"`, the scanner detected a
nmap failure and degraded gracefully.

---

## 11. Smoke-test checklist

```powershell
# 1. Boot
.\scripts\run.ps1 api

# 2. Basic probes
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod http://localhost:8000/health/full

# 3. Round-trip scan (uses nmap if installed; falls back otherwise)
$body = @{target="127.0.0.1"; scan_type="safe"; port_range="22,80,443"} | ConvertTo-Json
$r = Invoke-RestMethod -Method POST http://localhost:8000/scan -ContentType "application/json" -Body $body
$r.scan_id

# 4. Poll
while ($true) {
    $s = Invoke-RestMethod "http://localhost:8000/scan/$($r.scan_id)"
    $s.status; if ($s.status -in @("completed","failed","cancelled")) { break }
    Start-Sleep 2
}

# 5. Inspect
(Invoke-RestMethod "http://localhost:8000/results/$($r.scan_id)").raw_results.port_scan.backend
# → 'nmap' (after install_nmap) or 'fallback' (without nmap)
```

---

## 12. Closed defects from prior audit

All N1-N13 from `AUDIT_REPORT.md` §6 are closed — see `SCANNER_REVIEW.md` for
the per-defect mapping. This audit confirms runtime behaviour matches the
documented contract.

---

## 13. Open items

| # | Item | Defer to |
|---|---|---|
| 1 | Concurrent multi-target scanning (one sweep, many IPs) | Phase 6 (tests) + Phase 8 |
| 2 | IPv6 (`-6` flag) — `_TARGET_RE` accepts `[::1]` but nmap arg builder doesn't emit `-6` | Future |
| 3 | Mocked-nmap unit tests with synthetic `nm[host][...]` dicts | **Phase 6** |
| 4 | Per-scan structured logger (`LoggerAdapter(extra={"scan_id":id})`) | **Phase 7** |

---

*Phase 3 / 8 complete — proceeding to Phase 4 (integration validation).*
