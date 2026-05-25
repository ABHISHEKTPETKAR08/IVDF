# SCANNER_REVIEW.md — Nmap Scanner Stabilisation (Phase 3)

> **Goal**: Replace the unstable `port_scanner.py` with a hardened, async-safe,
> privilege-aware implementation that does not hang, does not require root for
> the default flow, supports retry, and emits stable normalised results.

---

## 1. Defects Closed (from AUDIT_REPORT.md §6)

| Ref | Defect | Fix |
|---|---|---|
| N1 | `asyncio.get_event_loop()` (deprecated) | Replaced with `asyncio.get_running_loop()` and `asyncio.to_thread()` for the blocking call. |
| N2 | No subprocess timeout — nmap could hang | Each nmap invocation is wrapped in `asyncio.wait_for(..., timeout=nmap_timeout)` (default 180 s). Plus `--host-timeout {nmap_timeout}s` passed to nmap itself, so the subprocess also self-limits. |
| N3 | f-string interpolation of `port_range` into nmap args | Both `target` and `port_range` are now matched against strict regex allowlists (`^[A-Za-z0-9_.\-:\[\]/]+$` and `^[0-9,\-]+$`) and length-capped before any string-formatting. Defence-in-depth even though the validators layer above already filtered them. |
| N4 | `-sS` (SYN scan) needs root → silent failure | `_is_privileged()` detects EUID/Admin at module-import time; `_build_nmap_args` automatically downgrades to `-sT` (TCP connect) when unprivileged. |
| N5 | `-O` OS detection needs root → silent failure | Same privilege gate; OS flag emitted only when privileged. |
| N6 | Multi-host result overwrites `resolved_ip` | Now uses `hosts[0]` as primary canonical identity; OS guess pulled from the primary host only. |
| N7 | Race on `result.open_ports.append` from many tasks | Fallback path now uses an `asyncio.Lock` around all appends. |
| N8 | `asyncio.open_connection` called with raw URL-form `target` | Scanner now validates `target` against an allowlist (`_validate_target`); the orchestrator strips schemes before reaching the scanner. |
| N9 | No retry on transient failures | New `max_retries` parameter (default 2). Each retry sleeps `min(2 * attempt, 10)` seconds. |
| N10 | No NSE vulnerability scripting | New `enable_nse` flag → adds `--script vuln --script-timeout 60s`. Enabled for `full`/`stealth` modes in the orchestrator. |
| N11 | No UDP scan support | New `scan_type="udp"` accepted by `scan()`; degrades gracefully when unprivileged. |
| N12 | Inconsistent result shape between nmap and fallback paths | Both paths now produce a `PortScanResult` with a `to_dict()` returning a stable normalised JSON envelope, including `backend: "nmap" | "fallback"` so the caller knows which path executed. |

---

## 2. New Capabilities

### 2.1 Privilege awareness
On Linux / macOS, `os.geteuid()` is checked. On Windows, `ctypes.windll.shell32.IsUserAnAdmin()` is invoked. The result is captured at module load:

```python
PRIVILEGED = _is_privileged()
```

All argument construction reads this flag — the scanner never crashes due to a privilege denial:

| Logical scan | Privileged | Unprivileged |
|---|---|---|
| `full` | `-sT -sV -O --osscan-guess -T3 -Pn` | `-sT -sV -T3 -Pn` |
| `quick` | `--top-ports 100 -T3 -sV -Pn` | (same) |
| `stealth` | `-p<range> -T2 -sS --max-retries 1 -Pn` | `-p<range> -T2 -sT --max-retries 1 -Pn` |
| `udp` | `-p<range> -sU -T3 --max-retries 1 -Pn` | downgraded to `-p<range> -sT -T3 -sV -Pn` (with warning log) |

### 2.2 NSE vulnerability scripting
When `enable_nse=True`, the scanner appends `--script vuln`. Each port's `info["script"]` map is searched for the marker `VULNERABLE`; matches become `PortScanResult.nse_vulns` entries:

```python
{"port": 8080, "protocol": "tcp", "script": "http-vuln-cve2017-5638", "output": "..."}
```

The orchestrator (`backend/automation/tasks.py`) reads these and synthesises `VulnerabilityFinding` records of type `"NSE Vulnerability"` so they surface in the dashboard alongside HTTP detector findings.

### 2.3 Stable result envelope

```python
{
  "target": "192.168.1.100",
  "resolved_ip": "192.168.1.100",
  "os_guess": "Linux 5.x",
  "open_ports": [{"port": 22, "protocol": "tcp", "state": "open",
                  "service": "ssh", "version": "OpenSSH 8.4",
                  "extra_info": "", "cpe": "cpe:/o:linux:kernel"}],
  "filtered_ports": [80],
  "closed_port_count": 998,
  "scan_type": "full",
  "backend": "nmap",                  // or "fallback"
  "duration_seconds": 12.34,
  "nse_vulns": [],
  "errors": []
}
```

The orchestrator persists this entire object under `scan.raw_results["port_scan"]`, so future debugging / forensic queries can reconstruct exactly what the scanner saw.

### 2.4 Retry + back-off

```python
for attempt in range(1, self.max_retries + 2):
    try:
        await asyncio.wait_for(asyncio.to_thread(self._run_nmap_sync, ...), timeout=...)
        return
    except asyncio.TimeoutError:
        # log, sleep min(2*attempt, 10), continue
```

Two failure classes are caught: `TimeoutError` (nmap subprocess too slow) and generic `Exception` (nmap output parse failure, network blip). Permission errors are not retried (they will keep failing) — instead the scanner records the error and lets the orchestrator continue with HTTP-layer detectors.

### 2.5 Argument allowlist
Both inputs that flow into the nmap argument string are validated **at the scanner layer** (not just upstream):

```python
_PORT_RANGE_RE = re.compile(r"^[0-9,\-]+$")
_TARGET_RE     = re.compile(r"^[A-Za-z0-9_.\-:\[\]/]+$")
```

`port_range` is re-validated inside `_build_nmap_args` (defence in depth). This eliminates any command-injection path even if a future bug in the routes/validators layer allows tainted input through.

---

## 3. Behavioural Contract — what the orchestrator can rely on

| Property | Guarantee |
|---|---|
| `scan()` always returns a `PortScanResult` | Even on total failure (nmap missing, target down). `result.errors` is the diagnostic surface. |
| `scan()` never raises | All exceptions are caught and appended to `result.errors`. |
| `scan()` never blocks the event loop > `nmap_timeout` | Hard `wait_for` guard. |
| Open-port list is deduplicated | Set-backed `_parse_port_range`. |
| Mutation of `result.open_ports` is thread-safe in the fallback path | `asyncio.Lock` guards all writes. |
| Stable `result.backend` field indicates which engine produced the data | `"nmap"` after a successful nmap scan, `"fallback"` otherwise. |

---

## 4. Worked Examples

### 4.1 Unprivileged Linux container, `scan_type="full"`
```
nmap_args: -p 1-1024 -sT -sV -T3 -Pn --host-timeout 180s
backend:   "nmap"
os_guess:  None (no -O without root)
duration:  ~10 s for top 1024 ports on a single host
```

### 4.2 Root on a lab box, `scan_type="full"` + `enable_nse=True`
```
nmap_args: -p 1-1024 -sT -sV -O --osscan-guess -T3 -Pn \
           --script vuln --script-timeout 60s --host-timeout 180s
backend:   "nmap"
os_guess:  "Linux 5.10 - 5.15"
nse_vulns: [...]
duration:  ~60-180 s depending on script matches
```

### 4.3 nmap binary absent
```
backend:   "fallback"
errors:    []                       (no nmap was even attempted)
open_ports: <asyncio TCP-connect results>
duration:  ~timeout × max_concurrent / num_ports
```

### 4.4 nmap binary present but target unreachable
```
backend:   "fallback"               (after nmap returned 0 hosts)
errors:    ["nmap returned no hosts (target unreachable?)"]
open_ports: []
```

---

## 5. Files Modified

| File | Change |
|---|---|
| [backend/scanners/port_scanner.py](backend/scanners/port_scanner.py) | Full rewrite — see fixes table above. |
| [backend/automation/tasks.py](backend/automation/tasks.py) | Added `"udp"` to `_SCAN_TYPE_MAP`; orchestrator opts-in to NSE for full/stealth; reads `port_result.nse_vulns` to synthesise vulnerability findings; persists `port_result.to_dict()` under `scan.raw_results["port_scan"]`. |

---

## 6. Out-of-scope (deferred)

- **Concurrent multi-target scanning** (scan many IPs in a single sweep). Current design is one-target-per-`scan()`; can be lifted to a higher coordinator in Phase 8 (Performance).
- **Service brute-force / credential probing** — never in scope for this project (defensive-only).
- **Pcap capture** — not requested.
- **IPv6 scan** — `_TARGET_RE` accepts `[::1]` syntax but nmap requires `-6`; flag not yet exposed.

---

*Phase 3 / 8 complete — proceeding to Phase 4 (Frontend/Backend integration).*
