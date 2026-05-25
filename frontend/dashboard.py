"""
IVDAF Streamlit Dashboard — Intelligent Vulnerability Detection and Analysis Framework.

Run from the vulnerability-scanner/ project root:
  Windows PS  :  $env:PYTHONPATH="."; streamlit run frontend/dashboard.py
  Linux/macOS :  PYTHONPATH=. streamlit run frontend/dashboard.py
  After install: pip install -e . && streamlit run frontend/dashboard.py
"""
import sys
import os as _os

# ── Path bootstrap (no-op when editable-installed or PYTHONPATH set) ──────────
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
# ─────────────────────────────────────────────────────────────────────────────

import time
from typing import Optional

import pandas as pd
import requests
import streamlit as st

from frontend.charts import (
    cvss_histogram,
    scan_history_timeline,
    severity_bar,
    severity_donut,
    vuln_type_bar,
)
from frontend.ui_components import (
    alert_banner,
    inject_styles,
    kpi_row,
    landing_hero,
    page_header,
    render_horizontal_nav,
    scan_radar,
    severity_badge,
    severity_summary_cards,
    terminal_box,
    vulnerability_card,
)

# ── Page config — must be first Streamlit call ────────────────────────────────
st.set_page_config(
    page_title="IVDAF — Vulnerability Framework",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Inject global cyberpunk CSS + matrix rain JS ──────────────────────────────
inject_styles()

# ── Session defaults ──────────────────────────────────────────────────────────
# Honour the API_BASE_URL env var so the dashboard works both standalone
# (defaults to localhost) and inside docker-compose (where it must reach the
# backend container by service name, e.g. http://backend:8000).
_DEFAULT_API_BASE = _os.environ.get("API_BASE_URL", "http://localhost:8000").rstrip("/")
if "api_base" not in st.session_state:
    st.session_state["api_base"] = _DEFAULT_API_BASE


# ── Health probe ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=10)
def _check_api(base: str) -> bool:
    """Liveness check — True if the API responds at all."""
    try:
        return requests.get(f"{base}/health", timeout=4).status_code == 200
    except Exception:
        return False


@st.cache_data(ttl=30)
def _check_api_full(base: str) -> dict:
    """
    Full readiness check. Returns the /health/full JSON dict.
    Falls back to {"status": "unknown"} if unreachable.
    """
    try:
        r = requests.get(f"{base}/health/full", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {"status": "unknown"}


api_online = _check_api(st.session_state["api_base"])
api_status = _check_api_full(st.session_state["api_base"]) if api_online else {}
api_degraded = api_online and api_status.get("status") == "degraded"

# ── Top horizontal navigation (sidebar-independent) ───────────────────────────
PAGE = render_horizontal_nav(api_online)

# Show a non-fatal degraded warning in the sidebar
if api_degraded:
    redis_ok  = api_status.get("redis")  == "connected"
    celery_ok = api_status.get("celery") == "running"
    with st.sidebar:
        st.warning(
            "**Infrastructure degraded**\n\n"
            + ("" if redis_ok  else "- Redis unavailable — Celery disabled\n")
            + ("" if celery_ok else "- No Celery workers — asyncio fallback active\n")
            + "\nScans still work via asyncio background tasks."
        )

# API URL override — still available in the sidebar for power users.
with st.sidebar:
    st.markdown(
        "<div style='font-family:Share Tech Mono,monospace;font-size:12px;"
        "color:var(--c-cyan);letter-spacing:2px;padding:6px 0 12px 0'>"
        "⚙ SETTINGS</div>",
        unsafe_allow_html=True,
    )
    with st.expander("API URL override"):
        new_url = st.text_input("API URL", value=st.session_state["api_base"], label_visibility="visible")
        if new_url != st.session_state["api_base"]:
            st.session_state["api_base"] = new_url
            st.cache_data.clear()
            st.rerun()

API_BASE = st.session_state["api_base"]


# ── API helpers ───────────────────────────────────────────────────────────────

def api_get(path: str, timeout: float = 10.0) -> Optional[dict | list]:
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=timeout)
        if r.status_code >= 400:
            _render_api_error(r, "GET", path)
            return None
        return r.json()
    except requests.Timeout:
        st.error(f"API timeout — GET {path} took > {timeout}s. Is the backend healthy?")
        return None
    except requests.ConnectionError:
        st.error(f"API unreachable — backend at `{API_BASE}` is down or blocked.")
        return None
    except requests.RequestException as exc:
        st.error(f"API error — {exc}")
        return None


def api_post(path: str, payload: dict, timeout: float = 30.0) -> Optional[dict]:
    try:
        r = requests.post(
            f"{API_BASE}{path}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        if r.status_code >= 400:
            _render_api_error(r, "POST", path, payload=payload)
            return None
        return r.json()
    except requests.Timeout:
        st.error(f"API timeout — POST {path} took > {timeout}s.")
        return None
    except requests.ConnectionError:
        st.error(f"API unreachable — backend at `{API_BASE}` is down or blocked.")
        return None
    except requests.RequestException as exc:
        st.error(f"API error — {exc}")
        return None


def _render_api_error(
    response: "requests.Response", method: str, path: str,
    payload: Optional[dict] = None,
) -> None:
    """Render a structured error from the centralised backend error envelope."""
    try:
        body = response.json()
    except Exception:
        body = {"detail": response.text}

    code = response.status_code
    detail = body.get("detail", body)
    if code == 422:
        st.error(f"**Validation error (422)** — {detail}")
    elif code == 429:
        retry = response.headers.get("Retry-After", "?")
        st.warning(f"**Rate limited (429)** — retry after {retry}s.")
    elif code == 404:
        st.warning(f"**Not found (404)** — {detail}")
    elif code >= 500:
        st.error(
            f"**Backend error ({code})** — {detail}\n\n"
            f"Request ID: `{body.get('request_id', 'n/a')}`"
        )
    else:
        st.error(f"**{method} {path} → {code}** — {detail}")

    if payload is not None:
        with st.expander("Debug: raw request payload"):
            st.json(payload)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: Dashboard
# ═══════════════════════════════════════════════════════════════════════════════

def page_dashboard() -> None:
    landing_hero(api_online)

    if not api_online:
        terminal_box(
            [
                "ERROR: Cannot reach backend API.",
                f"Expected: {API_BASE}/health",
                "Action: start backend → .\\scripts\\run.ps1 api",
                "",
                "Verify with: Invoke-RestMethod http://localhost:8000/health",
            ],
            title="SYSTEM DIAGNOSTICS",
        )
        return

    if api_degraded:
        lines = ["WARNING: Infrastructure running in degraded mode."]
        if api_status.get("redis") != "connected":
            lines.append("  redis   : unavailable — start with: docker run -d --name vuln-redis -p 6379:6379 redis:7-alpine")
        if api_status.get("celery") != "running":
            lines.append("  celery  : no workers — start with: .\\scripts\\run.ps1 worker")
        lines.append("")
        lines.append("Scans will run via asyncio fallback. All features functional.")
        terminal_box(lines, title="DEGRADED MODE")

    scans = api_get("/results?per_page=50") or []

    # ── KPI row ───────────────────────────────────────────────────────────────
    total    = len(scans)
    done     = sum(1 for s in scans if s.get("status") == "completed")
    findings = sum(s.get("vulnerability_count", 0) for s in scans)
    critical = sum(s.get("critical", 0) for s in scans)

    kpi_row([
        {"label": "Total Scans",    "value": str(total),    "color": "c-cyan"},
        {"label": "Completed",      "value": str(done),     "color": "c-low"},
        {"label": "Total Findings", "value": str(findings), "color": "c-high"},
        {"label": "Critical",       "value": str(critical), "color": "c-crit"},
    ])

    if not scans:
        alert_banner("No scan data yet — start a scan from the NEW SCAN page.", "info")
        return

    # ── Aggregate severity ────────────────────────────────────────────────────
    agg = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for s in scans:
        for k in agg:
            agg[k] += s.get(k.lower(), 0)

    # ── Charts ────────────────────────────────────────────────────────────────
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown('<div class="pg-title" style="font-size:14px">SEVERITY DISTRIBUTION</div>', unsafe_allow_html=True)
        st.plotly_chart(severity_donut(agg), use_container_width=True)
    with col_b:
        st.markdown('<div class="pg-title" style="font-size:14px">FINDINGS BY SEVERITY</div>', unsafe_allow_html=True)
        st.plotly_chart(severity_bar(agg), use_container_width=True)

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="pg-title" style="font-size:14px">SCAN HISTORY TIMELINE</div>', unsafe_allow_html=True)
    st.plotly_chart(scan_history_timeline(scans), use_container_width=True)

    # ── Recent scans table ────────────────────────────────────────────────────
    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="pg-title" style="font-size:14px">RECENT SCANS</div>', unsafe_allow_html=True)
    df = pd.DataFrame([
        {
            "ID":        s["scan_id"][:8] + "…",
            "Target":    s.get("target", ""),
            "Type":      s.get("scan_type", ""),
            "Status":    s.get("status", "").upper(),
            "Completed": (s.get("completed_at") or "—")[:19],
            "Findings":  s.get("vulnerability_count", 0),
            "Critical":  s.get("critical", 0),
            "High":      s.get("high", 0),
        }
        for s in scans[:10]
    ])
    st.dataframe(df, use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: New Scan
# ═══════════════════════════════════════════════════════════════════════════════

def page_new_scan() -> None:
    page_header("NEW SCAN", "Configure and launch a vulnerability assessment")

    terminal_box(
        [
            "Accepted targets: any valid IP address, hostname, or URL.",
            "Examples:  192.168.1.100  ·  https://target.local  ·  10.0.0.5",
            "Evasion:  adaptive mode rotates UA headers + Poisson timing to reduce IDS alerts.",
            "WARNING: Only scan systems you own or have explicit written permission to test.",
        ],
        title="SCAN POLICY",
    )

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)

    with st.form("scan_form"):
        col1, col2 = st.columns(2)

        with col1:
            target = st.text_input(
                "Target  (IP / Hostname / URL)",
                placeholder="192.168.1.100  or  http://dvwa.local",
            )
            scan_type = st.selectbox(
                "Scan Type",
                ["normal", "safe", "stealth"],
                help=(
                    "normal — full port + HTTP detection  |  "
                    "safe — HTTP-only, no port scan  |  "
                    "stealth — slow adaptive with IDS evasion"
                ),
            )
            adaptive  = st.checkbox(
                "Enable Adaptive (Low-Noise) Mode",
                help="Randomises timing and reduces packet rate to evade IDS/IPS.",
            )

        with col2:
            port_range  = st.text_input("Port Range", value="1-1024")
            description = st.text_input("Description (optional)")
            st.info(
                "**Authorisation required**\n"
                "Only scan targets you own or have written permission to test.\n"
                "Enable **Adaptive Mode** to activate IDS/IPS/WAF evasion."
            )

        launched = st.form_submit_button("◈  LAUNCH SCAN", use_container_width=True)

    if not launched:
        return

    if not target:
        alert_banner("Target is required.", "error")
        return

    if not api_online:
        alert_banner(
            "Backend API is offline. Start it with:  .\\scripts\\run.ps1 api",
            "error",
        )
        return

    if api_degraded:
        alert_banner(
            "Infrastructure degraded (Redis/Celery unavailable). "
            "Scan will run via asyncio fallback — results will still be saved.",
            "warning",
        )

    with st.spinner("Queuing scan…"):
        resp = api_post("/scan", {
            "target":        target,
            "scan_type":     scan_type,
            "port_range":    port_range,
            "adaptive_mode": adaptive,
            "description":   description or None,
        })

    if not resp:
        return

    scan_id  = resp.get("scan_id", "")
    exec_path = "asyncio" if not resp.get("task_id") else "celery"

    st.success(f"Scan queued via **{exec_path}** — ID: `{scan_id}`")
    terminal_box(
        [
            f"scan_id   : {scan_id}",
            f"target    : {target}",
            f"scan_type : {scan_type}",
            f"execution : {exec_path}",
            "polling every 5 seconds...",
        ],
        title="SCAN INITIALISED",
    )

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)

    radar_slot  = st.empty()
    status_slot = st.empty()
    prog_slot   = st.progress(0)
    result_slot = st.empty()

    final_status = "unknown"
    MAX_POLLS    = 72   # 6 minutes total

    for i in range(MAX_POLLS):
        with radar_slot.container():
            scan_radar("SCANNING TARGET...")

        time.sleep(5)
        poll = api_get(f"/scan/{scan_id}")
        if not poll:
            break

        cur      = poll.get("status", "")
        findings = poll.get("vulnerability_count", 0)
        elapsed  = (i + 1) * 5

        with status_slot.container():
            kpi_row([
                {"label": "Status",   "value": cur.upper(),    "color": "c-cyan"},
                {"label": "Findings", "value": str(findings),  "color": "c-high"},
                {"label": "Elapsed",  "value": f"{elapsed}s",  "color": "c-med"},
            ])

        prog_slot.progress(min((i + 1) / MAX_POLLS, 1.0))

        if cur in ("completed", "failed", "cancelled"):
            final_status = cur
            break

    radar_slot.empty()

    # ── Display final result ──────────────────────────────────────────────────
    if final_status == "completed":
        st.success("Scan complete!")
        results = api_get(f"/results/{scan_id}")
        if results and results.get("vulnerabilities"):
            vulns = results["vulnerabilities"]
            severity_summary_cards({
                "CRITICAL": results.get("severity_counts", {}).get("critical", 0),
                "HIGH":     results.get("severity_counts", {}).get("high", 0),
                "MEDIUM":   results.get("severity_counts", {}).get("medium", 0),
                "LOW":      results.get("severity_counts", {}).get("low", 0),
                "INFO":     results.get("severity_counts", {}).get("info", 0),
            })
            st.markdown(
                f'<div class="pg-title" style="font-size:13px;margin:12px 0">'
                f'{len(vulns)} FINDING(S) DETECTED</div>',
                unsafe_allow_html=True,
            )
            for v in vulns:
                vulnerability_card(v)
        else:
            alert_banner("No vulnerabilities detected, or results not yet saved.", "info")

    elif final_status == "failed":
        poll = api_get(f"/scan/{scan_id}") or {}
        err  = poll.get("error_message", "Unknown error")
        st.error(f"Scan failed: {err}")
        terminal_box(
            [f"error: {err}", "Check backend logs for details."],
            title="SCAN FAILURE",
        )
    elif final_status == "cancelled":
        alert_banner("Scan was cancelled.", "warning")
    else:
        alert_banner(
            f"Scan timed out in polling (status={final_status!r}). "
            "Check SCAN HISTORY for final result.",
            "warning",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: Scan History
# ═══════════════════════════════════════════════════════════════════════════════

def page_scan_history() -> None:
    page_header("SCAN HISTORY", "Browse and inspect previous scan results")

    # ── Continuous-monitoring status banner ──────────────────────────────────
    sched = api_get("/targets/scheduler/status") or {}
    if sched:
        ran = "enabled" if sched.get("enabled") else "disabled"
        running = "running" if sched.get("running") else "stopped"
        interval = sched.get("interval_minutes", "?")
        last_tick = (sched.get("last_tick_at") or "—")[:19]
        last_n = sched.get("last_dispatched", 0)
        terminal_box(
            [
                f"auto-rescan : {ran} ({running})",
                f"interval    : every {interval} min",
                f"last tick   : {last_tick}  (dispatched {last_n} target(s))",
                "",
                "Toggle per target below — disabled targets are skipped by the scheduler.",
            ],
            title="CONTINUOUS MONITORING",
        )

    # ── Per-target auto-rescan toggles ───────────────────────────────────────
    targets = api_get("/targets") or []
    if targets:
        st.markdown(
            '<div class="pg-title" style="font-size:13px;margin:14px 0 6px 0">'
            'MONITORED TARGETS</div>', unsafe_allow_html=True,
        )
        for t in targets:
            tid, addr = t["id"], t["address"]
            enabled = bool(t.get("auto_rescan", True))
            last = (t.get("last_scanned_at") or "never")[:19]
            c1, c2, c3 = st.columns([4, 3, 2])
            with c1:
                st.markdown(
                    f"<div style='font-family:Share Tech Mono,monospace;font-size:13px'>"
                    f"<b>{addr}</b><br>"
                    f"<span style='color:var(--c-muted);font-size:11px'>"
                    f"last scan: {last}</span></div>",
                    unsafe_allow_html=True,
                )
            with c2:
                badge = "● ON " if enabled else "○ OFF"
                color = "c-low" if enabled else "c-muted"
                st.markdown(
                    f"<div style='font-family:Share Tech Mono,monospace;"
                    f"font-size:13px;color:var(--{color})'>"
                    f"AUTO-RESCAN: {badge}</div>",
                    unsafe_allow_html=True,
                )
            with c3:
                if st.button(
                    "DISABLE" if enabled else "ENABLE",
                    key=f"toggle_{tid}",
                    use_container_width=True,
                ):
                    api_request_patch = requests.patch(
                        f"{API_BASE}/targets/{tid}/auto-rescan",
                        json={"enabled": not enabled},
                        timeout=10,
                    )
                    if api_request_patch.status_code == 200:
                        st.rerun()
                    else:
                        st.error(f"Toggle failed: HTTP {api_request_patch.status_code}")

        st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)

    scans = api_get("/results?per_page=100") or []
    if not scans:
        alert_banner("No scans found.", "info")
        return

    # ── Filters ───────────────────────────────────────────────────────────────
    col1, col2 = st.columns(2)
    with col1:
        status_f = st.selectbox("Filter by Status", ["All", "completed", "failed", "pending", "running"])
    with col2:
        target_f = st.text_input("Filter by Target", placeholder="192.168…")

    if status_f != "All":
        scans = [s for s in scans if s.get("status") == status_f]
    if target_f:
        scans = [s for s in scans if target_f.lower() in s.get("target", "").lower()]

    st.markdown(f'<div class="pg-sub" style="margin-bottom:12px">{len(scans)} scan(s) found</div>', unsafe_allow_html=True)

    for scan in scans:
        sev = {k: scan.get(k, 0) for k in ["critical", "high", "medium", "low", "info"]}
        worst = (
            "CRITICAL" if sev["critical"] else
            "HIGH"     if sev["high"]     else
            "MEDIUM"   if sev["medium"]   else
            "LOW"      if sev["low"]      else "INFO"
        )

        with st.expander(
            f"[{scan.get('scan_id','')[:8]}]  {scan.get('target','')}  ·  "
            f"{scan.get('status','').upper()}  ·  "
            f"Findings: {scan.get('vulnerability_count', 0)}"
        ):
            c1, c2, c3 = st.columns(3)
            c1.markdown(f"**Type:** `{scan.get('scan_type','N/A')}`")
            c2.markdown(f"**Completed:** `{(scan.get('completed_at') or '—')[:19]}`")
            c3.markdown(severity_badge(worst), unsafe_allow_html=True)

            st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)
            severity_summary_cards({
                "CRITICAL": sev["critical"], "HIGH": sev["high"],
                "MEDIUM":   sev["medium"],   "LOW":  sev["low"], "INFO": sev["info"],
            })

            btn1, btn2 = st.columns(2)
            with btn1:
                if st.button("View Vulnerabilities", key=f"view_{scan['scan_id']}"):
                    st.session_state["vuln_scan_id"] = scan["scan_id"]
                    st.rerun()
            with btn2:
                if scan.get("status") == "completed":
                    if st.button("Generate PDF Report", key=f"pdf_{scan['scan_id']}"):
                        with st.spinner("Generating report…"):
                            r = api_post(f"/reports/{scan['scan_id']}", {"format": "pdf"})
                        if r:
                            st.success(f"Report generated: {r.get('file_path', '')}")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: Vulnerabilities
# ═══════════════════════════════════════════════════════════════════════════════

def page_vulnerabilities() -> None:
    page_header("VULNERABILITIES", "Browse, filter, and analyse all detected findings")

    # ── Filters ───────────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        sev_f = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    with col2:
        scan_id_f = st.text_input(
            "Scan ID",
            value=st.session_state.pop("vuln_scan_id", ""),
            placeholder="optional",
        )
    with col3:
        page_num = st.number_input("Page", min_value=1, value=1)

    params = f"?page={page_num}&per_page=20"
    if sev_f != "All":
        params += f"&severity={sev_f}"
    if scan_id_f.strip():
        params += f"&scan_id={scan_id_f.strip()}"

    vulns = api_get(f"/vulnerabilities{params}") or []

    if not vulns:
        alert_banner("No vulnerabilities match the current filters.", "info")
        return

    kpi_row([
        {"label": "Findings",   "value": str(len(vulns)), "color": "c-cyan"},
        {"label": "Critical",   "value": str(sum(1 for v in vulns if v.get("severity","").upper()=="CRITICAL")), "color": "c-crit"},
        {"label": "High",       "value": str(sum(1 for v in vulns if v.get("severity","").upper()=="HIGH")),     "color": "c-high"},
        {"label": "Avg CVSS",   "value": (
            f"{sum(float(v['cvss_score']) for v in vulns if v.get('cvss_score')) / max(1, sum(1 for v in vulns if v.get('cvss_score'))):.1f}"
            if any(v.get("cvss_score") for v in vulns) else "—"
        ), "color": "c-med"},
    ])

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)

    # ── Charts ────────────────────────────────────────────────────────────────
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown('<div class="pg-title" style="font-size:13px">VULNERABILITY TYPES</div>', unsafe_allow_html=True)
        st.plotly_chart(vuln_type_bar(vulns), use_container_width=True)
    with col_b:
        st.markdown('<div class="pg-title" style="font-size:13px">CVSS DISTRIBUTION</div>', unsafe_allow_html=True)
        st.plotly_chart(cvss_histogram(vulns), use_container_width=True)

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)
    st.markdown('<div class="pg-title" style="font-size:13px;margin-bottom:12px">FINDING DETAILS</div>', unsafe_allow_html=True)

    for v in vulns:
        vulnerability_card(v)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: Reports
# ═══════════════════════════════════════════════════════════════════════════════

def page_reports() -> None:
    page_header("REPORTS", "Generate and download vulnerability assessment reports")

    reports = api_get("/reports?per_page=50") or []

    if reports:
        kpi_row([{"label": "Reports Generated", "value": str(len(reports)), "color": "c-cyan"}])
        df = pd.DataFrame([
            {
                "Report ID": r["report_id"][:8] + "…",
                "Scan ID":   r["scan_id"][:8] + "…",
                "Format":    r.get("format", "").upper(),
                "Size KB":   f"{(r.get('file_size_bytes') or 0) // 1024}",
                "Generated": (r.get("generated_at") or "")[:19],
            }
            for r in reports
        ])
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        alert_banner(
            "No reports yet — complete a scan and generate a report from SCAN HISTORY.",
            "info",
        )

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)
    page_header("GENERATE REPORT", "Select a completed scan and output format")

    scans = api_get("/results?per_page=50&status=completed") or []
    if not scans:
        alert_banner("No completed scans available.", "warning")
        return

    scan_opts = {
        f"{s['scan_id'][:8]}…  —  {s.get('target','')}": s["scan_id"]
        for s in scans
    }
    chosen_label = st.selectbox("Completed Scan", list(scan_opts.keys()))
    chosen_id    = scan_opts[chosen_label]
    fmt          = st.radio("Format", ["PDF", "JSON", "CSV"], horizontal=True)

    if st.button("⬇  GENERATE REPORT"):
        with st.spinner(f"Generating {fmt} report…"):
            r = api_post(f"/reports/{chosen_id}", {"format": fmt.lower()})
        if r:
            st.success("Report generated.")
            st.json(r)
            dl = f"{API_BASE}/reports/{r.get('report_id','')}/download"
            st.markdown(f"[⬇ Download Report]({dl})", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: About
# ═══════════════════════════════════════════════════════════════════════════════

def page_about() -> None:
    page_header("ABOUT IVDAF", "Intelligent Vulnerability Detection and Analysis Framework")

    terminal_box(
        [
            "IVDAF v1.0.0  —  Python 3.13 · FastAPI · SQLAlchemy · Streamlit",
            "License: MIT (educational / authorised lab use only)",
            "Targets: DVWA · OWASP Juice Shop · Metasploitable 2/3",
            "Backend: http://localhost:8000   Frontend: http://localhost:8501",
        ],
        title="SYSTEM INFO",
    )

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("### Architecture")
        st.markdown("""
| Layer | Technology |
|---|---|
| Backend API | FastAPI + AsyncIO |
| Database | SQLAlchemy 2.0 (SQLite/PostgreSQL) |
| Task Queue | Celery + Redis |
| Frontend | Streamlit + Plotly |
| Scanning | python-nmap · httpx |
| Reporting | ReportLab (PDF/JSON/CSV) |
| Containers | Docker + Docker Compose |
        """)

    with col_b:
        st.markdown("### OWASP Top 10 Coverage")
        st.markdown("""
| OWASP ID | Category | Detectors |
|---|---|---|
| A01:2021 | Broken Access Control | Directory Traversal, HTTP Methods |
| A02:2021 | Cryptographic Failures | SSL/TLS Checker |
| A03:2021 | Injection | SQL Injection, XSS |
| A05:2021 | Security Misconfiguration | Header Checker, Port Checker |
| A06:2021 | Vulnerable Components | SSH Checker |
| A07:2021 | Auth Failures | Port Checker (Redis, MongoDB) |
        """)

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)
    st.markdown("### Detection Modules")

    kpi_row([
        {"label": "SQL Injection",     "value": "◈", "color": "c-crit"},
        {"label": "XSS",               "value": "◈", "color": "c-high"},
        {"label": "Header Checker",    "value": "◈", "color": "c-med"},
        {"label": "SSL / TLS",         "value": "◈", "color": "c-cyan"},
        {"label": "Port Scanner",      "value": "◈", "color": "c-low"},
        {"label": "SSH Checker",       "value": "◈", "color": "c-info"},
        {"label": "Dir Traversal",     "value": "◈", "color": "c-crit"},
        {"label": "HTTP Methods",      "value": "◈", "color": "c-high"},
    ])

    st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)
    st.warning(
        "**Disclaimer** — This tool is for educational and authorised security testing only. "
        "Only scan systems you own or have explicit written permission to test. "
        "Unauthorised scanning may be illegal in your jurisdiction."
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Router
# ═══════════════════════════════════════════════════════════════════════════════

_PAGE_MAP = {
    "DASHBOARD":       page_dashboard,
    "NEW SCAN":        page_new_scan,
    "SCAN HISTORY":    page_scan_history,
    "VULNERABILITIES": page_vulnerabilities,
    "REPORTS":         page_reports,
    "ABOUT":           page_about,
}

_PAGE_MAP.get(PAGE, page_dashboard)()
