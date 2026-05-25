"""
Neon Plotly chart helpers for the IVDAF cyberpunk dashboard.
All charts render on transparent backgrounds using the project's neon palette.
"""
from collections import Counter, defaultdict
from typing import Dict, List

import plotly.graph_objects as go
import pandas as pd

_FONT = "Share Tech Mono, Courier New, monospace"
_FG   = "#e0e0ff"
_MUTED = "#5a7a9a"
_GRID  = "rgba(0,245,255,0.07)"
_AXIS_LINE = "rgba(0,245,255,0.13)"

_SEV = {
    "CRITICAL": "#ff0055",
    "HIGH":     "#ff4500",
    "MEDIUM":   "#ffaa00",
    "LOW":      "#00ff88",
    "INFO":     "#4169e1",
}

_STATUS = {
    "completed": "#00ff88",
    "failed":    "#ff0055",
    "running":   "#00f5ff",
    "pending":   "#ffaa00",
    "cancelled": "#5a7a9a",
}

_SHARED = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family=_FONT, color=_FG, size=11),
    margin=dict(t=24, b=24, l=20, r=20),
    legend=dict(
        bgcolor="rgba(0,8,17,0.82)",
        bordercolor="rgba(0,245,255,0.18)",
        borderwidth=1,
        font=dict(family=_FONT, color=_FG, size=10),
    ),
)

_AXIS = dict(
    gridcolor=_GRID,
    linecolor=_AXIS_LINE,
    tickfont=dict(family=_FONT, color=_MUTED, size=10),
    zerolinecolor="rgba(0,245,255,0.08)",
)


def _fig(*traces, **layout_kw) -> go.Figure:
    fig = go.Figure(data=list(traces))
    kw = {**_SHARED, **layout_kw}
    fig.update_layout(**kw)
    return fig


def _empty(msg: str = "No data available") -> go.Figure:
    fig = _fig()
    fig.add_annotation(
        text=msg, showarrow=False,
        font=dict(family=_FONT, color=_MUTED, size=13),
        x=0.5, y=0.5, xref="paper", yref="paper",
    )
    return fig


# ── Severity donut ────────────────────────────────────────────────────────────

def severity_donut(severity_counts: Dict[str, int]) -> go.Figure:
    """Neon donut chart of vulnerability severity distribution."""
    pairs = [(k, v) for k, v in severity_counts.items() if v > 0]
    if not pairs:
        return _empty("No vulnerabilities detected")

    labels, values = zip(*pairs)
    colors = [_SEV.get(l, _MUTED) for l in labels]
    total  = sum(values)

    fig = _fig(
        go.Pie(
            labels=list(labels),
            values=list(values),
            hole=0.65,
            marker=dict(colors=colors, line=dict(color="#000811", width=3)),
            textinfo="label+percent",
            textfont=dict(family=_FONT, size=11, color=_FG),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
            pull=[0.05 if l == "CRITICAL" else 0 for l in labels],
            direction="clockwise",
        ),
        showlegend=True,
        legend=dict(orientation="h", y=-0.14, x=0.5, xanchor="center"),
        annotations=[dict(
            text=f'<b style="font-size:24px;color:#00f5ff">{total}</b>'
                 '<br><span style="font-size:9px;color:#5a7a9a;letter-spacing:2px">TOTAL</span>',
            x=0.5, y=0.5, showarrow=False,
            font=dict(family=_FONT),
        )],
    )
    return fig


# ── Severity bar ──────────────────────────────────────────────────────────────

def severity_bar(severity_counts: Dict[str, int]) -> go.Figure:
    """Neon horizontal bar chart of severity counts."""
    order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = [severity_counts.get(s, 0) for s in order]
    colors = [_SEV[s] for s in order]

    fig = _fig(
        go.Bar(
            x=counts, y=order, orientation="h",
            marker=dict(color=colors, line=dict(color="rgba(0,0,0,0)", width=0), opacity=0.88),
            text=counts, textposition="outside",
            textfont=dict(family=_FONT, color=_FG, size=11),
            hovertemplate="<b>%{y}</b>: %{x}<extra></extra>",
        ),
        showlegend=False,
        xaxis=dict(**_AXIS, title=dict(text="Count", font=dict(family=_FONT, color=_MUTED))),
        yaxis={**_AXIS, "gridcolor": "rgba(0,0,0,0)"},
    )
    return fig


# ── Scan history timeline ─────────────────────────────────────────────────────

def scan_history_timeline(scans: List[dict]) -> go.Figure:
    """Neon scatter timeline of scans with status-colored markers."""
    if not scans:
        return _empty("No scan history yet")

    df = pd.DataFrame(scans)
    df["completed_at"] = pd.to_datetime(df.get("completed_at", pd.NaT), errors="coerce")
    df["vuln_count"]   = pd.to_numeric(df.get("vulnerability_count", 0), errors="coerce").fillna(0)
    df["target"]       = df.get("target", "").fillna("unknown")
    df["status"]       = df.get("status", "unknown").fillna("unknown")

    traces = []
    for status, grp in df.groupby("status"):
        color = _STATUS.get(status, _MUTED)
        sizes = (grp["vuln_count"].clip(lower=1) * 3 + 10).clip(upper=42)
        traces.append(go.Scatter(
            x=grp["completed_at"],
            y=grp["target"],
            mode="markers",
            name=status.upper(),
            marker=dict(
                size=list(sizes),
                color=color,
                opacity=0.82,
                line=dict(color=color, width=1),
                symbol="circle",
            ),
            hovertemplate=(
                "<b>%{y}</b><br>"
                "Time: %{x}<br>"
                "Status: " + status.upper() +
                "<extra></extra>"
            ),
        ))

    fig = _fig(
        *traces,
        showlegend=True,
        legend=dict(orientation="h", y=-0.18, x=0.5, xanchor="center"),
        xaxis=dict(**_AXIS, title=dict(text="Completed At", font=dict(family=_FONT, color=_MUTED))),
        yaxis=dict(**_AXIS, title=dict(text="Target", font=dict(family=_FONT, color=_MUTED))),
    )
    return fig


# ── CVSS histogram ────────────────────────────────────────────────────────────

def cvss_histogram(vulnerabilities: List[dict]) -> go.Figure:
    """Severity-colored bar histogram of CVSS scores (no numpy required)."""
    scores = []
    for v in vulnerabilities:
        raw = v.get("cvss_score") or v.get("cvss")
        if raw is not None:
            try:
                scores.append(float(raw))
            except (ValueError, TypeError):
                pass

    if not scores:
        return _empty("No CVSS data available")

    def _sev_color(s: float) -> str:
        if s >= 9:   return _SEV["CRITICAL"]
        if s >= 7:   return _SEV["HIGH"]
        if s >= 4:   return _SEV["MEDIUM"]
        if s >= 0.1: return _SEV["LOW"]
        return _SEV["INFO"]

    # Manual 0.5-wide bins
    bins: dict = defaultdict(int)
    for s in scores:
        key = round(int(s * 2) / 2, 1)
        bins[key] += 1

    x_vals = sorted(bins)
    y_vals = [bins[k] for k in x_vals]
    colors = [_sev_color(x) for x in x_vals]

    fig = _fig(
        go.Bar(
            x=x_vals, y=y_vals, width=0.44,
            marker=dict(color=colors, opacity=0.88, line=dict(color="#000811", width=1)),
            hovertemplate="CVSS %{x:.1f} — %{y} findings<extra></extra>",
        ),
        showlegend=False,
        xaxis=dict(
            **_AXIS, range=[0, 10],
            title=dict(text="CVSS Score", font=dict(family=_FONT, color=_MUTED)),
        ),
        yaxis=dict(
            **_AXIS,
            title=dict(text="Findings", font=dict(family=_FONT, color=_MUTED)),
        ),
    )
    return fig


# ── Vulnerability type bar ────────────────────────────────────────────────────

def vuln_type_bar(vulnerabilities: List[dict]) -> go.Figure:
    """Horizontal bar chart of top vulnerability types (neon cyan gradient)."""
    counts = Counter(v.get("vuln_type", "Unknown") for v in vulnerabilities)
    if not counts:
        return _empty("No vulnerability data")

    top = counts.most_common(10)
    types, cnts = zip(*top)
    n = len(types)

    # Fade from bright cyan → dim cyan as rank decreases
    bar_colors = [
        f"rgba(0,245,255,{max(0.35, 0.95 - 0.55 * i / max(n - 1, 1)):.2f})"
        for i in range(n)
    ]

    fig = _fig(
        go.Bar(
            y=list(types), x=list(cnts), orientation="h",
            marker=dict(color=bar_colors, line=dict(color="rgba(0,0,0,0)", width=0)),
            text=list(cnts), textposition="outside",
            textfont=dict(family=_FONT, color=_FG, size=11),
            hovertemplate="<b>%{y}</b>: %{x}<extra></extra>",
        ),
        showlegend=False,
        xaxis=dict(**_AXIS, title=dict(text="Count", font=dict(family=_FONT, color=_MUTED))),
        yaxis={**_AXIS, "gridcolor": "rgba(0,0,0,0)"},
    )
    return fig
