"""
Futuristic Cyber UI Components for IVDAF Dashboard.
All components use pure HTML/CSS — no external assets required.
"""
import streamlit as st
from typing import Dict, List, Optional


# ── Design tokens ─────────────────────────────────────────────────────────────
CYBER_CYAN     = "#00f5ff"
CYBER_PURPLE   = "#7b2fff"
CYBER_CRITICAL = "#ff0055"
CYBER_HIGH     = "#ff4500"
CYBER_MEDIUM   = "#ffaa00"
CYBER_LOW      = "#00ff88"
CYBER_INFO     = "#4169e1"
CYBER_BG       = "#000811"
CYBER_MUTED    = "#5a7a9a"
CYBER_TEXT     = "#e0e0ff"

SEV_CONFIG = {
    "CRITICAL": {"color": CYBER_CRITICAL, "icon": "◈", "css": "critical"},
    "HIGH":     {"color": CYBER_HIGH,     "icon": "▲", "css": "high"},
    "MEDIUM":   {"color": CYBER_MEDIUM,   "icon": "◆", "css": "medium"},
    "LOW":      {"color": CYBER_LOW,      "icon": "▼", "css": "low"},
    "INFO":     {"color": CYBER_INFO,     "icon": "●", "css": "info"},
}


# ── Global style injection ─────────────────────────────────────────────────────

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap');

:root {
    --c-bg:       #000811;
    --c-surface:  rgba(0, 245, 255, 0.025);
    --c-border:   rgba(0, 245, 255, 0.14);
    --c-cyan:     #00f5ff;
    --c-purple:   #7b2fff;
    --c-critical: #ff0055;
    --c-high:     #ff4500;
    --c-medium:   #ffaa00;
    --c-low:      #00ff88;
    --c-info:     #4169e1;
    --c-text:     #e0e0ff;
    --c-muted:    #5a7a9a;
    --glow-c:     0 0 8px rgba(0,245,255,.45), 0 0 20px rgba(0,245,255,.15);
    --glow-p:     0 0 8px rgba(123,47,255,.45), 0 0 20px rgba(123,47,255,.15);
}

/* ── App shell ── */
.stApp, body { background-color: var(--c-bg) !important; }

[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(ellipse at 8% 20%,  rgba(0,245,255,.04)   0%, transparent 42%),
        radial-gradient(ellipse at 92% 80%, rgba(123,47,255,.04)  0%, transparent 42%),
        radial-gradient(ellipse at 50% 50%, rgba(0,8,17,1) 0%, var(--c-bg) 100%);
}

/* Hide Streamlit chrome */
#MainMenu, footer { visibility: hidden; }
[data-testid="stHeader"]  { background: transparent !important; }
[data-testid="stToolbar"] { display: none; }

/* ── Main content ── */
.block-container {
    padding: 1.5rem 2rem !important;
    max-width: 1440px !important;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: rgba(0, 6, 15, 0.98) !important;
    border-right: 1px solid var(--c-border) !important;
}
[data-testid="stSidebar"] > div:first-child { padding-top: 0 !important; }
[data-testid="stSidebarContent"] { padding: 0 !important; }

/* ── Buttons ── */
.stButton > button {
    background: transparent !important;
    border: 1px solid var(--c-cyan) !important;
    color: var(--c-cyan) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 12px !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    border-radius: 3px !important;
    transition: all .25s ease !important;
    box-shadow: 0 0 8px rgba(0,245,255,.1) !important;
    padding: 0.45rem 1.2rem !important;
}
.stButton > button:hover {
    background: rgba(0,245,255,.08) !important;
    box-shadow: var(--glow-c) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:active { transform: translateY(0) !important; }

/* ── Inputs ── */
.stTextInput > div > div > input,
.stSelectbox > div > div,
.stNumberInput > div > div > input,
.stTextArea textarea {
    background: rgba(0,245,255,.025) !important;
    border: 1px solid var(--c-border) !important;
    border-radius: 4px !important;
    color: var(--c-text) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 13px !important;
    transition: border-color .2s, box-shadow .2s !important;
}
.stTextInput > div > div > input:focus,
.stTextArea textarea:focus {
    border-color: var(--c-cyan) !important;
    box-shadow: 0 0 0 1px rgba(0,245,255,.3) !important;
    outline: none !important;
}

/* ── Labels ── */
.stTextInput label, .stSelectbox label, .stCheckbox label span,
.stNumberInput label, .stTextArea label, .stRadio label {
    color: var(--c-muted) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 11px !important;
    letter-spacing: 1.5px !important;
    text-transform: uppercase !important;
}

/* ── Expanders ── */
[data-testid="stExpander"] {
    background: var(--c-surface) !important;
    border: 1px solid var(--c-border) !important;
    border-radius: 6px !important;
    transition: border-color .25s, box-shadow .25s !important;
}
[data-testid="stExpander"]:hover {
    border-color: rgba(0,245,255,.35) !important;
    box-shadow: 0 4px 20px rgba(0,245,255,.06) !important;
}
[data-testid="stExpander"] summary { color: var(--c-text) !important; }

/* ── Tabs ── */
[data-baseweb="tab"] {
    color: var(--c-muted) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 11px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
}
[data-baseweb="tab"][aria-selected="true"] {
    color: var(--c-cyan) !important;
    border-bottom-color: var(--c-cyan) !important;
}
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    border-bottom: 1px solid var(--c-border) !important;
}

/* ── DataFrames ── */
[data-testid="stDataFrame"] iframe { background: transparent !important; }

/* ── Alert boxes ── */
[data-testid="stInfo"]    { background: rgba(0,245,255,.05) !important; border: 1px solid rgba(0,245,255,.2) !important; border-radius: 4px !important; }
[data-testid="stSuccess"] { background: rgba(0,255,136,.05) !important; border: 1px solid rgba(0,255,136,.2) !important; border-radius: 4px !important; }
[data-testid="stWarning"] { background: rgba(255,170,0,.05)  !important; border: 1px solid rgba(255,170,0,.2)  !important; border-radius: 4px !important; }
[data-testid="stError"]   { background: rgba(255,0,85,.05)   !important; border: 1px solid rgba(255,0,85,.2)   !important; border-radius: 4px !important; }

/* ── Progress bar ── */
[data-testid="stProgress"] > div { background: rgba(0,245,255,.1) !important; border-radius: 2px !important; }
[data-testid="stProgress"] > div > div { background: linear-gradient(90deg,var(--c-cyan),var(--c-purple)) !important; box-shadow: var(--glow-c) !important; border-radius: 2px !important; }

/* ── Metric ── */
[data-testid="metric-container"] label { color: var(--c-muted) !important; font-family: 'Share Tech Mono', monospace !important; font-size: 10px !important; letter-spacing: 1.5px !important; }
[data-testid="metric-container"] [data-testid="stMetricValue"] { color: var(--c-cyan) !important; font-family: 'Orbitron', monospace !important; }

/* ── Divider ── */
hr { border-color: var(--c-border) !important; margin: 1rem 0 !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--c-bg); }
::-webkit-scrollbar-thumb { background: rgba(0,245,255,.2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--c-cyan); box-shadow: var(--glow-c); }

/* ── Typography ── */
h1, h2, h3 { color: var(--c-cyan) !important; font-family: 'Orbitron', monospace !important; letter-spacing: 2px !important; }
h4, h5, h6 { color: var(--c-text) !important; font-family: 'Rajdhani', sans-serif !important; }
p, li, span { color: var(--c-text) !important; }
code { background: rgba(0,245,255,.08) !important; color: var(--c-cyan) !important; border-radius: 3px !important; font-family: 'Share Tech Mono', monospace !important; }

/* ── Checkbox ── */
.stCheckbox label { display: flex !important; align-items: center !important; gap: 8px !important; }

/* ── Animations ── */
@keyframes pulse-glow {
    0%,100% { box-shadow: 0 0 5px rgba(0,245,255,.3); }
    50%      { box-shadow: 0 0 18px rgba(0,245,255,.65), 0 0 35px rgba(0,245,255,.18); }
}
@keyframes glitch-text {
    0%,88%,100% { text-shadow: 0 0 25px rgba(0,245,255,.55); transform: none; }
    89%  { text-shadow: -3px 0 var(--c-critical), 3px 0 var(--c-cyan); transform: translateX(-2px) skewX(-1deg); }
    91%  { text-shadow:  3px 0 var(--c-purple),  -3px 0 var(--c-cyan); transform: translateX(2px)  skewX(1deg); }
    93%  { text-shadow: 0 0 25px rgba(0,245,255,.55); transform: none; }
    95%  { text-shadow: -1px 0 var(--c-critical), 1px 0 var(--c-purple); transform: translateX(-1px); }
    97%  { text-shadow: 0 0 25px rgba(0,245,255,.55); }
}
@keyframes shimmer-h {
    0%   { left: -100%; }
    100% { left:  100%; }
}
@keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
@keyframes float  { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-6px); } }
@keyframes spin   { from { transform: rotate(0deg);   } to { transform: rotate(360deg); } }
@keyframes spin-r { from { transform: rotate(360deg); } to { transform: rotate(0deg);   } }
@keyframes fade-in-up { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
@keyframes corner-pulse { 0%,100%{opacity:.4;} 50%{opacity:1;} }

/* ── Hero ── */
.hero-wrap {
    text-align: center;
    padding: 48px 24px 36px;
    animation: fade-in-up .8s ease both;
}
.hero-badge {
    display: inline-block;
    color: var(--c-cyan);
    border: 1px solid rgba(0,245,255,.45);
    padding: 4px 18px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    letter-spacing: 3px;
    margin-bottom: 28px;
    animation: pulse-glow 2.5s ease-in-out infinite;
    border-radius: 2px;
}
.hero-title {
    font-family: 'Orbitron', monospace;
    font-size: clamp(52px, 9vw, 100px);
    font-weight: 900;
    color: var(--c-cyan);
    letter-spacing: 10px;
    margin: 0 0 10px;
    animation: glitch-text 6s ease-in-out infinite;
    text-shadow: 0 0 30px rgba(0,245,255,.45);
    line-height: 1;
}
.hero-sub {
    font-family: 'Rajdhani', sans-serif;
    font-size: clamp(13px, 1.8vw, 17px);
    letter-spacing: 5px;
    color: var(--c-muted);
    margin: 0 0 14px;
    text-transform: uppercase;
}
.hero-desc {
    font-size: 15px;
    color: rgba(224,224,255,.55);
    max-width: 580px;
    margin: 0 auto 36px;
    line-height: 1.9;
    font-family: 'Rajdhani', sans-serif;
}

/* ── Status bar ── */
.status-row {
    display: flex; gap: 28px; justify-content: center;
    margin: 8px 0 40px; flex-wrap: wrap;
}
.status-pill {
    display: flex; align-items: center; gap: 8px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px; color: var(--c-muted); letter-spacing: 1px;
}
.s-dot { width:8px; height:8px; border-radius:50%; animation: blink 1.8s ease-in-out infinite; }
.s-dot.on  { background: var(--c-low);      box-shadow: 0 0 8px var(--c-low);      }
.s-dot.off { background: var(--c-critical); box-shadow: 0 0 8px var(--c-critical); }
.s-dot.pnd { background: var(--c-medium);   box-shadow: 0 0 8px var(--c-medium);   }

/* ── Stat grid ── */
.stat-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px; margin-top: 8px;
}
@media(max-width:720px){ .stat-grid { grid-template-columns: repeat(2,1fr); } }
.stat-box {
    background: rgba(0,245,255,.025);
    border: 1px solid var(--c-border);
    border-radius: 6px; padding: 24px 14px;
    text-align: center; transition: all .3s;
    position: relative; overflow: hidden;
}
.stat-box::after {
    content:''; position:absolute; bottom:0; left:0; right:0; height:2px;
    background: linear-gradient(90deg, transparent, var(--c-cyan), transparent);
    opacity:0; transition: opacity .3s;
}
.stat-box:hover { border-color:rgba(0,245,255,.35); box-shadow:0 0 18px rgba(0,245,255,.07); }
.stat-box:hover::after { opacity:1; }
.stat-num  { font-family:'Orbitron',monospace; font-size:34px; font-weight:700; color:var(--c-cyan); text-shadow:var(--glow-c); display:block; margin-bottom:6px; }
.stat-lbl  { font-family:'Share Tech Mono',monospace; font-size:10px; color:var(--c-muted); letter-spacing:2px; text-transform:uppercase; }

/* ── KPI cards ── */
.kpi-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:22px; }
.kpi-card {
    background: rgba(0,245,255,.02);
    border: 1px solid var(--c-border);
    border-radius:6px; padding:18px 16px;
    position:relative; overflow:hidden;
    animation: fade-in-up .5s ease both;
    transition: all .25s;
}
.kpi-card::before { content:''; position:absolute; top:0; left:0; bottom:0; width:3px; border-radius:6px 0 0 6px; }
.kpi-card.c-cyan::before { background:var(--c-cyan); }
.kpi-card.c-crit::before { background:var(--c-critical); }
.kpi-card.c-high::before { background:var(--c-high); }
.kpi-card.c-med::before  { background:var(--c-medium); }
.kpi-card.c-low::before  { background:var(--c-low); }
.kpi-card.c-info::before { background:var(--c-info); }
.kpi-card:hover { border-color:rgba(0,245,255,.3); box-shadow:0 4px 18px rgba(0,245,255,.05); transform:translateY(-2px); }
.kpi-lbl { font-family:'Share Tech Mono',monospace; font-size:9px; letter-spacing:2px; text-transform:uppercase; color:var(--c-muted); margin-bottom:6px; }
.kpi-val { font-family:'Orbitron',monospace; font-size:30px; font-weight:700; line-height:1; }
.kpi-card.c-cyan .kpi-val { color:var(--c-cyan); text-shadow:var(--glow-c); }
.kpi-card.c-crit .kpi-val { color:var(--c-critical); text-shadow:0 0 10px rgba(255,0,85,.4); }
.kpi-card.c-high .kpi-val { color:var(--c-high); }
.kpi-card.c-med  .kpi-val { color:var(--c-medium); }
.kpi-card.c-low  .kpi-val { color:var(--c-low); text-shadow:0 0 10px rgba(0,255,136,.4); }
.kpi-card.c-info .kpi-val { color:var(--c-info); }

/* ── Page header ── */
.pg-header {
    background: rgba(0,245,255,.025);
    border: 1px solid var(--c-border);
    border-left: 3px solid var(--c-cyan);
    border-radius: 6px;
    padding: 18px 22px;
    margin-bottom: 22px;
    position: relative; overflow: hidden;
    animation: fade-in-up .4s ease both;
}
.pg-header::before {
    content:''; position:absolute; top:0; left:-100%; width:100%; height:1px;
    background: linear-gradient(90deg, transparent, var(--c-cyan), transparent);
    animation: shimmer-h 3.5s ease-in-out infinite;
}
.pg-title { font-family:'Orbitron',monospace; font-size:22px; font-weight:700; color:var(--c-cyan); letter-spacing:3px; text-transform:uppercase; margin:0 0 4px; text-shadow:0 0 15px rgba(0,245,255,.3); }
.pg-sub   { font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--c-muted); letter-spacing:1.5px; }

/* ── Severity badge ── */
.sev-badge {
    display:inline-flex; align-items:center; gap:5px;
    padding:2px 9px; border-radius:3px;
    font-family:'Share Tech Mono',monospace; font-size:11px;
    font-weight:bold; letter-spacing:1px; border:1px solid;
}
.sev-badge.critical { color:var(--c-critical); border-color:var(--c-critical); background:rgba(255,0,85,.08);   box-shadow:0 0 8px rgba(255,0,85,.2); }
.sev-badge.high     { color:var(--c-high);     border-color:var(--c-high);     background:rgba(255,69,0,.08);   }
.sev-badge.medium   { color:var(--c-medium);   border-color:var(--c-medium);   background:rgba(255,170,0,.08);  }
.sev-badge.low      { color:var(--c-low);      border-color:var(--c-low);      background:rgba(0,255,136,.08);  box-shadow:0 0 8px rgba(0,255,136,.15); }
.sev-badge.info     { color:var(--c-info);     border-color:var(--c-info);     background:rgba(65,105,225,.08); }

/* ── Terminal box ── */
.term-box {
    background:#000511; border:1px solid var(--c-border);
    border-radius:6px; padding:36px 20px 20px;
    font-family:'Share Tech Mono',monospace; font-size:13px;
    color:var(--c-cyan); position:relative; line-height:1.9;
}
.term-box::before { content:'● ● ●'; position:absolute; top:10px; left:16px; font-size:8px; color:var(--c-muted); letter-spacing:5px; }
.term-cursor { display:inline-block; width:7px; height:13px; background:var(--c-cyan); animation:blink 1s step-end infinite; vertical-align:text-bottom; margin-left:2px; }

/* ── Radar animation ── */
.radar-wrap { display:flex; flex-direction:column; align-items:center; gap:20px; padding:24px; }
.radar { width:90px; height:90px; position:relative; }
.radar-ring { position:absolute; border-radius:50%; border:1px solid; top:50%; left:50%; transform:translate(-50%,-50%); }
.radar-ring:nth-child(1) { width:90px; height:90px; border-color:rgba(0,245,255,.6); border-top-color:var(--c-cyan); animation:spin 2.5s linear infinite; }
.radar-ring:nth-child(2) { width:62px; height:62px; border-color:rgba(0,245,255,.35); animation:spin-r 1.8s linear infinite; border-right-color:var(--c-purple); }
.radar-ring:nth-child(3) { width:34px; height:34px; border-color:rgba(0,245,255,.2); animation:spin  1s linear infinite; background:rgba(0,245,255,.04); }
.radar-dot  { position:absolute; width:6px; height:6px; border-radius:50%; background:var(--c-cyan); top:50%; left:50%; transform:translate(-50%,-50%); box-shadow:var(--glow-c); animation:pulse-glow 1s ease-in-out infinite; }
.radar-label { font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--c-cyan); letter-spacing:3px; text-transform:uppercase; animation:blink 1.5s ease-in-out infinite; }

/* ── Sidebar navigation ── */
.side-logo {
    padding: 24px 20px 20px;
    border-bottom: 1px solid var(--c-border);
    text-align: center;
    margin-bottom: 8px;
}
.side-logo-title {
    font-family: 'Orbitron', monospace;
    font-size: 20px; font-weight: 900;
    color: var(--c-cyan);
    letter-spacing: 4px;
    text-shadow: var(--glow-c);
    animation: glitch-text 8s ease-in-out infinite;
}
.side-logo-sub {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px; color: var(--c-muted);
    letter-spacing: 2px; margin-top: 4px;
}
.side-nav-item {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px; letter-spacing: 1.5px;
    color: var(--c-muted); cursor: pointer;
    transition: all .2s; border-left: 2px solid transparent;
    text-transform: uppercase;
}
.side-nav-item:hover, .side-nav-item.active {
    color: var(--c-cyan);
    border-left-color: var(--c-cyan);
    background: rgba(0,245,255,.04);
    text-shadow: 0 0 6px rgba(0,245,255,.35);
}
.side-footer {
    padding: 16px 20px;
    border-top: 1px solid var(--c-border);
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; color: var(--c-muted);
    letter-spacing: 1px;
}

/* ── Corner accent for cyber effect ── */
.corner-tl, .corner-tr, .corner-bl, .corner-br {
    position: absolute; width:12px; height:12px;
    border-color: var(--c-cyan); border-style: solid;
    animation: corner-pulse 2s ease-in-out infinite;
}
.corner-tl { top:0; left:0;  border-width:2px 0 0 2px; }
.corner-tr { top:0; right:0; border-width:2px 2px 0 0; }
.corner-bl { bottom:0; left:0;  border-width:0 0 2px 2px; }
.corner-br { bottom:0; right:0; border-width:0 2px 2px 0; }

/* ── Vuln card ── */
.vuln-row {
    background: rgba(0,245,255,.018);
    border: 1px solid var(--c-border);
    border-radius: 6px; margin-bottom: 10px;
    transition: all .25s; position: relative; overflow: hidden;
}
.vuln-row::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; border-radius:6px 0 0 6px; }
.vuln-row.critical::before { background:var(--c-critical); }
.vuln-row.high::before     { background:var(--c-high); }
.vuln-row.medium::before   { background:var(--c-medium); }
.vuln-row.low::before      { background:var(--c-low); }
.vuln-row.info::before     { background:var(--c-info); }
.vuln-row:hover { border-color:rgba(0,245,255,.3); box-shadow:0 4px 16px rgba(0,245,255,.05); }

/* ── Table override ── */
.stDataFrame { border-radius:6px !important; border:1px solid var(--c-border) !important; }

/* ── Typewriter ── */
.typewriter {
    overflow: hidden; white-space: nowrap;
    border-right: 2px solid var(--c-cyan);
    animation: type-out 3s steps(40,end) 1s both, blink .7s step-end 3.1s infinite;
    font-family: 'Share Tech Mono', monospace;
    font-size: 14px; color: var(--c-muted); letter-spacing: 2px;
    display: inline-block; margin: 0 auto 32px;
}
@keyframes type-out { from{width:0} to{width:100%} }

/* ── Neon divider ── */
.neon-divider { height:1px; background:linear-gradient(90deg,transparent,var(--c-cyan),transparent); margin:20px 0; opacity:.4; }
</style>
"""

MATRIX_JS = """
<script>
(function(){
    var ID = 'ivdaf-particles';
    if (document.getElementById(ID)) return;

    /* ── Canvas ── */
    var c = document.createElement('canvas');
    c.id = ID;
    Object.assign(c.style, {
        position: 'fixed', top: '0', left: '0',
        width: '100vw', height: '100vh',
        zIndex: '-1', pointerEvents: 'none', opacity: '0.22'
    });
    document.body.insertBefore(c, document.body.firstChild);
    var ctx = c.getContext('2d');

    /* ── Config ── */
    var PALETTE = ['#00f5ff','#00f5ff','#00f5ff','#7b2fff','#00ff88'];
    var N = 72, MAX_D = 145;
    var W, H, pts;

    function mkPt() {
        return {
            x: Math.random() * W,
            y: Math.random() * H,
            vx: (Math.random() - 0.5) * 0.28,
            vy: (Math.random() - 0.5) * 0.28,
            r: Math.random() * 1.6 + 0.7,
            col: PALETTE[Math.floor(Math.random() * PALETTE.length)],
            phase: Math.random() * Math.PI * 2
        };
    }

    function resize() {
        c.width  = W = window.innerWidth;
        c.height = H = window.innerHeight;
    }

    function init() {
        resize();
        pts = Array.from({length: N}, mkPt);
    }
    init();
    window.addEventListener('resize', resize);

    /* ── Render loop ── */
    var t = 0, rid;

    function frame() {
        rid = requestAnimationFrame(frame);
        ctx.clearRect(0, 0, W, H);
        t += 0.006;

        /* connections */
        for (var i = 0; i < N; i++) {
            for (var j = i + 1; j < N; j++) {
                var dx = pts[j].x - pts[i].x;
                var dy = pts[j].y - pts[i].y;
                var d  = Math.sqrt(dx * dx + dy * dy);
                if (d < MAX_D) {
                    var a = (1 - d / MAX_D) * 0.52;
                    ctx.beginPath();
                    ctx.strokeStyle = 'rgba(0,245,255,' + a + ')';
                    ctx.lineWidth   = 0.55;
                    ctx.moveTo(pts[i].x, pts[i].y);
                    ctx.lineTo(pts[j].x, pts[j].y);
                    ctx.stroke();
                }
            }
        }

        /* nodes */
        for (var k = 0; k < N; k++) {
            var p     = pts[k];
            var pulse = Math.sin(t * 1.9 + p.phase) * 0.32 + 0.78;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r * pulse, 0, Math.PI * 2);
            ctx.fillStyle  = p.col;
            ctx.shadowColor = p.col;
            ctx.shadowBlur = 9;
            ctx.fill();
            ctx.shadowBlur = 0;

            /* wrap-around movement — no bouncing */
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < -12) p.x = W + 12;
            if (p.x > W + 12) p.x = -12;
            if (p.y < -12) p.y = H + 12;
            if (p.y > H + 12) p.y = -12;
        }
    }
    frame();

    /* cleanup when Streamlit re-renders */
    new MutationObserver(function() {
        if (!document.getElementById(ID)) cancelAnimationFrame(rid);
    }).observe(document.body, {childList: true, subtree: false});
})();
</script>
"""


def inject_styles() -> None:
    """Inject global CSS and matrix rain. Call once at top of dashboard."""
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
    st.markdown(MATRIX_JS,  unsafe_allow_html=True)


# ── Sidebar (restored to original) ────────────────────────────────────────────

# (Earlier sticky top-nav experiment removed — sidebar nav restored below.)


# ── Simple horizontal navigation (always visible, sidebar-independent) ──────

_HNAV_ITEMS = [
    ("DASHBOARD",       "◈"),
    ("NEW SCAN",        "▶"),
    ("SCAN HISTORY",    "≡"),
    ("VULNERABILITIES", "⬡"),
    ("REPORTS",         "⬇"),
    ("ABOUT",           "ℹ"),
]

_HNAV_CSS = """
<style>
.hnav-wrap {
    display: flex; align-items: center; gap: 14px;
    padding: 10px 6px 4px 6px;
    border-bottom: 1px solid rgba(0,245,255,.18);
    margin-bottom: 14px;
}
.hnav-brand {
    font-family: 'Orbitron', monospace;
    font-weight: 800; font-size: 16px; letter-spacing: 4px;
    color: var(--c-cyan);
    text-shadow: 0 0 8px rgba(0,245,255,.35);
    padding-right: 12px; margin-right: 4px;
    border-right: 1px solid rgba(0,245,255,.14);
}
.hnav-status {
    margin-left: auto;
    display: inline-flex; align-items: center; gap: 7px;
    padding: 5px 11px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px; letter-spacing: 1.5px;
    color: var(--c-text);
    border: 1px solid rgba(0,245,255,.22);
    border-radius: 20px;
    background: rgba(0,8,17,.55);
}
.hnav-status .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--c-low);
    box-shadow: 0 0 6px var(--c-low);
    animation: hnav-pulse 2s ease-in-out infinite;
}
.hnav-status.off .dot {
    background: var(--c-critical);
    box-shadow: 0 0 6px var(--c-critical);
}
@keyframes hnav-pulse {
    0%, 100% { opacity: 1; }
    50%      { opacity: .55; }
}

/* Restyle the Streamlit buttons that sit on the very first horizontal row
   only — uses :nth-of-type(1) so it doesn't bleed into page-content rows. */
.hnav-host .stButton > button {
    background: transparent !important;
    border: 1px solid transparent !important;
    color: rgba(224,224,255,.65) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 11px !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
    padding: 6px 8px !important;
    border-radius: 4px !important;
    box-shadow: none !important;
    width: 100% !important;
    transition: color .2s ease, background .2s ease, border-color .2s ease !important;
}
.hnav-host .stButton > button:hover {
    color: var(--c-cyan) !important;
    background: rgba(0,245,255,.06) !important;
    border-color: rgba(0,245,255,.22) !important;
}
.hnav-host .stButton > button:focus { outline: none !important; }
.hnav-host .stButton > button[kind="primary"] {
    color: var(--c-cyan) !important;
    background: rgba(0,245,255,.10) !important;
    border-color: rgba(0,245,255,.45) !important;
    box-shadow: 0 0 0 1px rgba(0,245,255,.20) inset !important;
}
</style>
"""


def render_horizontal_nav(api_online: bool) -> str:
    """
    Render a simple horizontal navigation bar at the top of the page.

    Works independently of the sidebar (which may be hidden). Returns the
    currently selected page id.
    """
    st.markdown(_HNAV_CSS, unsafe_allow_html=True)

    if "nav_page" not in st.session_state:
        st.session_state["nav_page"] = _HNAV_ITEMS[0][0]

    # Brand + status pill row (above the buttons)
    status_class = "" if api_online else "off"
    status_label = "ONLINE" if api_online else "OFFLINE"
    st.markdown(
        f'<div class="hnav-wrap">'
        f'  <span class="hnav-brand">IVDAF</span>'
        f'  <span style="font-family:Share Tech Mono,monospace;font-size:11px;'
        f'        color:var(--c-muted);letter-spacing:2px">VULNERABILITY FRAMEWORK</span>'
        f'  <span class="hnav-status {status_class}">'
        f'    <span class="dot"></span><span>API {status_label}</span>'
        f'  </span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Buttons row — wrapped in a host div so CSS only targets these buttons.
    st.markdown('<div class="hnav-host">', unsafe_allow_html=True)
    cols = st.columns(len(_HNAV_ITEMS), gap="small")
    for col, (page_id, glyph) in zip(cols, _HNAV_ITEMS):
        active = (st.session_state["nav_page"] == page_id)
        with col:
            if st.button(
                f"{glyph}  {page_id}",
                key=f"hnav_{page_id}",
                type=("primary" if active else "secondary"),
                use_container_width=True,
            ) and not active:
                st.session_state["nav_page"] = page_id
                st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    return st.session_state["nav_page"]


def render_sidebar(api_online: bool) -> str:
    """Render the cyberpunk sidebar and return the selected page name."""
    with st.sidebar:
        st.markdown("""
        <div class="side-logo">
            <div class="side-logo-title">IVDAF</div>
            <div class="side-logo-sub">VULNERABILITY FRAMEWORK v1.0</div>
        </div>
        """, unsafe_allow_html=True)

        page = st.radio(
            "NAV",
            ["◈  DASHBOARD", "▶  NEW SCAN", "≡  SCAN HISTORY",
             "⬡  VULNERABILITIES", "⬇  REPORTS", "ℹ  ABOUT"],
            label_visibility="collapsed",
        )

        st.markdown("<div class='neon-divider'></div>", unsafe_allow_html=True)

        dot = "on" if api_online else "off"
        label = "ONLINE" if api_online else "OFFLINE"
        st.markdown(f"""
        <div style="padding:0 20px;">
            <div class="status-pill">
                <div class="s-dot {dot}"></div>
                <span>API {label}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="side-footer" style="margin-top:auto;">
            ⚠ Authorised lab use only<br>
            Targets: DVWA · JuiceShop · Metasploitable
        </div>
        """, unsafe_allow_html=True)

    return page.split("  ", 1)[-1]


# ── Page header ───────────────────────────────────────────────────────────────

def page_header(title: str, subtitle: str = "") -> None:
    st.markdown(f"""
    <div class="pg-header">
        <div class="pg-title">{title}</div>
        {"<div class='pg-sub'>" + subtitle + "</div>" if subtitle else ""}
    </div>
    """, unsafe_allow_html=True)


# ── KPI / metrics ─────────────────────────────────────────────────────────────

def kpi_row(items: List[dict]) -> None:
    """
    items = [{"label":"Scans","value":"12","color":"c-cyan"}, ...]
    color classes: c-cyan c-crit c-high c-med c-low c-info
    """
    cards = "".join(f"""
    <div class="kpi-card {it['color']}" style="animation-delay:{i*0.07}s">
        <div class="kpi-lbl">{it['label']}</div>
        <div class="kpi-val">{it['value']}</div>
    </div>""" for i, it in enumerate(items))
    st.markdown(f'<div class="kpi-row">{cards}</div>', unsafe_allow_html=True)


# ── Severity badge ─────────────────────────────────────────────────────────────

def severity_badge(severity: str) -> str:
    cfg = SEV_CONFIG.get(severity.upper(), {"color": CYBER_MUTED, "icon": "●", "css": "info"})
    return (
        f'<span class="sev-badge {cfg["css"]}">'
        f'{cfg["icon"]} {severity.upper()}</span>'
    )


def severity_summary_cards(counts: Dict[str, int]) -> None:
    """Display 5 severity KPI cards inline."""
    items = [
        {"label": "CRITICAL", "value": str(counts.get("CRITICAL", 0)), "color": "c-crit"},
        {"label": "HIGH",     "value": str(counts.get("HIGH", 0)),     "color": "c-high"},
        {"label": "MEDIUM",   "value": str(counts.get("MEDIUM", 0)),   "color": "c-med"},
        {"label": "LOW",      "value": str(counts.get("LOW", 0)),      "color": "c-low"},
        {"label": "INFO",     "value": str(counts.get("INFO", 0)),     "color": "c-info"},
    ]
    kpi_row(items)


# ── Landing hero ─────────────────────────────────────────────────────────────

def landing_hero(api_online: bool) -> None:
    dot = "on" if api_online else "off"
    api_label = "ONLINE" if api_online else "OFFLINE"
    st.markdown(f"""
    <div class="hero-wrap">
        <div class="hero-badge">◈ AUTHORIZED PERSONNEL ONLY ◈</div>
        <div class="hero-title">IVDAF</div>
        <div class="hero-sub">Intelligent Vulnerability Detection &amp; Analysis Framework</div>
        <div class="typewriter">INITIALISING THREAT DETECTION ENGINE...</div>
        <div class="hero-desc">
            Multi-layer adaptive vulnerability assessment platform with IDS-aware
            scanning, AI-powered explainable findings, and automated remediation.
        </div>
        <div class="status-row">
            <div class="status-pill"><div class="s-dot {dot}"></div><span>API {api_label}</span></div>
            <div class="status-pill"><div class="s-dot on"></div><span>ENGINE READY</span></div>
            <div class="status-pill"><div class="s-dot pnd"></div><span>AWAITING TARGET</span></div>
            <div class="status-pill"><div class="s-dot on"></div><span>DB CONNECTED</span></div>
        </div>
        <div class="stat-grid">
            <div class="stat-box"><span class="stat-num">8</span><span class="stat-lbl">Vuln Detectors</span></div>
            <div class="stat-box"><span class="stat-num">15</span><span class="stat-lbl">REST Endpoints</span></div>
            <div class="stat-box"><span class="stat-num">A01–A07</span><span class="stat-lbl">OWASP Coverage</span></div>
            <div class="stat-box"><span class="stat-num">3</span><span class="stat-lbl">Report Formats</span></div>
        </div>
    </div>
    <div class="neon-divider"></div>
    """, unsafe_allow_html=True)


# ── Terminal box ──────────────────────────────────────────────────────────────

def terminal_box(lines: List[str], title: str = "") -> None:
    formatted = "".join(
        f'<div><span style="color:var(--c-muted)">❯</span> {line}</div>'
        for line in lines
    )
    st.markdown(f"""
    <div class="term-box">
        {'<div style="color:var(--c-muted);font-size:10px;letter-spacing:2px;margin-bottom:10px;">' + title + '</div>' if title else ''}
        {formatted}
        <span class="term-cursor"></span>
    </div>
    """, unsafe_allow_html=True)


# ── Scan radar ───────────────────────────────────────────────────────────────

def scan_radar(label: str = "SCANNING...") -> None:
    st.markdown(f"""
    <div class="radar-wrap">
        <div class="radar">
            <div class="radar-ring"></div>
            <div class="radar-ring"></div>
            <div class="radar-ring"></div>
            <div class="radar-dot"></div>
        </div>
        <div class="radar-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


# ── Alert banner ─────────────────────────────────────────────────────────────

def alert_banner(message: str, level: str = "info") -> None:
    fn = {"info": st.info, "warning": st.warning, "error": st.error, "success": st.success}
    fn.get(level, st.info)(message)


# ── Scan status ───────────────────────────────────────────────────────────────

def scan_status_indicator(status: str) -> str:
    m = {
        "pending":   '<span style="color:var(--c-medium)">⏳ PENDING</span>',
        "running":   '<span style="color:var(--c-cyan);animation:blink 1s infinite">⟳ RUNNING</span>',
        "completed": '<span style="color:var(--c-low)">✔ COMPLETED</span>',
        "failed":    '<span style="color:var(--c-critical)">✖ FAILED</span>',
        "cancelled": '<span style="color:var(--c-muted)">⊘ CANCELLED</span>',
    }
    return m.get(status.lower(), f'<span>{status.upper()}</span>')


# ── Vulnerability card ────────────────────────────────────────────────────────

def vulnerability_card(vuln: dict) -> None:
    sev  = vuln.get("severity", "INFO").upper()
    cfg  = SEV_CONFIG.get(sev, SEV_CONFIG["INFO"])
    name = vuln.get("name", "Unknown")
    cvss = vuln.get("cvss_score") or vuln.get("cvss") or "—"

    with st.expander(
        f"{cfg['icon']}  {name}   ·   CVSS {cvss}   ·   {sev}",
        expanded=False,
    ):
        c1, c2 = st.columns([3, 1])
        with c1:
            st.markdown(severity_badge(sev), unsafe_allow_html=True)
            st.markdown(
                f"**OWASP:** `{vuln.get('owasp_mapping','N/A')}`  "
                f"  **CWE:** `{vuln.get('cwe','N/A')}`",
            )
            if vuln.get("affected_url"):
                st.markdown(f"**Target:** `{vuln['affected_url']}`")
            if vuln.get("affected_port"):
                st.markdown(f"**Port:** `{vuln['affected_port']}`")
        with c2:
            if vuln.get("cvss_score"):
                score = float(vuln["cvss_score"])
                ring_color = (
                    CYBER_CRITICAL if score >= 9 else
                    CYBER_HIGH     if score >= 7 else
                    CYBER_MEDIUM   if score >= 4 else CYBER_LOW
                )
                st.markdown(f"""
                <div style="
                    text-align:center; padding:14px;
                    border:2px solid {ring_color};
                    border-radius:50%; width:80px; height:80px;
                    display:flex; flex-direction:column;
                    align-items:center; justify-content:center;
                    box-shadow:0 0 14px {ring_color}44;
                    background:{ring_color}0d; margin:auto;
                ">
                    <span style="font-family:'Orbitron',monospace;font-size:22px;font-weight:700;color:{ring_color}">{score}</span>
                    <span style="font-size:9px;color:var(--c-muted);letter-spacing:1px">CVSS</span>
                </div>
                """, unsafe_allow_html=True)

        st.markdown('<div class="neon-divider"></div>', unsafe_allow_html=True)

        # ── Plain-English "What this means" banner (non-technical readers) ───
        plain = vuln.get("non_technical")
        blurb = vuln.get("severity_blurb")
        if plain:
            banner_color = cfg["color"]
            st.markdown(f"""
            <div style="
                border-left: 4px solid {banner_color};
                background: {banner_color}14;
                padding: 12px 16px; border-radius: 6px;
                margin: 8px 0 14px 0;
                font-family: 'Rajdhani', sans-serif;
                font-size: 15px; line-height: 1.5;
                color: var(--c-text);
            ">
                <div style="
                    text-transform: uppercase;
                    letter-spacing: 1.5px; font-size: 11px;
                    color: {banner_color}; font-weight: 700;
                    margin-bottom: 6px;
                ">What this means</div>
                <div>{plain}</div>
                {f'<div style="margin-top:8px;opacity:.85;font-size:13px"><b>Urgency:</b> {blurb}</div>' if blurb else ''}
            </div>
            """, unsafe_allow_html=True)

        tabs = st.tabs(["WHAT TO DO", "TECHNICAL DETAIL", "IMPACT", "EVIDENCE"])
        with tabs[0]:
            st.markdown("**Fix steps:**")
            for step in (vuln.get("fix") or ["No specific remediation listed."]):
                st.markdown(f"- {step}")
            refs = vuln.get("references") or []
            if refs:
                st.markdown("**Learn more:**")
                for ref in refs:
                    st.markdown(f"- [{ref}]({ref})")
        with tabs[1]:
            st.markdown(f"> {vuln.get('explanation') or vuln.get('summary') or '—'}")
            if vuln.get("description") or vuln.get("technical_description"):
                terminal_box(
                    [(vuln.get("description") or vuln.get("technical_description"))[:400]],
                    title="TECHNICAL DETAIL"
                )
            if vuln.get("attack_scenario"):
                st.markdown(f"**Attack scenario:** {vuln['attack_scenario']}")
        with tabs[2]:
            st.warning(vuln.get("impact") or "Impact not specified.")
        with tabs[3]:
            if vuln.get("payload_used"):
                st.code(vuln["payload_used"], language="text")
            if vuln.get("response_snippet"):
                st.code(vuln["response_snippet"][:500], language="html")
            cves = vuln.get("cve_references") or []
            if cves:
                st.markdown("**CVEs:** " + " · ".join(f"`{c}`" for c in cves))
