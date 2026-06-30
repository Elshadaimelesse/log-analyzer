"""
dashboard.py
------------
Optional Streamlit web dashboard for the SOC Log Analyzer.

Run with:
    streamlit run dashboard.py

Requirements:
    pip install streamlit matplotlib
"""

import os
import datetime
import streamlit as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from core.parser import parse_log_file
from core.detector import analyze, top_attackers

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

# ── Custom CSS for dark SOC aesthetic ─────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0d1117; }
    .stMetric label { color: #58a6ff !important; font-weight: bold; }
    .stMetric .metric-value { color: #ffffff !important; }
    .risk-high   { color: #ff4d4d; font-size: 1.4rem; font-weight: bold; }
    .risk-medium { color: #ffa500; font-size: 1.4rem; font-weight: bold; }
    .risk-low    { color: #4caf50; font-size: 1.4rem; font-weight: bold; }
    h1, h2, h3  { color: #58a6ff; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.image("https://img.icons8.com/color/96/000000/cyber-security.png", width=80)
st.sidebar.title("SOC Log Analyzer")
st.sidebar.markdown("---")

log_path = st.sidebar.text_input("Log file path", value=os.path.join("logs", "access.log"))
refresh  = st.sidebar.button("🔄 Analyze / Refresh")

st.sidebar.markdown("---")
st.sidebar.markdown("**Thresholds**")
brute_thresh = st.sidebar.slider("Brute-force threshold", 2, 20, 5)
scan_thresh  = st.sidebar.slider("Scan 404 threshold",    2, 20, 4)

# ── Main panel ────────────────────────────────────────────────────────────────
st.title("🛡️ SOC Log Analyzer — Threat Intelligence Dashboard")
st.caption(f"Last run: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if not os.path.exists(log_path):
    st.error(f"Log file not found: `{log_path}`")
    st.stop()

# Parse & analyze
entries = parse_log_file(log_path)
summary = analyze(entries)

# ── KPI row ───────────────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("📄 Total Entries",    summary.total_entries)
col2.metric("🌐 Unique IPs",       summary.unique_ips)
col3.metric("🔐 Brute-force IPs",  len(summary.brute_force_ips))
col4.metric("🔍 Scanning IPs",     len(summary.scanning_ips))
col5.metric("💉 SQLi Attempts",    len(summary.sqli_attempts))

st.markdown("---")

# ── Risk level ────────────────────────────────────────────────────────────────
risk = summary.risk_level
risk_class = f"risk-{risk.lower()}"
st.markdown(f'<p class="{risk_class}">⚠ Overall Risk Level: {risk}</p>', unsafe_allow_html=True)
st.markdown("---")

# ── Two-column layout ─────────────────────────────────────────────────────────
left, right = st.columns(2)

with left:
    st.subheader("📊 Top IPs by Request Volume")
    attackers = top_attackers(summary, 10)
    flagged = {
        d["ip"] for lst in (summary.brute_force_ips, summary.scanning_ips, summary.sqli_attempts)
        for d in lst
    }
    ips    = [a[0] for a in attackers][::-1]
    counts = [a[1] for a in attackers][::-1]
    colors = ["#e74c3c" if ip in flagged else "#2980b9" for ip in ips]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.barh(ips, counts, color=colors)
    ax.set_facecolor("#1a1a2e")
    fig.patch.set_facecolor("#0d1117")
    ax.tick_params(colors="white")
    ax.xaxis.label.set_color("white")
    ax.set_xlabel("Requests", color="white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#333355")
    st.pyplot(fig)

with right:
    st.subheader("📈 HTTP Status Code Distribution")
    labels = list(summary.status_counts.keys())
    values = [summary.status_counts[k] for k in labels]
    palette = []
    for code in labels:
        if code.startswith("2"):   palette.append("#2ecc71")
        elif code.startswith("4"): palette.append("#f39c12")
        elif code.startswith("5"): palette.append("#e74c3c")
        else:                      palette.append("#3498db")

    fig2, ax2 = plt.subplots(figsize=(5, 4))
    ax2.pie(values, labels=labels, colors=palette, autopct="%1.0f%%",
            textprops={"color": "white"})
    fig2.patch.set_facecolor("#0d1117")
    st.pyplot(fig2)

st.markdown("---")

# ── Threat tables ─────────────────────────────────────────────────────────────
if summary.brute_force_ips:
    st.subheader("🔐 Brute-Force Attacks")
    st.table(summary.brute_force_ips)

if summary.scanning_ips:
    st.subheader("🔍 Scanning / Enumeration")
    st.table(summary.scanning_ips)

if summary.sqli_attempts:
    st.subheader("💉 SQL Injection Probes")
    st.table(summary.sqli_attempts)

if summary.suspicious_path_hits:
    st.subheader("⚠ Suspicious Endpoint Access")
    st.table(summary.suspicious_path_hits[:30])

st.markdown("---")
st.caption("SOC Log Analyzer — Portfolio Project | Built with Python & Streamlit")
