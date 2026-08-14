import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from datetime import datetime
import re

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Banking Honeypot Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "honeypot_traffic.log"

# ============================================================
# PAGE TITLE
# ============================================================

st.title("🛡️ Banking Honeypot Security Dashboard")
st.caption("Real-time monitoring of login attempts, attacks, AI predictions and threat intelligence")

# ============================================================
# LOAD LOG FILE
# ============================================================

def load_logs():
    """Read honeypot traffic log."""

    if not LOG_FILE.exists():
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        return [line.strip() for line in lines if line.strip()]

    except Exception as error:
        st.error(f"Unable to read log file: {error}")
        return []


logs = load_logs()

# ============================================================
# BASIC LOG ANALYSIS
# ============================================================

def count_attacks(logs):
    """Count suspicious/attack related log entries."""

    attack_keywords = [
        "attack",
        "malicious",
        "failed",
        "brute",
        "suspicious",
        "sql injection",
        "xss",
        "credential",
        "blocked",
        "unauthorized",
    ]

    count = 0

    for log in logs:
        log_lower = log.lower()

        if any(keyword in log_lower for keyword in attack_keywords):
            count += 1

    return count


def extract_ips(logs):
    """Extract IPv4 addresses from logs."""

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    ips = []

    for log in logs:
        found = re.findall(ip_pattern, log)

        for ip in found:
            ips.append(ip)

    return ips


def extract_countries(logs):
    """Try to detect countries from log text."""

    countries = [
        "India",
        "United States",
        "USA",
        "UK",
        "United Kingdom",
        "Germany",
        "France",
        "Canada",
        "Australia",
        "Singapore",
        "China",
        "Japan",
        "Russia",
    ]

    detected = []

    for log in logs:
        for country in countries:
            if country.lower() in log.lower():
                detected.append(country)

    return detected


# ============================================================
# CALCULATE DASHBOARD VALUES
# ============================================================

total_login_attempts = len(logs)

total_attacks = count_attacks(logs)

ips = extract_ips(logs)

countries = extract_countries(logs)

# Simple AI prediction placeholder
if total_attacks > 0:
    ai_prediction = "Attack Detected"
else:
    ai_prediction = "Normal"

# Threat level
if total_attacks >= 50:
    threat_level = "CRITICAL"
elif total_attacks >= 20:
    threat_level = "HIGH"
elif total_attacks >= 5:
    threat_level = "MEDIUM"
else:
    threat_level = "LOW"

# ============================================================
# KPI CARDS
# ============================================================

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="🔐 Total Login Attempts",
        value=total_login_attempts,
    )

with col2:
    st.metric(
        label="🚨 Total Attacks",
        value=total_attacks,
    )

with col3:
    st.metric(
        label="🤖 AI Prediction",
        value=ai_prediction,
    )

with col4:
    st.metric(
        label="⚠️ Threat Level",
        value=threat_level,
    )

st.divider()

# ============================================================
# ATTACK TIMELINE
# ============================================================

st.subheader("📈 Attack Timeline")

if logs:

    timeline_data = pd.DataFrame(
        {
            "Event": range(1, len(logs) + 1),
            "Login Attempts": range(1, len(logs) + 1),
        }
    )

    fig = px.line(
        timeline_data,
        x="Event",
        y="Login Attempts",
        markers=True,
        title="Login / Attack Activity",
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )

else:
    st.info("No traffic data available yet.")

# ============================================================
# TOP COUNTRIES
# ============================================================

col1, col2 = st.columns(2)

with col1:

    st.subheader("🌍 Top Countries")

    if countries:

        country_counts = (
            pd.Series(countries)
            .value_counts()
            .reset_index()
        )

        country_counts.columns = [
            "Country",
            "Attacks",
        ]

        fig_country = px.bar(
            country_counts,
            x="Country",
            y="Attacks",
            title="Traffic by Country",
        )

        st.plotly_chart(
            fig_country,
            use_container_width=True,
        )

    else:
        st.info(
            "Country information is not available in the current log format."
        )

# ============================================================
# AI PREDICTION
# ============================================================

with col2:

    st.subheader("🤖 AI Predictions")

    prediction_data = pd.DataFrame(
        {
            "Prediction": [
                "Attack",
                "Suspicious",
                "Normal",
            ],
            "Count": [
                total_attacks,
                max(0, total_login_attempts - total_attacks),
                0,
            ],
        }
    )

    fig_ai = px.pie(
        prediction_data,
        names="Prediction",
        values="Count",
        title="AI Detection Results",
    )

    st.plotly_chart(
        fig_ai,
        use_container_width=True,
    )

# ============================================================
# LIVE LOGIN LOGS
# ============================================================

st.divider()

st.subheader("🔴 Live Login Logs")

if logs:

    recent_logs = logs[-20:]

    log_data = pd.DataFrame(
        {
            "Log": recent_logs,
        }
    )

    st.dataframe(
        log_data,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info("No login logs found.")

# ============================================================
# IP INFORMATION
# ============================================================

st.subheader("🌐 Detected IP Addresses")

if ips:

    ip_counts = (
        pd.Series(ips)
        .value_counts()
        .reset_index()
    )

    ip_counts.columns = [
        "IP Address",
        "Attempts",
    ]

    st.dataframe(
        ip_counts.head(20),
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info("No IP addresses detected in the logs.")

# ============================================================
# THREAT INTELLIGENCE
# ============================================================

st.divider()

st.subheader("🚨 Threat Intelligence")

threat_data = pd.DataFrame(
    {
        "Threat": [
            "Brute Force",
            "Credential Attack",
            "Suspicious Login",
        ],
        "Status": [
            "Monitoring",
            "Monitoring",
            "Monitoring",
        ],
        "Severity": [
            "High",
            "High",
            threat_level,
        ],
    }
)

st.dataframe(
    threat_data,
    use_container_width=True,
    hide_index=True,
)

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("🛡️ Honeypot Controls")

    st.write(
        f"**Log file:** `{LOG_FILE.name}`"
    )

    st.write(
        f"**Total logs:** {total_login_attempts}"
    )

    st.write(
        f"**Detected attacks:** {total_attacks}"
    )

    st.write(
        f"**Threat level:** {threat_level}"
    )

    st.divider()

    if st.button("🔄 Refresh Dashboard"):

        st.rerun()

    st.caption(
        f"Last checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )