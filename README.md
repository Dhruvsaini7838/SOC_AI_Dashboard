# SOC AI Threat Intelligence Platform 🛡️

A Streamlit-powered SOC dashboard that ingests security log CSVs, **auto-maps columns**, runs **risk detections** (DDoS-like traffic, repeated failures, country risk), and presents an **executive intelligence** view with clear KPIs.

## ✨ Features

- **Upload any CSV** (firewall/SIEM/web logs) and get instant **validation + structure checks**
- **Smart column mapping** (IP, timestamp, event type, country, status) + synthetic fields when missing
- **Tunable detections** (sidebar sliders):
  - Multiple failed attempts (per ASN/IP)
  - DDoS-like requests per minute
  - Country failure-rate cutoff (high-risk tagging)
- **Executive KPIs**: Total Events, Critical Alerts, High/Medium Risk %, Unique Sources, Countries
- **Sample data generator** for demos (normalized hour/country/event distributions; intensity control)
- **Clean UI** with compact spacing, alert cards, and gradient theme

---

## 📦 Tech Stack

- **Python** (3.9+ recommended)
- **Streamlit**, **Pandas**, **NumPy**, **Plotly**

---

## 🚀 Quickstart

```bash
# 1) Clone
git clone https://github.com/Dhruvsaini7838/SOC_AI_Dashboard.git
cd SOC_AI_Dashboard

# 2) Create & activate a venv (recommended)
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# 3) Install deps
pip install -r requirements.txt

# 4) Run
streamlit run app.py
