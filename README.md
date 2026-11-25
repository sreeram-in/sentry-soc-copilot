# SENTRY SOC Copilot

**A local-first network intrusion detection dashboard for live traffic analysis, explainable alerts, and AI-assisted SOC workflows.**

SENTRY captures network flows from a selected interface, classifies suspicious activity with machine-learning and behavioral rules, and presents findings in a Flask dashboard. Optional Groq-powered chat and report summaries help analysts investigate detections.

> **Use responsibly:** Capture only traffic you own or are authorized to monitor. SENTRY is an educational and analysis tool, not a replacement for a professionally managed security monitoring system. Model predictions can be wrong.

## Features

- Live packet capture and flow analysis using Scapy/Npcap.
- Supervised classification, Isolation Forest anomaly detection, and behavioral detection rules.
- Dashboard for live flows, alerts, interface status, and model evaluation.
- Alert-specific and general AI chat, plus PDF reports.
- SQLite persistence for alert and conversation history.

## Requirements

- Python 3.11 or newer.
- Windows users: Npcap for live packet capture; administrator privileges may be needed for the selected interface.
- CICIDS2017 and/or CICIDS2018 flow datasets for model training if a compatible trained model is not already available.
- Optional Groq API key for AI chat and generated report narratives.

## Run locally

1. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env`. Add a Groq API key only if you want to use AI features.
4. Put compatible CICIDS datasets in `data/` if model training is required.
5. Start the server:

   ```powershell
   python app.py
   ```

6. Open <http://127.0.0.1:5000>.

The application binds to localhost by default. Do not expose it directly to the public internet: authentication and user/role authorization are not implemented. For production, deploy behind an appropriately configured HTTPS reverse proxy, set `FLASK_ENV=production`, `SENTRY_SESSION_SECRET`, and `SENTRY_TRUSTED_ORIGINS`, and add an authentication layer.

## Configuration

| Variable | Purpose |
| --- | --- |
| `GROQ_API_KEY` | Optional key for AI chat and report generation. |
| `GROQ_REPORT_API_KEY` | Optional separate key for report narratives; falls back to `GROQ_API_KEY`. |
| `SENTRY_SESSION_SECRET` | Required for production session signing; generate a strong random value and keep it private. |
| `SENTRY_TRUSTED_ORIGINS` | Comma-separated trusted origins for production deployments. |
| `FLASK_ENV` | Set to `production` when served over HTTPS in production. |

Never commit `.env`, API keys, trained model files, packet captures, datasets, or runtime database/log data.

## Project layout

```text
app.py             Flask routes and application setup
capture.py         Packet capture and flow extraction
model.py           Classification and anomaly-detection pipeline
rules.py           Behavioral detection rules
storage.py         SQLite persistence
llm_chat.py        Optional Groq integration
templates/         Server-rendered HTML pages
static/            CSS and browser JavaScript
data/              Local datasets, model, and database (not committed)
data_out/          Local capture logs (not committed)
```
