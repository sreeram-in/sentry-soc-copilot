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

## Install prerequisites (Windows)

1. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/) or with Windows Package Manager:

   ```powershell
   winget install --id Python.Python.3.11 -e
   ```

   Close and reopen PowerShell afterward, then check `py --version`.

2. Install [Npcap](https://npcap.com/#download) if you need live packet capture. Use the official installer and its default compatibility options. Capture only interfaces and traffic you are authorized to monitor. Run the application with the minimum permissions required by your selected interface.
3. Optional: create a Groq account/API key only if you want AI chat and narrative reports. Keep keys in your local `.env`; never add them to source control.
4. Optional for the separate Java CLI: install JDK 17 and Maven. These are not required to run the Flask website.

## Install and run SENTRY

From PowerShell in the project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open <http://127.0.0.1:5000>. Add a Groq key to `.env` only if you intend to use AI features. Put compatible CICIDS2017 and/or CICIDS2018 flow datasets in `data/` if model training is required. Dataset files, trained models, captures, databases, and `.env` are intentionally excluded from the public repository.

The app binds to localhost by default. Authentication and user/role authorization are not implemented, so do not expose it directly to the public internet. For a production deployment, use a properly configured HTTPS reverse proxy, set `FLASK_ENV=production`, `SENTRY_SESSION_SECRET`, and `SENTRY_TRUSTED_ORIGINS`, and add authentication and authorization.

## Safe validation

- Keep Windows Firewall enabled. SENTRY does not require disabling the firewall for ordinary local operation.
- For a safe smoke test, open the dashboard and check that its status endpoint responds:

  ```powershell
  Invoke-RestMethod http://127.0.0.1:5000/api/status
  ```

- To evaluate detection quality, use the included model-evaluation page and authorized, labeled CICIDS datasets in a controlled environment. Use offline/replay evaluation or a dedicated isolated lab you own; do not generate attack traffic against public networks, third-party systems, or devices without explicit authorization.
- Stop live capture when testing is finished. Do not weaken host protections or expose the development server to the internet.

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
