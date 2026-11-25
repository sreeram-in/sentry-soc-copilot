"""Groq chat helpers. Raises LLMError on failure so errors are never saved as chat.

Uses two separate keys:
  GROQ_API_KEY         -- per-alert chat + general chat
  GROQ_REPORT_API_KEY  -- report narratives (falls back to GROQ_API_KEY if unset)
"""
import os

import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODELS = ["openai/gpt-oss-120b", "openai/gpt-oss-20b"]
_working_model = None


class LLMError(Exception):
    pass


def _clean(key):
    return (key or "").strip().strip('"').strip("'")


def _chat_key():
    return _clean(os.getenv("GROQ_API_KEY", ""))


def _report_key():
    return _clean(os.getenv("GROQ_REPORT_API_KEY", "")) or _chat_key()


def _call_groq(messages, api_key, max_tokens=600, temperature=0.3):
    global _working_model
    if not api_key or api_key in ("paste_your_new_key_here", ""):
        raise LLMError(
            "Groq API key missing. Put GROQ_API_KEY=... (and optionally "
            "GROQ_REPORT_API_KEY=...) in the .env file and restart app.py."
        )

    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }
    order = ([_working_model] if _working_model else []) + [m for m in MODELS if m != _working_model]
    last = ""

    for model in order:
        payload = {"model": model, "messages": messages,
                   "max_tokens": max_tokens, "temperature": temperature}
        try:
            r = requests.post(GROQ_URL, headers=headers, json=payload, timeout=30)
        except requests.RequestException as e:
            last = f"network error: {e}"
            continue

        if r.status_code == 200:
            try:
                text = r.json()["choices"][0]["message"]["content"].strip()
            except Exception:
                last = "unexpected response format"
                continue
            _working_model = model
            return text
        if r.status_code in (401, 403):
            raise LLMError(f"Groq rejected the API key ({r.status_code}). "
                           "Check it in .env for typos or extra spaces.")
        last = f"HTTP {r.status_code}: {r.text[:200]}"

    raise LLMError(f"Groq request failed on all models: {last}")


def _clean_history(history, limit=10):
    return [{"role": m["role"], "content": m["content"]}
            for m in history[-limit:]
            if m.get("role") in ("user", "assistant") and m.get("content")]


def _alert_context(a):
    feats = ", ".join(f"{f['feature']}={f['impact']}" for f in a.get("top_features", []))
    return (
        f"Alert #{a.get('id')} at {a.get('time')}\n"
        f"Flow: {a.get('src')} -> {a.get('dst')} ({a.get('protocol')})\n"
        f"Classification: {a.get('label')} (confidence {a.get('confidence')}%)\n"
        f"Flagged as attack: {a.get('is_attack')} | anomaly: {a.get('is_anomaly')} "
        f"(anomaly score {a.get('anomaly_score')})\n"
        f"Most influential features: {feats or 'n/a'}"
    )


SYSTEM_STYLE = (
    "Keep answers concise and well-structured: short paragraphs, '## Heading' for "
    "section titles, '-' for bullet lists, '**word**' only for genuinely key terms. "
    "Never use tables."
)


def chat_about_alert(alert, history, user_message):
    messages = [
        {"role": "system", "content":
            "You are SENTRY SOC Copilot, an expert network security analyst. Explain "
            "detections clearly and concisely. Note that detections can be false positives. "
            + SYSTEM_STYLE},
        {"role": "system", "content": "Alert context:\n" + _alert_context(alert)},
    ] + _clean_history(history) + [{"role": "user", "content": user_message}]
    return _call_groq(messages, _chat_key(), max_tokens=500, temperature=0.3)


def general_chat(history, user_message):
    messages = [{"role": "system", "content":
                 "You are SENTRY SOC Copilot, a helpful network security assistant. Answer "
                 "questions on networking, cybersecurity, threat mitigation and NIDS concepts. "
                 + SYSTEM_STYLE}]
    messages += _clean_history(history) + [{"role": "user", "content": user_message}]
    return _call_groq(messages, _chat_key(), max_tokens=600, temperature=0.4)


def report_for_alert(alert):
    messages = [
        {"role": "system", "content":
            "You are a SOC analyst writing a short incident report (what happened, likely "
            "meaning, recommended actions, and a note on possible false positive). Under "
            "150 words. " + SYSTEM_STYLE},
        {"role": "user", "content": _alert_context(alert)},
    ]
    return _call_groq(messages, _report_key(), max_tokens=400, temperature=0.3)


def summarize_session(stats):
    ips = ", ".join(f"{ip} ({c})" for ip, c in stats["top_source_ips"]) or "none"
    cats = ", ".join(f"{k}: {v}" for k, v in stats["by_label"].items()) or "none"
    messages = [
        {"role": "system", "content":
            "You are a SOC analyst. Summarize this monitoring session in 3-5 sentences and "
            "give one recommendation. " + SYSTEM_STYLE},
        {"role": "user", "content":
            f"Flows analyzed: {stats['total_flows']}\nFlagged: {stats['total_flagged']}\n"
            f"By category: {cats}\nTop source IPs: {ips}"},
    ]
    return _call_groq(messages, _report_key(), max_tokens=300, temperature=0.3)
