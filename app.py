import io
import os
import queue
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from secrets import token_hex

from flask import Flask, jsonify, make_response, render_template, request, send_file, session, url_for

import llm_chat
from capture import FlowSniffer, list_interfaces
from live_log import LiveLogger
from model import SOCModel
from report_pdf import build_report_pdf
from rules import RuleDetector
from storage import AlertStorage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MIN_ATTACK_CONFIDENCE = 95.0   # ML labels below this are treated as Normal (live-feature domain shift)
MIN_PKTS_FOR_ANOMALY = 2
DEBUG_FLOWS = os.getenv("SENTRY_DEBUG") == "1"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.config["SECRET_KEY"] = os.getenv("SENTRY_SESSION_SECRET") or os.getenv("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    app.config["SECRET_KEY"] = token_hex(32) if os.getenv("FLASK_ENV") != "production" else None
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SENTRY_SESSION_SECRET must be set when running in production.")
app.config["TRUSTED_ORIGINS"] = {
    origin.strip().rstrip("/")
    for origin in os.getenv("SENTRY_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
}
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"

# Small in-process abuse controls. In a multi-process deployment, replace with
# a shared Redis-backed implementation.
_rate_lock = threading.Lock()
_rate_windows = defaultdict(list)


def rate_limit(limit, window_seconds, key_prefix):
    def decorator(fn):
        def wrapped(*args, **kwargs):
            now = time.time()
            key = f"{key_prefix}:{request.remote_addr}"
            with _rate_lock:
                calls = [stamp for stamp in _rate_windows[key] if now - stamp < window_seconds]
                if len(calls) >= limit:
                    _rate_windows[key] = calls
                    return jsonify({"error": "Too many requests. Please wait and try again."}), 429
                calls.append(now)
                _rate_windows[key] = calls
            return fn(*args, **kwargs)
        wrapped.__name__ = fn.__name__
        return wrapped
    return decorator


@app.before_request
def protect_requests():
    if not session.get("csrf_token"):
        session["csrf_token"] = token_hex(32)
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.mimetype not in (
        "application/json",
        "application/x-www-form-urlencoded",
    ):
        return jsonify({"error": "Unsupported content type."}), 415
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        supplied = request.headers.get("X-CSRF-Token")
        if not supplied or supplied != session["csrf_token"]:
            return jsonify({"error": "Invalid or missing CSRF token."}), 403
        origin = request.headers.get("Origin")
        if origin:
            expected = request.host_url.rstrip("/")
            trusted = app.config["TRUSTED_ORIGINS"]
            if origin.rstrip("/") != expected and origin.rstrip("/") not in trusted:
                return jsonify({"error": "Cross-origin requests are not allowed."}), 403


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if os.getenv("FLASK_ENV") == "production" or request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.context_processor
def site_context():
    titles = {
        "dashboard": ("SENTRY | Live Network Intrusion Feed", "Monitor live network flows and detect anomalous traffic with SENTRY."),
        "ai_index": ("SENTRY AI | SOC Security Assistant", "Chat with SENTRY AI and investigate detected network security alerts."),
        "chat_page": ("SENTRY AI | Alert Investigation", "Investigate a specific network intrusion alert with SENTRY AI."),
        "report": ("SENTRY | Security Reports", "Generate alert and session reports for network monitoring activity."),
        "model_eval": ("SENTRY | Model Evaluation", "Review SENTRY network intrusion model accuracy and performance metrics."),
        "about": ("About SENTRY | Network Intrusion Detection", "Learn how SENTRY captures, analyzes, and explains network security detections."),
    }
    title, description = titles.get(request.endpoint, ("SENTRY | SOC Copilot", "Network intrusion detection and security operations dashboard."))
    if request.endpoint in ("chat_page", "not_found"):
        canonical = url_for("dashboard", _external=True)
    else:
        canonical = url_for(request.endpoint, _external=True) if request.endpoint in titles else url_for("dashboard", _external=True)
    return {
        "csrf_token": session.get("csrf_token"),
        "page_title": title,
        "meta_description": description,
        "canonical_url": canonical,
        "noindex_page": request.endpoint == "chat_page",
        "current_year": datetime.now().year,
    }

db = AlertStorage(os.path.join(BASE_DIR, "data", "sentry.db"))
logger = LiveLogger(os.path.join(BASE_DIR, "data_out", "live_captured.csv"))
model = SOCModel()
rules = RuleDetector()
sniffer = None
start_time = time.time()
general_chat_history = []

flow_queue = queue.Queue(maxsize=3000)
dropped_flows = 0


# ---------------------------------------------------------------- pages
@app.route("/")
def dashboard():
    return render_template("dashboard.html", active="dashboard", backend=model.backend_name)


@app.route("/ai")
def ai_index():
    alerts = db.get_all_alerts()
    for a in alerts:
        a["message_count"] = len(db.get_chat_history(a["id"]))
    return render_template(
        "ai.html", active="ai", alerts=alerts,
        history=general_chat_history, backend=model.backend_name,
    )


@app.route("/chat/<int:aid>")
def chat_page(aid):
    alert = db.get_alert_by_id(aid)
    if not alert:
        return "Alert not found", 404
    return render_template("chat.html", active="ai", alert=alert,
                           history=db.get_chat_history(aid), backend=model.backend_name)


@app.route("/report")
def report():
    return render_template("report.html", active="report", backend=model.backend_name)


@app.route("/model-eval")
def model_eval():
    m = model.get_eval_metrics()
    return render_template(
        "model_eval.html", active="eval",
        eval_accuracy=m.get("accuracy", 0), eval_train_size=m.get("train_size", 0),
        eval_test_size=m.get("test_size", 0), eval_labels=m.get("labels", []),
        eval_report=m.get("report", {}), eval_confusion=m.get("confusion", []),
        backend=model.backend_name)


@app.route("/about")
def about():
    return render_template("about.html", active="about", backend=model.backend_name)


@app.route("/robots.txt")
def robots_txt():
    response = make_response(
        "User-agent: *\nAllow: /\n"
        f"Sitemap: {request.host_url.rstrip('/')}/sitemap.xml\n"
    )
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


@app.route("/sitemap.xml")
def sitemap_xml():
    entries = []
    for path in ("/", "/ai", "/report", "/model-eval", "/about"):
        entries.append(
            "<url><loc>" + request.host_url.rstrip("/") + path
            + "</loc><changefreq>weekly</changefreq></url>"
        )
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           + "".join(entries) + "</urlset>")
    response = make_response(xml)
    response.headers["Content-Type"] = "application/xml; charset=utf-8"
    return response


@app.route("/favicon.svg")
def favicon():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<rect width="64" height="64" rx="12" fill="#171615"/>'
        '<rect x="16" y="16" width="32" height="32" rx="7" fill="#E8590C"/>'
        '</svg>'
    )
    response = make_response(svg)
    response.headers["Content-Type"] = "image/svg+xml"
    return response


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html", active=None), 404


# ---------------------------------------------------------------- capture
def is_ignorable_traffic(f):
    return (f["dst_ip"] in ("224.0.0.251", "239.255.255.250", "255.255.255.255")
            or f["dst_port"] in (5353, 1900))


def process_flow(flow):
    if is_ignorable_traffic(flow):
        return

    pred = model.predict(flow)
    total_pkts = flow["tot_fwd_pkts"] + flow["tot_bwd_pkts"]
    hit = rules.observe(flow)

    if hit:
        # behaviour rule wins over the ML label
        is_attack, label, confidence = True, hit["label"], hit["confidence"]
        is_anomaly = False
        save = hit["new"]          # one alert per detection, flows of the same scan are only logged
    else:
        is_attack = bool(pred["is_attack"]) and pred["confidence"] >= MIN_ATTACK_CONFIDENCE
        label = pred["label"] if is_attack else "Normal"
        confidence = pred["confidence"]
        is_anomaly = bool(pred["is_anomaly"]) and total_pkts >= MIN_PKTS_FOR_ANOMALY
        save = is_attack or is_anomaly

    if DEBUG_FLOWS:
        print(f"[flow] {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} "
              f"{flow['proto']} pkts={flow['tot_fwd_pkts']}/{flow['tot_bwd_pkts']} "
              f"syn={flow['syn_cnt']} rst={flow['rst_cnt']} "
              f"=> model:{pred['label']} {pred['confidence']}% | rule:{hit['label'] if hit else '-'}"
              f"{' NEW ALERT: ' + hit['reason'] if hit and hit['new'] else ''}")

    rec = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "src": f"{flow['src_ip']}:{flow['src_port']}",
        "dst": f"{flow['dst_ip']}:{flow['dst_port']}",
        "protocol": flow["proto"].upper(),
        "label": label,
        "confidence": confidence,
        "is_attack": int(is_attack),
        "is_anomaly": int(is_anomaly),
        "anomaly_score": pred["anomaly_score"],
        "top_features": pred["top_features"],
    }
    logger.log_flow(rec)
    if save:
        db.save_alert(rec)


def on_flow_completed(flow):
    global dropped_flows
    try:
        flow_queue.put_nowait(flow)
    except queue.Full:
        dropped_flows += 1


def _worker():
    while True:
        flow = flow_queue.get()
        try:
            process_flow(flow)
        except Exception as e:
            print(f"[worker] flow processing error: {e}")


def _drain_queue():
    try:
        while True:
            flow_queue.get_nowait()
    except queue.Empty:
        pass


threading.Thread(target=_worker, daemon=True).start()


@app.route("/api/interfaces")
def get_interfaces():
    return jsonify({"interfaces": list_interfaces()})


@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    global sniffer, dropped_flows
    data = request.get_json(silent=True) or {}
    iface = data.get("interface") or None

    if sniffer and sniffer.running:
        return jsonify({"ok": False, "error": "Capture is already running."})
    if not model.ready:
        return jsonify({"ok": False,
                        "error": "No trained model. Put CICIDS CSVs in data/ and restart the app."})
    try:
        dropped_flows = 0
        s = FlowSniffer(interface=iface, flow_callback=on_flow_completed)
        s.start()
        sniffer = s
        return jsonify({"ok": True})
    except Exception as e:
        sniffer = None
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    global sniffer
    if sniffer:
        sniffer.stop()
        sniffer = None
    _drain_queue()
    return jsonify({"ok": True})


@app.route("/api/status")
def status():
    s = sniffer
    return jsonify({
        "running": bool(s and s.running),
        "active_flows": s.get_active_flow_count() if s else 0,
        "error": s.last_error if s else None,
        "queued": flow_queue.qsize(),
        "dropped": dropped_flows,
    })


@app.route("/api/state")
def get_state():
    s = sniffer
    return jsonify({
        "stats": {
            "flows_analyzed": logger.get_total_count(),
            "threats_detected": db.count(),
            "uptime_seconds": int(time.time() - start_time),
        },
        "capture": {
            "running": bool(s and s.running),
            "active_flows": s.get_active_flow_count() if s else 0,
            "error": s.last_error if s else None,
        },
        "scan": logger.get_recent_flows(limit=100),
        "detected": db.get_all_alerts(),
    })


# ---------------------------------------------------------------- chat
@app.route("/api/chat/<int:aid>", methods=["POST"])
@rate_limit(limit=20, window_seconds=60, key_prefix="chat")
def chat_alert(aid):
    alert = db.get_alert_by_id(aid)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    msg = (request.get_json(silent=True) or {}).get("message", "").strip()
    if not msg:
        return jsonify({"error": "Empty message"}), 400
    if len(msg) > 2000:
        return jsonify({"error": "Message is too long (maximum 2000 characters)."}), 400

    history = db.get_chat_history(aid)
    try:
        reply = llm_chat.chat_about_alert(alert, history, msg)
    except llm_chat.LLMError as e:
        return jsonify({"error": str(e)}), 502

    db.save_chat_message(aid, "user", msg)
    db.save_chat_message(aid, "assistant", reply)
    return jsonify({"reply": reply})


@app.route("/api/chat/general", methods=["POST"])
@rate_limit(limit=20, window_seconds=60, key_prefix="general-chat")
def chat_general():
    msg = (request.get_json(silent=True) or {}).get("message", "").strip()
    if not msg:
        return jsonify({"error": "Empty message"}), 400
    if len(msg) > 2000:
        return jsonify({"error": "Message is too long (maximum 2000 characters)."}), 400
    try:
        reply = llm_chat.general_chat(general_chat_history, msg)
    except llm_chat.LLMError as e:
        return jsonify({"error": str(e)}), 502

    general_chat_history.append({"role": "user", "content": msg})
    general_chat_history.append({"role": "assistant", "content": reply})
    del general_chat_history[:-40]
    return jsonify({"reply": reply})


@app.route("/api/chat/general/clear", methods=["POST"])
def clear_general_chat():
    general_chat_history.clear()
    return jsonify({"ok": True})


@app.route("/api/history/clear", methods=["POST"])
@rate_limit(limit=10, window_seconds=60, key_prefix="clear-history")
def clear_history():
    _drain_queue()
    db.clear_all()
    logger.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------- reports
def build_summary():
    alerts = db.get_all_alerts(limit=1000)

    by_label = Counter(a["label"] if a["is_attack"] else "Anomaly" for a in alerts)

    per_ip = defaultdict(lambda: {"risk": 0.0, "by_label": Counter()})
    for a in alerts:
        ip = a["src"].rsplit(":", 1)[0]
        weight = 3.0 if a["is_attack"] else 1.0
        per_ip[ip]["risk"] += weight * (a["confidence"] / 100.0)
        per_ip[ip]["by_label"][a["label"] if a["is_attack"] else "Anomaly"] += 1

    top_ips = Counter({ip: sum(v["by_label"].values()) for ip, v in per_ip.items()})
    stats = {
        "total_flows": logger.get_total_count(),
        "total_flagged": db.count(),
        "by_label": dict(by_label),
        "top_source_ips": [[ip, c] for ip, c in top_ips.most_common(5)],
    }
    leaderboard = sorted(
        ({"ip": ip, "risk_score": round(v["risk"], 1), "by_label": dict(v["by_label"])}
         for ip, v in per_ip.items()),
        key=lambda r: r["risk_score"], reverse=True)[:10]
    return stats, leaderboard


@app.route("/api/report/summary")
def report_summary():
    stats, leaderboard = build_summary()
    narrative, error = None, None
    if stats["total_flagged"] > 0:
        try:
            narrative = llm_chat.summarize_session(stats)
        except llm_chat.LLMError as e:
            error = str(e)
    return jsonify({"stats": stats, "leaderboard": leaderboard,
                    "narrative": narrative, "error": error})


@app.route("/api/report/alert/<int:aid>")
def report_alert(aid):
    alert = db.get_alert_by_id(aid)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    try:
        return jsonify({"narrative": llm_chat.report_for_alert(alert)})
    except llm_chat.LLMError as e:
        return jsonify({"narrative": None, "error": str(e)})


@app.route("/api/report/pdf")
def report_pdf():
    stats, leaderboard = build_summary()
    narrative = None
    if stats["total_flagged"] > 0:
        try:
            narrative = llm_chat.summarize_session(stats)
        except llm_chat.LLMError:
            pass
    alerts = db.get_all_alerts(limit=1000)
    pdf = build_report_pdf(stats, narrative, leaderboard, alerts)
    return send_file(io.BytesIO(pdf), mimetype="application/pdf",
                     as_attachment=True, download_name="sentry_report.pdf")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)