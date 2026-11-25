const POLL_MS = 2000;
const seenIds = new Set();
let capturing = false;
let btnBusy = false;

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtUptime(sec) {
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function scanRow(a) {
  const el = document.createElement("div");
  el.className = "alert-row compact";
  const tagClass = a.is_attack ? "attack" : "benign";
  el.innerHTML = `
    <div class="row-top">
      <span class="flow-line"><b>${escapeHtml(a.time)}</b> &nbsp; ${escapeHtml(a.src)} &rarr; ${escapeHtml(a.dst)} &nbsp; ${escapeHtml(a.protocol)}</span>
      <span><span class="tag ${tagClass}">${a.is_attack ? a.label : "Normal"}</span> <span class="flow-line">conf ${a.confidence}%</span></span>
    </div>`;
  return el;
}

function detectRow(a) {
  const el = document.createElement("div");
  el.className = "alert-row";
  const anomalyTag = a.is_anomaly ? `<span class="tag anomaly">anomaly</span>` : "";
  const features = a.top_features.map(f => `<b>${escapeHtml(f.feature)}</b> (${escapeHtml(f.impact)})`).join(" &middot; ");
  el.innerHTML = `
    <div class="row-top">
      <span class="flow-line"><b>${escapeHtml(a.time)}</b> &nbsp; ${escapeHtml(a.src)} &rarr; ${escapeHtml(a.dst)} &nbsp; ${escapeHtml(a.protocol)}</span>
      <span><span class="tag attack">${escapeHtml(a.is_attack ? a.label : "Unusual")}</span>${anomalyTag} <span class="flow-line">conf ${escapeHtml(a.confidence)}%</span></span>
    </div>
    <div class="features">top features: ${features}</div>
    <a class="ask-ai-btn" href="/chat/${a.id}">ASK AI &rarr;</a>`;
  return el;
}

function addBlip(isAttack) {
  const g = document.getElementById("radar-blips");
  if (!g) return;
  const angle = Math.random() * Math.PI * 2;
  const dist = 15 + Math.random() * 80;
  const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  dot.setAttribute("cx", 110 + Math.cos(angle) * dist);
  dot.setAttribute("cy", 110 + Math.sin(angle) * dist);
  dot.setAttribute("r", 4);
  dot.setAttribute("class", "radar-blip" + (isAttack ? " attack" : ""));
  g.appendChild(dot);
  setTimeout(() => dot.remove(), 3200);
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function syncButton() {
  const btn = document.getElementById("capture-btn");
  if (!btn || btnBusy) return;
  btn.textContent = capturing ? "STOP CAPTURE" : "START CAPTURE";
  btn.classList.toggle("stop", capturing);
}

function refresh() {
  fetch("/api/state")
    .then(r => r.json())
    .then(data => {
      setText("stat-flows", data.stats.flows_analyzed);
      setText("stat-threats", data.stats.threats_detected);
      setText("stat-uptime", fmtUptime(data.stats.uptime_seconds));

      capturing = data.capture.running;   // stays correct after a page refresh
      syncButton();

      const scanFeed = document.getElementById("scan-feed");
      if (scanFeed) {
        scanFeed.innerHTML = "";
        data.scan.slice(0, 40).forEach(a => scanFeed.appendChild(scanRow(a)));
      }

      const detectFeed = document.getElementById("detect-feed");
      setText("detected-count", data.detected.length);
      if (detectFeed) {
        if (data.detected.length === 0) {
          detectFeed.innerHTML = `<p class="empty-note">No anomalies detected yet. Start capture and generate some traffic to see real detections here.</p>`;
        } else {
          detectFeed.innerHTML = "";
          data.detected.slice(0, 40).forEach(a => detectFeed.appendChild(detectRow(a)));
        }
      }

      data.scan.slice(0, 5).forEach(a => {
        if (!seenIds.has(a.id)) {
          seenIds.add(a.id);
          addBlip(a.is_attack);
        }
      });
    })
    .catch(err => console.error("state fetch failed:", err));
}

function loadInterfaces() {
  fetch("/api/interfaces")
    .then(r => r.json())
    .then(data => {
      const sel = document.getElementById("iface-select");
      sel.innerHTML = "";
      if (!data.interfaces || data.interfaces.length === 0) {
        sel.innerHTML = `<option value="">(default interface)</option>`;
        return;
      }
      data.interfaces.forEach(item => {
        const opt = document.createElement("option");
        opt.value = item.value;
        opt.textContent = item.label;
        sel.appendChild(opt);
      });
    })
    .catch(() => {
      document.getElementById("iface-select").innerHTML = `<option value="">(default interface)</option>`;
    });
}

function setupCaptureButton() {
  const btn = document.getElementById("capture-btn");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const msg = document.getElementById("capture-msg");
    const iface = document.getElementById("iface-select").value;
    btnBusy = true;

    if (!capturing) {
      btn.textContent = "STARTING...";
      fetch("/api/capture/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: iface || null }),
      })
        .then(r => r.json())
        .then(data => {
          capturing = !!data.ok;
          msg.textContent = data.ok ? "" : (data.error || "Failed to start capture.");
          msg.classList.toggle("err", !data.ok);
        })
        .catch(e => {
          capturing = false;
          msg.textContent = "Request failed: " + e;
          msg.classList.add("err");
        })
        .finally(() => { btnBusy = false; syncButton(); });
    } else {
      fetch("/api/capture/stop", { method: "POST" })
        .then(() => { capturing = false; })
        .finally(() => { btnBusy = false; syncButton(); });
    }
  });
}

function drawRadarTicks() {
  const g = document.getElementById("radar-ticks-group");
  if (!g) return;
  for (let i = 0; i < 24; i++) {
    const a = (i * 15) * Math.PI / 180;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", (110 + 100 * Math.sin(a)).toFixed(1));
    line.setAttribute("y1", (110 - 100 * Math.cos(a)).toFixed(1));
    line.setAttribute("x2", (110 + 92 * Math.sin(a)).toFixed(1));
    line.setAttribute("y2", (110 - 92 * Math.cos(a)).toFixed(1));
    line.setAttribute("class", "radar-tick-mark");
    g.appendChild(line);
  }
}

function updateRadarClock() {
  const el = document.getElementById("radar-clock");
  if (el) el.textContent = new Date().toTimeString().slice(0, 8);
}

document.addEventListener("DOMContentLoaded", () => {
  loadInterfaces();
  setupCaptureButton();
  drawRadarTicks();
  updateRadarClock();
  setInterval(updateRadarClock, 1000);
  refresh();
  setInterval(refresh, POLL_MS);
});