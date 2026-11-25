function loadAlertOptions() {
  const sel = document.getElementById("alert-select");
  if (!sel) return;
  fetch("/api/state")
    .then(r => r.json())
    .then(data => {
      sel.innerHTML = "";
      if (!data.detected || data.detected.length === 0) {
        sel.innerHTML = `<option value="">No detected alerts yet</option>`;
        return;
      }
      data.detected.forEach(a => {
        const opt = document.createElement("option");
        opt.value = a.id;
        opt.textContent = `#${a.id} -- ${a.time} -- ${a.is_attack ? a.label : "Anomaly"} (${a.src} -> ${a.dst})`;
        sel.appendChild(opt);
      });
    })
    .catch(() => {
      sel.innerHTML = `<option value="">Couldn't load alerts</option>`;
    });
}

document.getElementById("gen-alert-report-btn").addEventListener("click", () => {
  const aid = document.getElementById("alert-select").value;
  const btn = document.getElementById("gen-alert-report-btn");
  if (!aid) return;
  btn.textContent = "GENERATING...";
  fetch(`/api/report/alert/${aid}`)
    .then(r => r.json())
    .then(data => {
      document.getElementById("alert-report-body").style.display = "block";
      const el = document.getElementById("alert-report-text");
      if (data.narrative) {
        el.innerHTML = window.sentryFormat(data.narrative);
      } else {
        el.textContent = "Report unavailable: " + (data.error || "unknown error");
      }
      btn.textContent = "GENERATE";
    })
    .catch(() => { btn.textContent = "GENERATE (retry)"; });
});

document.getElementById("gen-report-btn").addEventListener("click", () => {
  const btn = document.getElementById("gen-report-btn");
  btn.textContent = "GENERATING...";
  fetch("/api/report/summary")
    .then(r => r.json())
    .then(data => {
      document.getElementById("report-body").style.display = "block";
      document.getElementById("r-total").textContent = data.stats.total_flows;
      document.getElementById("r-flagged").textContent = data.stats.total_flagged;

      const byLabel = document.getElementById("r-by-label");
      byLabel.innerHTML = "";
      const entries = Object.entries(data.stats.by_label);
      if (entries.length === 0) {
        byLabel.innerHTML = "<li>No flagged flows yet.</li>";
      } else {
        entries.forEach(([label, count]) => {
          const li = document.createElement("li");
          li.textContent = `${label}: ${count}`;
          byLabel.appendChild(li);
        });
      }

      const topIps = document.getElementById("r-top-ips");
      topIps.innerHTML = "";
      if (data.stats.top_source_ips.length === 0) {
        topIps.innerHTML = "<li>No flagged flows yet.</li>";
      } else {
        data.stats.top_source_ips.forEach(([ip, count]) => {
          const li = document.createElement("li");
          li.textContent = `${ip}: ${count} flagged flow(s)`;
          topIps.appendChild(li);
        });
      }

      const narrEl = document.getElementById("r-narrative");
      if (data.narrative) {
        narrEl.innerHTML = window.sentryFormat(data.narrative);
      } else {
        narrEl.textContent = data.error
          ? "AI summary unavailable: " + data.error
          : "Not enough flagged activity yet to summarize.";
      }
      btn.textContent = "REFRESH REPORT";
    })
    .catch(() => { btn.textContent = "GENERATE (retry)"; });
});

document.addEventListener("DOMContentLoaded", loadAlertOptions);