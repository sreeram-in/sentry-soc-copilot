const form = document.getElementById("chat-form");
const input = document.getElementById("chat-input");
const sendBtn = document.getElementById("chat-send");
const ALERT_ID = form.dataset.alertId;

function fmt(text) {
  try {
    return (typeof window.sentryFormat === "function") ? window.sentryFormat(text) : text;
  } catch (e) {
    return text;
  }
}

function appendMsg(role, content, isHtml = false) {
  const hist = document.getElementById("chat-history");
  const hint = hist.querySelector(".chat-hint");
  if (hint) hint.remove();
  const div = document.createElement("div");
  div.className = `chat-msg chat-${role}`;
  if (isHtml) div.innerHTML = content;
  else div.textContent = content;
  hist.appendChild(div);
  hist.scrollTop = hist.scrollHeight;
  return div;
}

async function send() {
  const text = input.value.trim();
  if (!text) return;
  appendMsg("user", text);
  input.value = "";
  input.disabled = true;
  sendBtn.disabled = true;
  const pending = appendMsg("assistant", "Thinking...");

  try {
    const res = await fetch(`/api/chat/${ALERT_ID}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text }),
    });
    const data = await res.json();
    if (data.reply) {
      pending.innerHTML = fmt(data.reply);
    } else {
      pending.textContent = "Error: " + (data.error || "no response");
    }
  } catch (e) {
    pending.textContent = "Request failed -- check that the Flask server is still running.";
  }
  input.disabled = false;
  sendBtn.disabled = false;
  input.focus();
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  send();
});

try {
  document.querySelectorAll("#chat-history .chat-assistant").forEach((el) => {
    el.innerHTML = fmt(el.textContent);
  });
} catch (e) { /* non-fatal */ }

document.getElementById("chat-history").scrollTop = 1e9;