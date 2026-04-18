const apiBase = "http://127.0.0.1:8000";

const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const injectBtn = document.getElementById("injectBtn");
const threatSelect = document.getElementById("threatSelect");
const canStream = document.getElementById("canStream");
const riskIndicator = document.getElementById("riskIndicator");
const riskReason = document.getElementById("riskReason");
const detectionPanel = document.getElementById("detectionPanel");
const threatDetails = document.getElementById("threatDetails");
const simStatus = document.getElementById("simStatus");

let threats = [];

async function callApi(path, method = "GET", body = null) {
  const response = await fetch(`${apiBase}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : null,
  });
  return response.json();
}

function appendStream(item) {
  const line = document.createElement("div");
  line.className = "stream-line";
  line.textContent = JSON.stringify(item);
  canStream.prepend(line);
  while (canStream.children.length > 80) {
    canStream.removeChild(canStream.lastChild);
  }
}

function setRisk(risk, reason) {
  riskIndicator.classList.remove("low", "medium", "high");
  riskIndicator.textContent = risk.toUpperCase();
  riskIndicator.classList.add(risk.toLowerCase());
  riskReason.textContent = reason || "No threats detected";
}

function renderThreatInfo(threat) {
  if (!threat) {
    threatDetails.innerHTML = "Select a threat scenario.";
    return;
  }
  threatDetails.innerHTML = `
    <strong>${threat.name}</strong><br>
    <strong>Entry Point:</strong> ${threat.entry_point}<br>
    <strong>Attack Path:</strong> ${threat.attack_path.join(" → ")}<br>
    <strong>Target Systems:</strong> ${threat.target_systems.join(", ")}
  `;
}

startBtn.onclick = async () => {
  await callApi("/api/simulation/start", "POST");
  simStatus.textContent = "Status: running";
};

stopBtn.onclick = async () => {
  await callApi("/api/simulation/stop", "POST");
  simStatus.textContent = "Status: stopped";
};

injectBtn.onclick = async () => {
  const slug = threatSelect.value;
  const result = await callApi("/api/attack/inject", "POST", { threat_slug: slug });
  if (result.active_threat) {
    renderThreatInfo(result.active_threat);
  }
};

threatSelect.onchange = () => {
  const threat = threats.find((t) => t.slug === threatSelect.value);
  renderThreatInfo(threat);
};

async function initThreats() {
  threats = await callApi("/api/threats");
  threats.forEach((threat) => {
    const opt = document.createElement("option");
    opt.value = threat.slug;
    opt.textContent = threat.name;
    threatSelect.appendChild(opt);
  });
  renderThreatInfo(threats[0]);
}

function connectWs() {
  const ws = new WebSocket("ws://127.0.0.1:8000/ws/stream");
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.kind === "can_message") {
      appendStream(msg.data);
    }
    if (msg.kind === "detection") {
      detectionPanel.textContent = JSON.stringify(msg.data, null, 2);
      setRisk(msg.data.risk || "Low", msg.data.reason);
    }
  };
  ws.onclose = () => setTimeout(connectWs, 1000);
}

initThreats();
connectWs();
