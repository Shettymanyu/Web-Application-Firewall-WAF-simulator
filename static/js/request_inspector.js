function initRequestInspector() {
  renderPayloadButtons();

  const form = document.getElementById("inspector-form");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btnText = document.getElementById("insp-btn-text");
    if (btnText) btnText.textContent = "Sending…";

    const method = document.getElementById("insp-method")?.value || "GET";
    const path = document.getElementById("insp-path")?.value || "/";
    const headersRaw = document.getElementById("insp-headers")?.value || "";
    const body = document.getElementById("insp-body")?.value || "";

    try {
      const res = await fetch("/dashboard/api/test-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ method, path, headers: headersRaw, body }),
      });
      const data = await res.json();
      showInspectorResult(data);
    } catch (err) {
      showInspectorError(err.message);
    } finally {
      if (btnText) btnText.textContent = "Send Request →";
    }
  });
}

function showInspectorResult(data) {
  const resultDiv = document.getElementById("inspector-result");
  const banner = document.getElementById("insp-result-banner");
  const details = document.getElementById("insp-result-details");
  if (!resultDiv || !banner || !details) return;

  resultDiv.classList.remove("hidden");

  if (data.action === "block") {
    banner.className = "px-4 py-3 font-bold text-sm flex items-center gap-2 bg-red-900/60 text-red-300";
    banner.innerHTML = `<span>🛡️</span> BLOCKED by WAF`;
  } else {
    banner.className = "px-4 py-3 font-bold text-sm flex items-center gap-2 bg-green-900/60 text-green-300";
    banner.innerHTML = `<span>✅</span> ALLOWED — Request would reach target app`;
  }

  const rows = [];
  if (data.rule_id) rows.push(detailRow("Rule ID", `<span class="font-mono text-yellow-400">${data.rule_id}</span>`));
  if (data.rule_name) rows.push(detailRow("Rule", `<span class="font-semibold">${data.rule_name}</span>`));
  if (data.severity) {
    const sevCls = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-blue-400" }[data.severity] || "";
    rows.push(detailRow("Severity", `<span class="${sevCls} font-semibold">${data.severity.toUpperCase()}</span>`));
  }
  if (data.matched_field) rows.push(detailRow("Matched Field", `<span class="font-mono text-purple-400">${data.matched_field}</span>`));
  if (data.pattern) rows.push(detailRow("Pattern", `<span class="text-gray-300">${data.pattern}</span>`));
  if (data.matched_value) {
    rows.push(`<div class="pt-1">
      <div class="text-gray-500 mb-1">Matched Value</div>
      <div class="font-mono text-xs bg-red-950/40 border border-red-900/50 px-3 py-2 rounded-lg text-red-300 break-all">${escHtml(data.matched_value.slice(0, 200))}</div>
    </div>`);
  }

  details.innerHTML = rows.length ? rows.join("") : `<div class="text-gray-500">No rule triggered — request is clean.</div>`;
}

function detailRow(label, valueHtml) {
  return `<div class="flex justify-between items-start gap-4">
    <span class="text-gray-500 flex-shrink-0">${label}</span>
    <span class="text-right">${valueHtml}</span>
  </div>`;
}

function showInspectorError(msg) {
  const resultDiv = document.getElementById("inspector-result");
  const banner = document.getElementById("insp-result-banner");
  const details = document.getElementById("insp-result-details");
  if (!resultDiv || !banner || !details) return;
  resultDiv.classList.remove("hidden");
  banner.className = "px-4 py-3 font-bold text-sm flex items-center gap-2 bg-yellow-900/60 text-yellow-300";
  banner.innerHTML = `<span>⚠️</span> Request Error`;
  details.innerHTML = `<div class="text-gray-400 text-xs">${escHtml(msg)}</div>`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
