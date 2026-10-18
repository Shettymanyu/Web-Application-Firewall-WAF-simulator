let logEntries = [];
let logFilterSeverity = "";
let logFilterAction = "";

function severityBadge(sev) {
  const map = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
  };
  const cls = map[sev] || "bg-gray-700 text-gray-300";
  return `<span class="px-1.5 py-0.5 rounded text-xs font-semibold ${cls}">${(sev || "—").toUpperCase()}</span>`;
}

function actionBadge(action) {
  const cls = action === "BLOCKED" ? "badge-blocked" : "badge-allowed";
  return `<span class="px-1.5 py-0.5 rounded text-xs font-semibold ${cls}">${action}</span>`;
}

function renderLogRow(entry) {
  const tr = document.createElement("tr");
  tr.className = `slide-in border-b border-gray-800/50 ${entry.action === "BLOCKED" ? "row-blocked" : "row-allowed"}`;
  const path = entry.path.length > 28 ? entry.path.slice(0, 28) + "…" : entry.path;
  const ruleCell = entry.rule_id
    ? `<span class="font-mono text-xs text-gray-400">${entry.rule_id}</span>`
    : `<span class="text-gray-600">—</span>`;
  tr.innerHTML = `
    <td class="py-1.5 pr-3 text-gray-500 whitespace-nowrap">${entry.timestamp_str}</td>
    <td class="py-1.5 pr-3 font-mono text-gray-400 whitespace-nowrap">${entry.ip}</td>
    <td class="py-1.5 pr-3 font-mono text-blue-400 whitespace-nowrap">${entry.method}</td>
    <td class="py-1.5 pr-3 font-mono text-gray-300 max-w-[160px] truncate" title="${entry.path}">${path}</td>
    <td class="py-1.5 pr-3 whitespace-nowrap">${actionBadge(entry.action)}</td>
    <td class="py-1.5 pr-3 whitespace-nowrap">${ruleCell}</td>
    <td class="py-1.5">${entry.severity ? severityBadge(entry.severity) : '<span class="text-gray-600">—</span>'}</td>
  `;
  return tr;
}

function rebuildLogTable() {
  const tbody = document.getElementById("log-tbody");
  if (!tbody) return;
  let filtered = logEntries;
  if (logFilterSeverity) filtered = filtered.filter(e => e.severity === logFilterSeverity);
  if (logFilterAction) filtered = filtered.filter(e => e.action === logFilterAction);

  tbody.innerHTML = "";
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-gray-600 py-8">No entries match filter</td></tr>`;
  } else {
    filtered.slice(0, 200).forEach(e => tbody.appendChild(renderLogRow(e)));
  }
  const countEl = document.getElementById("log-count");
  if (countEl) countEl.textContent = `${filtered.length} entr${filtered.length === 1 ? "y" : "ies"}`;
}

function prependLogEntry(entry) {
  logEntries.unshift(entry);
  if (logEntries.length > 500) logEntries.pop();
  rebuildLogTable();
}

function initAttackLog() {
  // Load initial logs
  fetch("/dashboard/api/logs?limit=50")
    .then(r => r.json())
    .then(data => {
      logEntries = data;
      rebuildLogTable();
    })
    .catch(() => {});

  // SSE live stream
  const evtSource = new EventSource("/dashboard/api/stream");
  evtSource.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "log") {
      prependLogEntry(msg.entry);
    }
  };
  evtSource.onerror = () => {
    setTimeout(() => initAttackLog(), 3000);
  };

  // Filters
  document.getElementById("log-severity-filter")?.addEventListener("change", (e) => {
    logFilterSeverity = e.target.value;
    rebuildLogTable();
  });
  document.getElementById("log-action-filter")?.addEventListener("change", (e) => {
    logFilterAction = e.target.value;
    rebuildLogTable();
  });
  document.getElementById("log-clear-btn")?.addEventListener("click", () => {
    logEntries = [];
    rebuildLogTable();
  });
}

