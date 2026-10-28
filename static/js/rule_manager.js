let rulesData = [];

function severityClass(sev) {
  return { critical: "badge-critical", high: "badge-high", medium: "badge-medium", low: "badge-low" }[sev]
    || "bg-gray-700 text-gray-300";
}

function renderRules(rules) {
  const container = document.getElementById("rules-list");
  if (!container) return;
  container.innerHTML = "";

  rules.forEach(rule => {
    const card = document.createElement("div");
    card.className = `flex items-start gap-3 p-3 rounded-xl border transition-all ${
      rule.enabled ? "border-gray-700 bg-gray-800/40" : "border-gray-800 bg-gray-900/20 opacity-60"
    }`;
    card.id = `rule-card-${rule.rule_id}`;

    card.innerHTML = `
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2 flex-wrap mb-0.5">
          <span class="font-mono text-xs text-gray-500">${rule.rule_id}</span>
          <span class="font-semibold text-sm">${rule.name}</span>
          <span class="px-1.5 py-0.5 rounded text-xs font-semibold ${severityClass(rule.severity)}">${rule.severity.toUpperCase()}</span>
        </div>
        <div class="text-xs text-gray-500 leading-relaxed">${rule.description}</div>
      </div>
      <div class="flex-shrink-0 pt-0.5">
        <button
          class="toggle-btn relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${
            rule.enabled ? "bg-blue-600" : "bg-gray-600"
          }"
          data-rule-id="${rule.rule_id}"
          data-enabled="${rule.enabled}"
          title="${rule.enabled ? "Click to disable" : "Click to enable"}"
          aria-label="Toggle ${rule.name}"
        >
          <span class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            rule.enabled ? "translate-x-6" : "translate-x-1"
          }"></span>
        </button>
      </div>
    `;
    container.appendChild(card);
  });

  // Attach toggle listeners
  container.querySelectorAll(".toggle-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const ruleId = btn.dataset.ruleId;
      toggleRule(ruleId, btn);
    });
  });
}

function toggleRule(ruleId, btn) {
  btn.disabled = true;
  btn.style.opacity = "0.5";

  fetch(`/dashboard/api/rules/${ruleId}/toggle`, { method: "POST" })
    .then(r => r.json())
    .then(data => {
      // Update local data
      const rule = rulesData.find(r => r.rule_id === ruleId);
      if (rule) rule.enabled = data.enabled;
      renderRules(rulesData);
    })
    .catch(() => {
      btn.disabled = false;
      btn.style.opacity = "1";
    });
}

function initRuleManager() {
  fetch("/dashboard/api/rules")
    .then(r => r.json())
    .then(rules => {
      rulesData = rules;
      renderRules(rules);
    })
    .catch(() => {});
}
