let doughnutChart = null;
let lineChart = null;

const RULE_COLORS = {
  "WAF-001": "#f87171",
  "WAF-002": "#fb923c",
  "WAF-003": "#facc15",
  "WAF-004": "#c084fc",
  "WAF-005": "#34d399",
  "WAF-006": "#60a5fa",
};

const RULE_LABELS = {
  "WAF-001": "SQL Injection",
  "WAF-002": "XSS",
  "WAF-003": "Path Traversal",
  "WAF-004": "Cmd Injection",
  "WAF-005": "CSRF",
  "WAF-006": "Rate Limit",
};

function initCharts() {
  const dCtx = document.getElementById("chart-doughnut")?.getContext("2d");
  const lCtx = document.getElementById("chart-line")?.getContext("2d");
  if (!dCtx || !lCtx) return;

  Chart.defaults.color = "#6b7280";
  Chart.defaults.borderColor = "#1f2937";

  doughnutChart = new Chart(dCtx, {
    type: "doughnut",
    data: {
      labels: Object.values(RULE_LABELS),
      datasets: [{
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: Object.values(RULE_COLORS),
        borderWidth: 0,
        hoverOffset: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { boxWidth: 10, font: { size: 10 } } }
      },
      cutout: "65%",
    }
  });

  lineChart = new Chart(lCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Blocked",
          data: [],
          borderColor: "#f87171",
          backgroundColor: "rgba(248,113,113,0.1)",
          fill: true,
          tension: 0.3,
          pointRadius: 2,
        },
        {
          label: "Allowed",
          data: [],
          borderColor: "#34d399",
          backgroundColor: "rgba(52,211,153,0.08)",
          fill: true,
          tension: 0.3,
          pointRadius: 2,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { boxWidth: 10, font: { size: 10 } } } },
      scales: {
        x: { ticks: { font: { size: 9 }, maxTicksLimit: 6 } },
        y: { beginAtZero: true, ticks: { font: { size: 9 } } },
      }
    }
  });
}

function updateCharts() {
  fetch("/dashboard/api/stats")
    .then(r => r.json())
    .then(stats => {
      // Update stats bar
      document.getElementById("stat-total").textContent = stats.total_requests;
      document.getElementById("stat-blocked").textContent = stats.total_blocked;
      document.getElementById("stat-allowed").textContent = stats.total_allowed;
      document.getElementById("stat-block-rate").textContent = `${stats.block_rate}% block rate`;

      // Top threat
      const byRule = stats.by_rule || {};
      const topRuleId = Object.keys(byRule).sort((a, b) => byRule[b] - byRule[a])[0];
      document.getElementById("stat-top-threat").textContent =
        topRuleId ? (RULE_LABELS[topRuleId] || topRuleId) : "—";

      // Doughnut
      if (doughnutChart) {
        const ruleIds = Object.keys(RULE_LABELS);
        doughnutChart.data.datasets[0].data = ruleIds.map(id => byRule[id] || 0);
        doughnutChart.update("none");
      }

      // Line chart
      if (lineChart && stats.timeseries?.length) {
        const ts = stats.timeseries.slice(-20);
        lineChart.data.labels = ts.map(t => {
          const d = new Date(t.ts * 1000);
          return `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`;
        });
        lineChart.data.datasets[0].data = ts.map(t => t.blocked);
        lineChart.data.datasets[1].data = ts.map(t => t.allowed);
        lineChart.update("none");
      }

      const upd = document.getElementById("chart-last-update");
      if (upd) upd.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    })
    .catch(() => {});
}

