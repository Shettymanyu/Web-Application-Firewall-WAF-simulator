document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  initAttackLog();
  initRuleManager();
  initRequestInspector();

  // Initial stats load + periodic refresh
  updateCharts();
  setInterval(updateCharts, 5000);
});
