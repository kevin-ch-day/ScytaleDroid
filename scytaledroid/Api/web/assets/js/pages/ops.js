async function opsLoadHealth(targetStatusId, targetCardsId) {
  try {
    const data = await apiGet("/health/summary");
    if (data.status !== "ok") {
      setText(targetStatusId, "Health summary unavailable.");
      return;
    }
    const counts = data.last_24h || {};
    const runningTotal = data.running_total || 0;
    setText(targetStatusId, "Last 24h counts");
    setHtml(
      targetCardsId,
      `
      <div class="stat-card"><div class="stat-label">RUNNING total</div><div class="stat-value">${runningTotal}</div></div>
      <div class="stat-card"><div class="stat-label">OK</div><div class="stat-value">${counts.OK || 0}</div></div>
      <div class="stat-card"><div class="stat-label">FAILED</div><div class="stat-value">${counts.FAILED || 0}</div></div>
      <div class="stat-card"><div class="stat-label">ABORTED</div><div class="stat-value">${counts.ABORTED || 0}</div></div>
      `
    );
  } catch (err) {
    setText(targetStatusId, String(err));
  }
}

async function opsFinalizeStaleRuns() {
  const minutes = document.getElementById("staleMinutes")?.value || "60";
  try {
    const response = await fetch(`/maintenance/finalize_stale?minutes=${minutes}`, { method: "POST" });
    if (!response.ok) {
      setText("finalizeStatus", "Request failed.");
      return;
    }
    const data = await response.json();
    setText("finalizeStatus", `Updated ${data.updated} run(s) (threshold ${data.threshold_minutes}m).`);
    opsLoadHealth("opsHealthStatus", "opsHealthCards");
  } catch (err) {
    setText("finalizeStatus", String(err));
  }
}
