async function runLoadDetails() {
  const params = new URLSearchParams(window.location.search);
  const session = params.get("session");
  if (!session) {
    setText("runStatus", "Missing session parameter.");
    return;
  }
  try {
    const status = await apiGet(`/run/${session}/status`);
    setText("runStatus", `Session ${session}`);
    setText("runCounts", JSON.stringify(status.counts || {}, null, 2));

    try {
      const report = await apiGet(`/run/${session}/report.json`);
      const summary = (report && report.view && report.view.summary) ? report.view.summary : {};
      const findings = summary.findings || {};
      setHtml(
        "runSummary",
        `
        <div class="stat-grid">
          <div class="stat-card"><div class="stat-label">Apps</div><div class="stat-value">${summary.app_count || "-"}</div></div>
          <div class="stat-card"><div class="stat-label">Artifacts</div><div class="stat-value">${summary.artifact_count || "-"}</div></div>
          <div class="stat-card"><div class="stat-label">High</div><div class="stat-value">${findings.high || 0}</div></div>
          <div class="stat-card"><div class="stat-label">Medium</div><div class="stat-value">${findings.med || 0}</div></div>
        </div>
        `
      );
    } catch (err) {
      setHtml("runSummary", "<div class=\"muted\">Report JSON not available yet.</div>");
    }
  } catch (err) {
    setText("runStatus", String(err));
  }
}
