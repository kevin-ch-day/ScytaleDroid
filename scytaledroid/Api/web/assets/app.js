let lastUploadPath = null;
let lastJobId = null;
let lastSession = null;
let pollTimer = null;

function safeFormatIso(value) {
  if (typeof formatIso === "function") {
    return formatIso(value);
  }
  return value || "-";
}

async function handleUpload() {
  const fileInput = document.getElementById("apkFile");
  if (!fileInput || !fileInput.files.length) {
    setText("uploadStatus", "Select an APK file first.");
    return;
  }
  try {
    setText("uploadStatus", "Uploading...");
    const result = await apiUpload(fileInput.files[0]);
    lastUploadPath = result.path;
    setText("uploadStatus", `Upload complete. sha256=${result.sha256}`);
    const scanBtn = document.getElementById("scanBtn");
    if (scanBtn) {
      scanBtn.disabled = false;
    }
  } catch (err) {
    setText("uploadStatus", String(err));
  }
}

async function handleScan() {
  if (!lastUploadPath) {
    setText("jobStatus", "Upload an APK first.");
    return;
  }
  const profile = document.getElementById("profile")?.value || "full";
  const scopeLabel = document.getElementById("scopeLabel")?.value || null;
  try {
    setText("jobStatus", "Starting scan...");
    const result = await apiPost("/scan", {
      apk_path: lastUploadPath,
      profile: profile,
      scope_label: scopeLabel,
    });
    lastJobId = result.job_id;
    lastSession = result.session_stamp;
    setText("jobStatus", `Job queued: ${lastJobId}`);
    startPollingJob();
  } catch (err) {
    setText("jobStatus", String(err));
  }
}

function startPollingJob() {
  if (pollTimer) {
    clearInterval(pollTimer);
  }
  pollTimer = setInterval(pollJobStatus, 1500);
  pollJobStatus();
}

function startJobsRefresh() {
  loadJobs();
  setInterval(loadJobs, 2000);
}

function startRunsRefresh() {
  loadRuns();
  setInterval(loadRuns, 4000);
}

async function pollJobStatus() {
  if (!lastJobId) {
    return;
  }
  try {
    const data = await apiGet(`/job/${lastJobId}`);
    const label = data.package_name || "unknown";
    setText("jobStatus", `Job ${data.state} · ${label}`);
    if (data.state === "OK" || data.state === "FAILED") {
      clearInterval(pollTimer);
      pollTimer = null;
      if (lastSession) {
        setHtml(
          "runLinks",
          `<a href="/ui/run?session=${lastSession}">View report</a>`
        );
      }
    }
  } catch (err) {
    setText("jobStatus", String(err));
  }
}

async function loadJobs() {
  try {
    const data = await apiGet("/jobs?limit=25");
    const rows = data.jobs
      .map(
        (job) => {
          const label = job.package_name || "-";
          const queued = formatDate(job.created_at);
          return `<tr><td>${job.job_id}</td><td>${job.state}</td><td>${label}</td><td>${queued}</td></tr>`;
        }
      )
      .join("");
    setHtml("jobsTable", rows || "<tr><td colspan=\"4\">No jobs</td></tr>");
  } catch (err) {
    setText("jobsStatus", String(err));
  }
}

async function loadRuns() {
  try {
    const data = await apiGet("/runs?limit=25");
    const rows = data.runs
      .map(
        (run) => {
          const label = run.display_name || run.package_name;
          const version = formatVersion(run);
          const ended = safeFormatIso(run.ended_at_utc);
          const open = run.session_stamp
            ? `<a href="/ui/run?session=${run.session_stamp}">View report</a>`
            : "-";
          return `<tr><td>${label}</td><td>${version}</td><td>${run.status}</td><td>${ended}</td><td>${open}</td></tr>`;
        }
      )
      .join("");
    setHtml("runsTable", rows || "<tr><td colspan=\"5\">No runs</td></tr>");
  } catch (err) {
    setText("runsStatus", String(err));
  }
}

function formatVersion(entry) {
  const code = entry.version_code || "-";
  const name = entry.version_name ? ` (${entry.version_name})` : "";
  return `${code}${name}`;
}

function formatSha(value) {
  if (!value) return "-";
  return value.slice(0, 12);
}

function escapeHtml(value) {
  const text = String(value ?? "");
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildStatCards(items) {
  return items
    .map(
      (item) =>
        `<div class="stat-card"><div class="stat-label">${escapeHtml(item.label)}</div><div class="stat-value">${escapeHtml(item.value)}</div></div>`
    )
    .join("");
}

function formatDuration(value) {
  if (value === null || value === undefined) return "-";
  const num = Number(value);
  if (Number.isNaN(num)) return "-";
  return `${num.toFixed(2)}s`;
}

function shorten(value, max = 80) {
  if (!value) return "-";
  const text = String(value);
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

function badgeForRisk(risk) {
  const normalized = String(risk || "").toLowerCase();
  if (normalized.includes("high")) return "badge danger";
  if (normalized.includes("medium")) return "badge warn";
  return "badge";
}

async function loadAppsRecent() {
  try {
    const data = await apiGet("/apps/recent?limit=25");
    const rows = data.apps
      .map((app) => {
        const label = app.display_name || app.package_name;
        const version = formatVersion(app);
        const status = app.latest_status || "-";
        const sha = formatSha(app.sha256);
        const ended = safeFormatIso(app.latest_ended_at);
        const open = app.app_version_id
          ? `<a href="/ui/report?app_version_id=${app.app_version_id}">View report</a>`
          : "-";
        return `<tr><td>${label}</td><td>${app.package_name || "-"}</td><td>${version}</td><td>${status}</td><td>${sha}</td><td>${ended}</td><td>${open}</td></tr>`;
      })
      .join("");
    setHtml("appsTable", rows || "<tr><td colspan=\"7\">No apps</td></tr>");
  } catch (err) {
    setText("appsStatus", String(err));
  }
}

async function loadApps() {
  try {
    const data = await apiGet("/apps?limit=50");
    const rows = data.apps
      .map((app) => {
        const label = app.display_name || app.package_name;
        const version = formatVersion(app);
        const status = app.latest_status || "-";
        const sha = formatSha(app.sha256);
        const ended = safeFormatIso(app.latest_ended_at);
        const open = app.app_version_id
          ? `<a href="/ui/report?app_version_id=${app.app_version_id}">View report</a>`
          : "-";
        return `<tr><td>${label}</td><td>${app.package_name || "-"}</td><td>${version}</td><td>${status}</td><td>${sha}</td><td>${ended}</td><td>${open}</td></tr>`;
      })
      .join("");
    setHtml("appsTable", rows || "<tr><td colspan=\"7\">No apps</td></tr>");
  } catch (err) {
    setText("appsStatus", String(err));
  }
}

async function loadRunDetails() {
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

function extractDetectorList(report) {
  const view = report && report.view ? report.view : {};
  const detectors = view.detectors || view.detector_list || [];
  if (Array.isArray(detectors) && detectors.length) {
    return detectors;
  }
  return [];
}

async function loadReportTemplate() {
  const params = new URLSearchParams(window.location.search);
  const session = params.get("session");
  const appVersionId = params.get("app_version_id");
  let sessionStamp = session;
  let reportHash = null;
  if (!sessionStamp && appVersionId) {
    try {
      const latest = await apiGet(`/app_version/${appVersionId}/latest_run`);
      if (latest.status === "ok") {
        sessionStamp = latest.session_stamp || null;
        reportHash = latest.report_hash || null;
      } else {
        setText("reportStatus", latest.message || "No completed runs for this app version.");
        return;
      }
    } catch (err) {
      setText("reportStatus", String(err));
      return;
    }
  }
  if (!sessionStamp && !reportHash) {
    setText("reportStatus", "Missing session or app_version_id parameter.");
    return;
  }
  try {
    const reportPath = reportHash ? `/report/${reportHash}.json` : `/run/${sessionStamp}/report.json`;
    const report = await apiGet(reportPath);
    const meta = report.metadata || {};
    const view = report.view || {};
    const identity = view.identity || {};
    const hashes = identity.hashes || report.hashes || {};
    const artifact = view.artifact || {};
    const run = view.run || {};
    const risk = view.risk || {};
    const result = view.result || {};
    const indicators = report.analysis_indicators || {};
    const findingsList = Array.isArray(report.findings) ? report.findings : [];
    const detectorResults = Array.isArray(report.detector_results) ? report.detector_results : [];
    const exported = report.exported_components || {};
    const permissionsList = Array.isArray(view.permissions) ? view.permissions : [];
    const permissionsFallback = report.permissions || {};

    const packageName = meta.package_name || meta.package || "-";
    const displayVersion = meta.version_name || meta.version_code || "-";
    const profile = run.profile || meta.profile || meta.scan_profile || "-";
    const reportTitle = meta.app_label || packageName;

    setText(
      "reportStatus",
      `Latest report for ${reportTitle} · app_version_id ${appVersionId || "-"}`
    );

    setHtml(
      "reportIdentity",
      buildStatCards([
        { label: "Package", value: packageName },
        { label: "Version", value: displayVersion },
        { label: "Profile", value: profile },
        { label: "Artifact Role", value: artifact.role_label || artifact.role || "-" },
        { label: "SHA256", value: hashes.sha256 || meta.sha256 || "-" },
        { label: "Size", value: identity.size_human || identity.size_bytes || "-" },
      ])
    );

    setHtml(
      "reportRun",
      buildStatCards([
        { label: "Run Time (UTC)", value: run.timestamp_utc || report.generated_at || "-" },
        { label: "Seed", value: run.seed || "-" },
        { label: "Tool Version", value: run.version || report.analysis_version || "-" },
        { label: "Toolchain", value: run.toolchain ? Object.keys(run.toolchain || {}).join(", ") : "-" },
      ])
    );

    setHtml(
      "reportRisk",
      buildStatCards([
        { label: "Risk Band", value: risk.band || "-" },
        { label: "Risk Score", value: risk.score ?? "-" },
        { label: "P0", value: result.p0 ?? 0 },
        { label: "P1", value: result.p1 ?? 0 },
        { label: "P2", value: result.p2 ?? 0 },
      ])
    );

    const indicatorCards = Object.entries(indicators).map(([key, value]) => ({
      label: key.replace(/_/g, " "),
      value: value,
    }));
    setHtml(
      "reportIndicators",
      indicatorCards.length ? buildStatCards(indicatorCards) : "<div class=\"muted\">No indicators available.</div>"
    );

    setHtml(
      "reportFindings",
      buildStatCards([
        { label: "Total", value: findingsList.length },
        { label: "P0", value: result.p0 ?? 0 },
        { label: "P1", value: result.p1 ?? 0 },
        { label: "P2", value: result.p2 ?? 0 },
      ])
    );

    setHtml(
      "reportComponents",
      buildStatCards([
        { label: "Activities", value: (exported.activities || []).length || 0 },
        { label: "Services", value: (exported.services || []).length || 0 },
        { label: "Receivers", value: (exported.receivers || []).length || 0 },
        { label: "Providers", value: (exported.providers || []).length || 0 },
      ])
    );

    const componentRows = [
      { label: "Activities", items: exported.activities || [] },
      { label: "Services", items: exported.services || [] },
      { label: "Receivers", items: exported.receivers || [] },
      { label: "Providers", items: exported.providers || [] },
    ].map((entry) => {
      const preview = entry.items.slice(0, 4).map((name) => escapeHtml(name)).join(", ");
      const extra = entry.items.length > 4 ? ` (+${entry.items.length - 4} more)` : "";
      return `<tr><td>${escapeHtml(entry.label)}</td><td>${preview || "-"}${extra}</td></tr>`;
    });
    setHtml(
      "reportComponentsTable",
      componentRows.length ? componentRows.join("") : "<tr><td colspan=\"2\">No component data.</td></tr>"
    );

    let permissionRows = [];
    if (permissionsList.length) {
      permissionRows = permissionsList.slice(0, 20).map((perm) => {
        const riskLabel = perm.risk || "Low";
        const protection = perm.profile?.protection || "-";
        return `<tr>
          <td>${escapeHtml(perm.display_name || perm.name || "-")}</td>
          <td><span class="${badgeForRisk(riskLabel)}">${escapeHtml(riskLabel)}</span></td>
          <td>${escapeHtml(protection)}</td>
          <td>${escapeHtml(perm.namespace || "-")}</td>
        </tr>`;
      });
    } else if (Array.isArray(permissionsFallback.declared)) {
      permissionRows = permissionsFallback.declared.slice(0, 20).map((name) => {
        return `<tr>
          <td>${escapeHtml(name)}</td>
          <td><span class="badge">Declared</span></td>
          <td>-</td>
          <td>${escapeHtml(String(name).split(".").slice(0, -1).join(".") || "-")}</td>
        </tr>`;
      });
    }
    setHtml(
      "reportPermissionsTable",
      permissionRows.length ? permissionRows.join("") : "<tr><td colspan=\"4\">No permissions</td></tr>"
    );

    const findingsRows = findingsList.slice(0, 15).map((finding) => {
      const tags = Array.isArray(finding.tags) ? finding.tags.join(", ") : "-";
      const masvs = Array.isArray(finding.category_masvs)
        ? finding.category_masvs.join(", ")
        : finding.category_masvs || "-";
      const evidence = Array.isArray(finding.evidence) && finding.evidence.length
        ? shorten(finding.evidence[0].location || finding.evidence[0].description || "-")
        : "-";
      return `<tr>
        <td>${escapeHtml(finding.title || "-")}</td>
        <td>${escapeHtml(finding.status || "-")}</td>
        <td>${escapeHtml(masvs)}</td>
        <td>${escapeHtml(tags)}</td>
        <td>${escapeHtml(evidence)}</td>
      </tr>`;
    });
    setHtml(
      "reportFindingsTable",
      findingsRows.length ? findingsRows.join("") : "<tr><td colspan=\"5\">No findings</td></tr>"
    );

    const detectorRows = detectorResults.map((detector) => {
      const notes = Array.isArray(detector.notes) ? detector.notes.join("; ") : detector.notes || "-";
      const findingCount = Array.isArray(detector.findings) ? detector.findings.length : 0;
      return `<tr>
        <td>${escapeHtml(detector.detector_id || detector.section_key || "-")}</td>
        <td>${escapeHtml(detector.status || "-")}</td>
        <td>${escapeHtml(formatDuration(detector.duration_sec))}</td>
        <td>${escapeHtml(findingCount)}</td>
        <td>${escapeHtml(shorten(notes, 120))}</td>
      </tr>`;
    });
    setHtml(
      "reportDetectorsTable",
      detectorRows.length ? detectorRows.join("") : "<tr><td colspan=\"5\">No detectors</td></tr>"
    );

    setText("reportJson", JSON.stringify(report, null, 2));
  } catch (err) {
    setText("reportStatus", "Report JSON not available for the latest run.");
    setHtml("reportIdentity", "");
    setHtml("reportRun", "");
    setHtml("reportRisk", "");
    setHtml("reportIndicators", "");
    setHtml("reportFindings", "");
    setHtml("reportComponents", "");
    setHtml("reportComponentsTable", "<tr><td colspan=\"2\">No component data.</td></tr>");
    setHtml("reportPermissionsTable", "<tr><td colspan=\"4\">No permissions</td></tr>");
    setHtml("reportFindingsTable", "<tr><td colspan=\"5\">No findings</td></tr>");
    setHtml("reportDetectorsTable", "<tr><td colspan=\"5\">No detectors</td></tr>");
    setText("reportJson", "");
  }
}

async function loadHealth() {
  try {
    const data = await apiGet("/health/summary");
    if (data.status !== "ok") {
      setText("healthStatus", "Health summary unavailable.");
      return;
    }
    const counts = data.last_24h || {};
    const runningTotal = data.running_total || 0;
    setText("healthStatus", "Last 24h counts");
    setHtml(
      "healthCards",
      `
      <div class="stat-card"><div class="stat-label">RUNNING total</div><div class="stat-value">${runningTotal}</div></div>
      <div class="stat-card"><div class="stat-label">OK</div><div class="stat-value">${counts.OK || 0}</div></div>
      <div class="stat-card"><div class="stat-label">FAILED</div><div class="stat-value">${counts.FAILED || 0}</div></div>
      <div class="stat-card"><div class="stat-label">ABORTED</div><div class="stat-value">${counts.ABORTED || 0}</div></div>
      `
    );
  } catch (err) {
    setText("healthStatus", String(err));
  }
}

async function loadOpsHealth() {
  try {
    const data = await apiGet("/health/summary");
    if (data.status !== "ok") {
      setText("opsHealthStatus", "Health summary unavailable.");
      return;
    }
    const counts = data.last_24h || {};
    const runningTotal = data.running_total || 0;
    setText("opsHealthStatus", "Last 24h counts");
    setHtml(
      "opsHealthCards",
      `
      <div class="stat-card"><div class="stat-label">RUNNING total</div><div class="stat-value">${runningTotal}</div></div>
      <div class="stat-card"><div class="stat-label">OK</div><div class="stat-value">${counts.OK || 0}</div></div>
      <div class="stat-card"><div class="stat-label">FAILED</div><div class="stat-value">${counts.FAILED || 0}</div></div>
      <div class="stat-card"><div class="stat-label">ABORTED</div><div class="stat-value">${counts.ABORTED || 0}</div></div>
      `
    );
  } catch (err) {
    setText("opsHealthStatus", String(err));
  }
}

async function finalizeStaleRuns() {
  const minutes = document.getElementById("staleMinutes")?.value || "60";
  try {
    const response = await fetch(`/maintenance/finalize_stale?minutes=${minutes}`, { method: "POST" });
    if (!response.ok) {
      setText("finalizeStatus", "Request failed.");
      return;
    }
    const data = await response.json();
    setText("finalizeStatus", `Updated ${data.updated} run(s) (threshold ${data.threshold_minutes}m).`);
    loadOpsHealth();
  } catch (err) {
    setText("finalizeStatus", String(err));
  }
}

function bindHandlers() {
  const uploadBtn = document.getElementById("uploadBtn");
  if (uploadBtn) {
    uploadBtn.addEventListener("click", handleUpload);
  }
  const scanBtn = document.getElementById("scanBtn");
  if (scanBtn) {
    scanBtn.addEventListener("click", handleScan);
  }
  if (document.getElementById("runsTable")) {
    startRunsRefresh();
  }
  if (document.getElementById("jobsTable")) {
    startJobsRefresh();
  }
  if (document.getElementById("appsTable") && document.getElementById("appsStatus")) {
    if (document.body.dataset.pageTitle === "Apps") {
      loadApps();
    } else {
      loadAppsRecent();
    }
  }
  if (document.getElementById("runStatus")) {
    loadRunDetails();
  }
  if (document.getElementById("healthStatus")) {
    loadHealth();
  }
  if (document.getElementById("opsHealthStatus")) {
    loadOpsHealth();
  }
  const finalizeBtn = document.getElementById("finalizeBtn");
  if (finalizeBtn) {
    finalizeBtn.addEventListener("click", finalizeStaleRuns);
  }
  if (document.getElementById("reportStatus")) {
    loadReportTemplate();
  }
  if (window.jQuery) {
    window.jQuery("#apkFile").on("change", function () {
      if (this.files && this.files.length) {
        setText("uploadStatus", `Selected ${this.files[0].name}`);
      }
    });
  }
}

if (window.jQuery) {
  window.jQuery(bindHandlers);
} else {
  document.addEventListener("DOMContentLoaded", bindHandlers);
}
