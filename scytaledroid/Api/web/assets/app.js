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
    setText("jobStatus", `Job ${data.state} · session=${data.session_stamp}`);
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
        (job) =>
          `<tr><td>${job.job_id}</td><td>${job.state}</td><td>${job.session_stamp}</td><td>${job.package_name}</td></tr>`
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

async function loadAppsRecent() {
  try {
    const data = await apiGet("/apps?limit=25");
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
        return `<tr><td>${label}</td><td>${version}</td><td>${status}</td><td>${sha}</td><td>${ended}</td><td>${open}</td></tr>`;
      })
      .join("");
    setHtml("appsTable", rows || "<tr><td colspan=\"6\">No apps</td></tr>");
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
        return `<tr><td>${label}</td><td>${version}</td><td>${status}</td><td>${sha}</td><td>${ended}</td><td>${open}</td></tr>`;
      })
      .join("");
    setHtml("appsTable", rows || "<tr><td colspan=\"6\">No apps</td></tr>");
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
  if (!sessionStamp && appVersionId) {
    try {
      const latest = await apiGet(`/app_version/${appVersionId}/latest_run`);
      if (latest.status === "ok") {
        sessionStamp = latest.session_stamp;
      }
    } catch (err) {
      setText("reportStatus", String(err));
      return;
    }
  }
  if (!sessionStamp) {
    setText("reportStatus", "Missing session or app_version_id parameter.");
    return;
  }
  try {
    const report = await apiGet(`/run/${sessionStamp}/report.json`);
    const meta = report.metadata || {};
    const view = report.view || {};
    const summary = view.summary || {};
    const findings = summary.findings || {};

    setText("reportStatus", `Latest report for app_version_id ${appVersionId || "-"}`);
    setHtml(
      "reportHeader",
      `
      <div class="stat-card"><div class="stat-label">Package</div><div class="stat-value">${meta.package_name || "-"}</div></div>
      <div class="stat-card"><div class="stat-label">Version</div><div class="stat-value">${meta.version_name || meta.version_code || "-"}</div></div>
      <div class="stat-card"><div class="stat-label">Profile</div><div class="stat-value">${meta.profile || "-"}</div></div>
      <div class="stat-card"><div class="stat-label">Artifacts</div><div class="stat-value">${summary.artifact_count || "-"}</div></div>
      `
    );

    setHtml(
      "reportFindings",
      `
      <div class="stat-card"><div class="stat-label">High</div><div class="stat-value">${findings.high || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Medium</div><div class="stat-value">${findings.med || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Low</div><div class="stat-value">${findings.low || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Info</div><div class="stat-value">${findings.info || 0}</div></div>
      `
    );

    const detectors = extractDetectorList(report);
    if (detectors.length) {
      setHtml("reportDetectors", detectors.map((item) => `<span class="badge">${item}</span>`).join(" "));
    }

    setText("reportJson", JSON.stringify(report, null, 2));
  } catch (err) {
    setText("reportStatus", "Report JSON not available for the latest run.");
    setHtml("reportHeader", "");
    setHtml("reportFindings", "");
    setHtml("reportDetectors", "<div class=\"muted\">No detector data.</div>");
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
