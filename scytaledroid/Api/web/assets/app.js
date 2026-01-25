let lastUploadPath = null;
let lastJobId = null;
let lastSession = null;
let pollTimer = null;

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
          `<a href="/ui/run?session=${lastSession}">Open run</a>`
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
        (run) =>
          `<tr><td>${run.session_stamp}</td><td>${run.status}</td><td>${run.package_name}</td><td><a href="/ui/run?session=${run.session_stamp}">Open</a></td></tr>`
      )
      .join("");
    setHtml("runsTable", rows || "<tr><td colspan=\"4\">No runs</td></tr>");
  } catch (err) {
    setText("runsStatus", String(err));
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
  } catch (err) {
    setText("runStatus", String(err));
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
      <div class="badge">RUNNING total: ${runningTotal}</div>
      <div class="badge">OK: ${counts.OK || 0}</div>
      <div class="badge">FAILED: ${counts.FAILED || 0}</div>
      <div class="badge">ABORTED: ${counts.ABORTED || 0}</div>
      `
    );
  } catch (err) {
    setText("healthStatus", String(err));
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("uploadBtn")) {
    document.getElementById("uploadBtn").addEventListener("click", handleUpload);
  }
  if (document.getElementById("scanBtn")) {
    document.getElementById("scanBtn").addEventListener("click", handleScan);
  }
  if (document.getElementById("jobsTable")) {
    loadJobs();
  }
  if (document.getElementById("runsTable")) {
    loadRuns();
  }
  if (document.getElementById("runStatus")) {
    loadRunDetails();
  }
  if (document.getElementById("healthStatus")) {
    loadHealth();
  }
});
