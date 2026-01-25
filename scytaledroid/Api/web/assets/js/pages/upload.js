let uploadLastPath = null;
let uploadJobId = null;
let uploadSession = null;
let uploadPollTimer = null;

async function uploadHandleUpload() {
  const fileInput = document.getElementById("apkFile");
  if (!fileInput || !fileInput.files.length) {
    setText("uploadStatus", "Select an APK file first.");
    return;
  }
  try {
    setText("uploadStatus", "Uploading...");
    const result = await apiUpload(fileInput.files[0]);
    uploadLastPath = result.path;
    setText("uploadStatus", `Upload complete. sha256=${result.sha256}`);
    const scanBtn = document.getElementById("scanBtn");
    if (scanBtn) {
      scanBtn.disabled = false;
    }
  } catch (err) {
    setText("uploadStatus", String(err));
  }
}

async function uploadHandleScan() {
  if (!uploadLastPath) {
    setText("jobStatus", "Upload an APK first.");
    return;
  }
  const profile = document.getElementById("profile")?.value || "full";
  const scopeLabel = document.getElementById("scopeLabel")?.value || null;
  try {
    setText("jobStatus", "Starting scan...");
    const result = await apiPost("/scan", {
      apk_path: uploadLastPath,
      profile: profile,
      scope_label: scopeLabel,
    });
    uploadJobId = result.job_id;
    uploadSession = result.session_stamp;
    setText("jobStatus", `Job queued: ${uploadJobId}`);
    uploadStartPollingJob();
  } catch (err) {
    setText("jobStatus", String(err));
  }
}

function uploadStartPollingJob() {
  if (uploadPollTimer) {
    clearInterval(uploadPollTimer);
  }
  uploadPollTimer = setInterval(uploadPollJobStatus, 1500);
  uploadPollJobStatus();
}

async function uploadPollJobStatus() {
  if (!uploadJobId) {
    return;
  }
  try {
    const data = await apiGet(`/job/${uploadJobId}`);
    const label = data.package_name || "unknown";
    setText("jobStatus", `Job ${data.state} · ${label}`);
    if (data.state === "OK" || data.state === "FAILED") {
      clearInterval(uploadPollTimer);
      uploadPollTimer = null;
      if (uploadSession) {
        setHtml(
          "runLinks",
          `<a href="/ui/run?session=${uploadSession}">View report</a>`
        );
      }
    }
  } catch (err) {
    setText("jobStatus", String(err));
  }
}

function uploadBindFileWatcher() {
  if (window.jQuery) {
    window.jQuery("#apkFile").on("change", function () {
      if (this.files && this.files.length) {
        setText("uploadStatus", `Selected ${this.files[0].name}`);
      }
    });
  }
}
