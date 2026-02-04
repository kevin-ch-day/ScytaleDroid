function bindHandlers() {
  const uploadBtn = document.getElementById("uploadBtn");
  if (uploadBtn && typeof uploadHandleUpload === "function") {
    uploadBtn.addEventListener("click", uploadHandleUpload);
  }
  const scanBtn = document.getElementById("scanBtn");
  if (scanBtn && typeof uploadHandleScan === "function") {
    scanBtn.addEventListener("click", uploadHandleScan);
  }
  if (document.getElementById("runsTable")) {
    if (typeof runsInit === "function") {
      runsInit();
    } else if (typeof runsStartRefresh === "function") {
      runsStartRefresh();
    }
  }
  if (document.getElementById("jobsTable") && typeof jobsStartRefresh === "function") {
    jobsStartRefresh();
  }
  if (document.getElementById("appsTable") && document.getElementById("appsStatus")) {
    if (document.body.dataset.pageTitle === "Apps") {
      if (typeof appsInit === "function") {
        appsInit();
      } else if (typeof appsLoadAll === "function") {
        appsLoadAll();
      }
    } else if (typeof appsLoadRecent === "function") {
      appsLoadRecent();
    }
  }
  if (document.getElementById("runStatus") && typeof runLoadDetails === "function") {
    runLoadDetails();
  }
  if (document.getElementById("healthStatus") && typeof opsLoadHealth === "function") {
    opsLoadHealth("healthStatus", "healthCards");
  }
  if (document.getElementById("opsHealthStatus") && typeof opsLoadHealth === "function") {
    opsLoadHealth("opsHealthStatus", "opsHealthCards");
  }
  const finalizeBtn = document.getElementById("finalizeBtn");
  if (finalizeBtn && typeof opsFinalizeStaleRuns === "function") {
    finalizeBtn.addEventListener("click", opsFinalizeStaleRuns);
  }
  if (document.getElementById("reportStatus") && typeof reportLoad === "function") {
    reportLoad();
  }
  if (typeof uploadBindFileWatcher === "function") {
    uploadBindFileWatcher();
  }
}

if (window.jQuery) {
  window.jQuery(bindHandlers);
} else {
  document.addEventListener("DOMContentLoaded", bindHandlers);
}
