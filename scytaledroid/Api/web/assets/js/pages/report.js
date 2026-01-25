function extractDetectorList(report) {
  const view = report && report.view ? report.view : {};
  const detectors = view.detectors || view.detector_list || [];
  if (Array.isArray(detectors) && detectors.length) {
    return detectors;
  }
  return [];
}

async function reportLoad() {
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
      buildKvRows([
        { label: "Package", value: packageName },
        { label: "Version", value: displayVersion },
        { label: "Profile", value: profile },
        { label: "Artifact Role", value: artifact.role_label || artifact.role || "-" },
        { label: "MD5", value: hashes.md5 || "-", className: "hash-value" },
        { label: "SHA1", value: hashes.sha1 || "-", className: "hash-value" },
        { label: "SHA256", value: hashes.sha256 || meta.sha256 || "-", className: "hash-value" },
        { label: "Size", value: identity.size_human || identity.size_bytes || "-" },
      ])
    );

    setHtml(
      "reportRun",
      buildKvRows([
        { label: "Run Time (UTC)", value: run.timestamp_utc || report.generated_at || "-" },
        { label: "Seed", value: run.seed || "-" },
        { label: "Tool Version", value: run.version || report.analysis_version || "-" },
        { label: "Toolchain", value: run.toolchain ? Object.keys(run.toolchain || {}).join(", ") : "-" },
      ])
    );

    setHtml(
      "reportRisk",
      buildKvRows([
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
      indicatorCards.length ? buildKvRows(indicatorCards) : "<div class=\"muted\">No indicators available.</div>"
    );

    setHtml(
      "reportFindings",
      buildKvRows([
        { label: "Total", value: findingsList.length },
        { label: "P0", value: result.p0 ?? 0 },
        { label: "P1", value: result.p1 ?? 0 },
        { label: "P2", value: result.p2 ?? 0 },
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
      return `<tr><td>${escapeHtml(entry.label)}</td><td>${entry.items.length}</td><td>${preview || "-"}${extra}</td></tr>`;
    });
    setHtml(
      "reportComponentsTable",
      componentRows.length ? componentRows.join("") : "<tr><td colspan=\"3\">No component data.</td></tr>"
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

    const downloadLink = document.getElementById("reportJsonDownload");
    if (downloadLink) {
      downloadLink.href = reportPath;
    }
  } catch (err) {
    setText("reportStatus", "Report JSON not available for the latest run.");
    setHtml("reportIdentity", "");
    setHtml("reportRun", "");
    setHtml("reportRisk", "");
    setHtml("reportIndicators", "");
    setHtml("reportFindings", "");
    setHtml("reportComponentsTable", "<tr><td colspan=\"3\">No component data.</td></tr>");
    setHtml("reportPermissionsTable", "<tr><td colspan=\"4\">No permissions</td></tr>");
    setHtml("reportFindingsTable", "<tr><td colspan=\"5\">No findings</td></tr>");
    setHtml("reportDetectorsTable", "<tr><td colspan=\"5\">No detectors</td></tr>");
    const downloadLink = document.getElementById("reportJsonDownload");
    if (downloadLink) {
      downloadLink.href = "#";
    }
  }
}
