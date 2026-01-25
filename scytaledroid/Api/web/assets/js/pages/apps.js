async function appsLoadRecent() {
  try {
    const data = await apiGet("/apps/recent?limit=25");
    const rows = data.apps
      .map((app) => {
        const label = app.display_name || app.package_name;
        const version = formatVersion(app);
        const status = app.latest_status || "-";
        const ended = safeFormatIso(app.latest_ended_at);
        const open = app.app_version_id
          ? `<a href="/ui/report?app_version_id=${app.app_version_id}">View report</a>`
          : "-";
        return `<tr><td>${label}</td><td>${app.package_name || "-"}</td><td>${version}</td><td>${status}</td><td>${ended}</td><td>${open}</td></tr>`;
      })
      .join("");
    setHtml("appsTable", rows || "<tr><td colspan=\"6\">No apps</td></tr>");
  } catch (err) {
    setText("appsStatus", String(err));
  }
}

async function appsLoadAll() {
  try {
    const data = await apiGet("/apps?limit=50");
    const rows = data.apps
      .map((app) => {
        const label = app.display_name || app.package_name;
        const version = formatVersion(app);
        const status = app.latest_status || "-";
        const ended = safeFormatIso(app.latest_ended_at);
        const open = app.app_version_id
          ? `<a href="/ui/report?app_version_id=${app.app_version_id}">View report</a>`
          : "-";
        return `<tr><td>${label}</td><td>${app.package_name || "-"}</td><td>${version}</td><td>${status}</td><td>${ended}</td><td>${open}</td></tr>`;
      })
      .join("");
    setHtml("appsTable", rows || "<tr><td colspan=\"6\">No apps</td></tr>");
  } catch (err) {
    setText("appsStatus", String(err));
  }
}
