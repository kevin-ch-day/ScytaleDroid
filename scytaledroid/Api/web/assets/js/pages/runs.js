let runsRefreshTimer = null;

async function runsLoad() {
  try {
    const data = await apiGet("/runs?limit=25");
    const rows = data.runs
      .map((run) => {
        const label = run.display_name || run.package_name;
        const version = formatVersion(run);
        const ended = safeFormatIso(run.ended_at_utc);
        const open = run.session_stamp
          ? `<a href="/ui/run?session=${run.session_stamp}">View report</a>`
          : "-";
        return `<tr><td>${label}</td><td>${version}</td><td>${run.status}</td><td>${ended}</td><td>${open}</td></tr>`;
      })
      .join("");
    setHtml("runsTable", rows || "<tr><td colspan=\"5\">No runs</td></tr>");
  } catch (err) {
    setText("runsStatus", String(err));
  }
}

function runsStartRefresh() {
  if (runsRefreshTimer) {
    clearInterval(runsRefreshTimer);
  }
  runsLoad();
  runsRefreshTimer = setInterval(runsLoad, 4000);
}
