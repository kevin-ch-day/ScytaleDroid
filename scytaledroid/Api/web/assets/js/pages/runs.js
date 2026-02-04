let runsRefreshTimer = null;

function getRunsFilters() {
  const search = document.getElementById("runsSearch")?.value?.trim() || "";
  const profile = document.getElementById("runsProfile")?.value || "";
  const limitRaw = document.getElementById("runsLimit")?.value || "25";
  const limit = Math.max(1, Math.min(500, Number(limitRaw) || 25));
  return { search, profile, limit };
}

function buildRunsQuery() {
  const { search, profile, limit } = getRunsFilters();
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  if (search) {
    params.set("q", search);
  }
  if (profile) {
    params.set("profile", profile);
  }
  return params.toString();
}

async function loadProfilesForRuns() {
  try {
    const data = await apiGet("/profiles");
    const select = document.getElementById("runsProfile");
    if (!select) return;
    const options = (data.profiles || []).map(
      (profile) => `<option value="${escapeHtml(profile)}">${escapeHtml(profile)}</option>`
    );
    select.innerHTML = `<option value="">All profiles</option>${options.join("")}`;
  } catch (err) {
    // optional
  }
}

async function runsLoad() {
  try {
    const query = buildRunsQuery();
    const data = await apiGet(`/runs?${query}`);
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

function runsBindFilters() {
  const apply = document.getElementById("runsApply");
  if (apply) {
    apply.addEventListener("click", (evt) => {
      evt.preventDefault();
      runsLoad();
    });
  }
  const search = document.getElementById("runsSearch");
  if (search) {
    search.addEventListener("keydown", (evt) => {
      if (evt.key === "Enter") {
        evt.preventDefault();
        runsLoad();
      }
    });
  }
}

async function runsInit() {
  await loadProfilesForRuns();
  runsBindFilters();
  runsStartRefresh();
}
