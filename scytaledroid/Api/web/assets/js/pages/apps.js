function getAppsFilters() {
  const search = document.getElementById("appsSearch")?.value?.trim() || "";
  const profile = document.getElementById("appsProfile")?.value || "";
  const limitRaw = document.getElementById("appsLimit")?.value || "50";
  const limit = Math.max(1, Math.min(500, Number(limitRaw) || 50));
  return { search, profile, limit };
}

function buildAppsQuery() {
  const { search, profile, limit } = getAppsFilters();
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

async function loadProfilesForApps() {
  try {
    const data = await apiGet("/profiles");
    const select = document.getElementById("appsProfile");
    if (!select) return;
    const options = (data.profiles || []).map(
      (profile) => `<option value="${escapeHtml(profile)}">${escapeHtml(profile)}</option>`
    );
    select.innerHTML = `<option value="">All profiles</option>${options.join("")}`;
  } catch (err) {
    // keep silent; profile filtering is optional
  }
}

async function appsLoadRecent() {
  try {
    const rows = await appsFetchRows("/apps/recent", 25);
    setHtml("appsTable", rows || "<tr><td colspan=\"6\">No apps</td></tr>");
  } catch (err) {
    setText("appsStatus", String(err));
  }
}

async function appsFetchRows(endpoint, defaultLimit) {
  const { search, profile, limit } = getAppsFilters();
  const params = new URLSearchParams();
  params.set("limit", String(limit || defaultLimit));
  if (search) params.set("q", search);
  if (profile) params.set("profile", profile);
  const data = await apiGet(`${endpoint}?${params.toString()}`);
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
  return rows;
}

async function appsLoadAll() {
  try {
    const rows = await appsFetchRows("/apps", 50);
    setHtml("appsTable", rows || "<tr><td colspan=\"6\">No apps</td></tr>");
  } catch (err) {
    setText("appsStatus", String(err));
  }
}

function appsBindFilters() {
  const apply = document.getElementById("appsApply");
  if (apply) {
    apply.addEventListener("click", (evt) => {
      evt.preventDefault();
      appsLoadAll();
    });
  }
  const search = document.getElementById("appsSearch");
  if (search) {
    search.addEventListener("keydown", (evt) => {
      if (evt.key === "Enter") {
        evt.preventDefault();
        appsLoadAll();
      }
    });
  }
}

async function appsInit() {
  await loadProfilesForApps();
  appsBindFilters();
  appsLoadAll();
}
