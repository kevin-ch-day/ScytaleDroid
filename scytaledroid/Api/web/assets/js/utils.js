function safeFormatIso(value) {
  if (typeof formatIso === "function") {
    return formatIso(value);
  }
  return value || "-";
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

function buildKvRows(items) {
  return items
    .map((item) => {
      const valueClass = item.className ? `kv-value ${item.className}` : "kv-value";
      return `<div class="kv-row"><div class="kv-label">${escapeHtml(item.label)}</div><div class="${valueClass}">${escapeHtml(item.value)}</div></div>`;
    })
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
