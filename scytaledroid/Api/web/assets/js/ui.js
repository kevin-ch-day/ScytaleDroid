function setText(id, text) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = text;
  }
}

function setHtml(id, html) {
  const el = document.getElementById(id);
  if (el) {
    el.innerHTML = html;
  }
}

function formatDate(seconds) {
  if (seconds === null || seconds === undefined || seconds === "") return "-";
  if (typeof seconds === "string" && seconds.includes("T")) {
    const parsed = new Date(seconds);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toLocaleString();
    }
  }
  const num = Number(seconds);
  if (Number.isNaN(num)) return "-";
  const date = new Date(num * 1000);
  return date.toLocaleString();
}

function formatIso(isoValue) {
  if (!isoValue) return "-";
  const date = new Date(isoValue);
  if (Number.isNaN(date.getTime())) {
    return isoValue;
  }
  return date.toLocaleString([], {
    hour: "numeric",
    minute: "2-digit",
    month: "numeric",
    day: "numeric",
    year: "numeric",
  });
}
