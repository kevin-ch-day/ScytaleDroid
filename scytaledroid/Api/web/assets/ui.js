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
  if (!seconds) return "-";
  const date = new Date(seconds * 1000);
  return date.toLocaleString();
}
