function buildHeader(titleText) {
  const title = titleText || document.title || "ScytaleDroid";
  return `
    <div>
      <div class="page-title">${title}</div>
      <div class="page-subtitle">Local API console</div>
    </div>
    <div class="page-meta">
      <span class="badge">127.0.0.1</span>
      <span class="badge">API</span>
    </div>
  `;
}

document.addEventListener("DOMContentLoaded", () => {
  const header = document.getElementById("pageHeader");
  if (header) {
    header.innerHTML = buildHeader(document.body.dataset.pageTitle);
  }
});
