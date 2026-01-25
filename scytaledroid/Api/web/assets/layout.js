function buildSidebar() {
  return `
    <div class="sidebar-brand">
      <div class="logo-dot"></div>
      <div>
        <div class="brand-title">ScytaleDroid</div>
        <div class="brand-subtitle">Operator UI</div>
      </div>
    </div>
    <nav class="sidebar-nav">
      <a href="/">Home</a>
      <a href="/ui/apps">Apps</a>
      <a href="/ui/upload">Upload</a>
      <a href="/ui/jobs">Jobs</a>
      <a href="/ui/runs">Runs (debug)</a>
      <a href="/ui/ops">Ops</a>
      <a href="/ui/run">Run Viewer</a>
      <a href="/ui/report">Report</a>
    </nav>
  `;
}

document.addEventListener("DOMContentLoaded", () => {
  const sidebar = document.getElementById("sidebar");

  if (sidebar) {
    sidebar.innerHTML = buildSidebar();
  }
});
