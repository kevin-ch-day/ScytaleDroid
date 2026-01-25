let jobsRefreshTimer = null;

async function jobsLoad() {
  try {
    const data = await apiGet("/jobs?limit=25");
    const rows = data.jobs
      .map((job) => {
        const label = job.package_name || "-";
        const queued = formatDate(job.created_at);
        return `<tr><td>${job.job_id}</td><td>${job.state}</td><td>${label}</td><td>${queued}</td></tr>`;
      })
      .join("");
    setHtml("jobsTable", rows || "<tr><td colspan=\"4\">No jobs</td></tr>");
  } catch (err) {
    setText("jobsStatus", String(err));
  }
}

function jobsStartRefresh() {
  if (jobsRefreshTimer) {
    clearInterval(jobsRefreshTimer);
  }
  jobsLoad();
  jobsRefreshTimer = setInterval(jobsLoad, 2000);
}
