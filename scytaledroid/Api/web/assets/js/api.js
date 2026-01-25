async function apiRequest(path, options = {}) {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 12000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, { ...options, signal: controller.signal });
    const isJson = response.headers.get("content-type")?.includes("application/json");
    const payload = isJson ? await response.json() : null;
    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText;
      throw new Error(`Request failed: ${response.status} ${detail || ""}`.trim());
    }
    return payload ?? {};
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Request timed out.");
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function apiGet(path) {
  return apiRequest(path);
}

async function apiPost(path, payload) {
  return apiRequest(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function apiUpload(file) {
  const form = new FormData();
  form.append("file", file);
  return apiRequest("/upload", { method: "POST", body: form, timeoutMs: 30000 });
}
