"""HTML report generation for static analysis outputs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config

from ..core import StaticAnalysisReport
from .view import build_report_view

CSS_BLOCK = """
:root{--bg:#0b0c0f;--card:#12141a;--muted:#9aa4af;--ok:#2ea043;--warn:#e3b341;--fail:#f85149;--hi:#00bcd4;--acc:#7c3aed}
body{margin:0;background:var(--bg);color:#e7edf3;font:14px/1.45 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Inter}
header{padding:20px 24px;border-bottom:1px solid #1f2330;background:#0e1116}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.card{background:var(--card);border:1px solid #1f2330;border-radius:12px;padding:16px}
h1{font-size:18px;margin:0 0 4px}
h2{font-size:14px;margin:0 0 12px;color:#c9d3dd;text-transform:uppercase;letter-spacing:.08em}
.kvs{display:grid;grid-template-columns:180px 1fr;gap:6px 12px}
.muted{color:var(--muted)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:600}
.ok{background:#17361f;color:#5ee788;border:1px solid #264b2d}
.warn{background:#3a2d18;color:#ffd580;border:1px solid #5a4424}
.fail{background:#3a1717;color:#ffb4b4;border:1px solid #5a2323}
.score{font:600 28px/1 monospace}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#191d2b;border:1px solid #26304a;margin:0 6px 6px 0}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 10px;border-bottom:1px solid #1f2330;text-align:left;vertical-align:top}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
footer{color:#8190a5;padding:14px 24px;border-top:1px solid #1f2330;margin-top:20px;font-size:12px}
.section{margin-top:16px}
""".strip()


def render_html_report(view: Mapping[str, Any]) -> str:
    """Render an HTML report from *view* produced by :func:`build_report_view`."""

    app = view.get("app", {})
    identity = view.get("identity", {})
    result = view.get("result", {})
    topology = view.get("topology", {})
    permissions = view.get("permissions", [])
    indicators = view.get("indicators", {})
    network = view.get("network", {})
    secrets = view.get("secrets", [])
    risk = view.get("risk", {})
    run = view.get("run", {})

    badge_class = escape(str(result.get("badge_class") or "ok"))
    badge_text = escape(str(result.get("badge") or "OK"))

    pill_modules = []
    modules = topology.get("modules") if isinstance(topology, Mapping) else {}
    if isinstance(modules, Mapping):
        if modules.get("base"):
            pill_modules.append("<span class=\"pill\">base</span>")
        for entry in modules.get("config", []) or []:
            pill_modules.append(f"<span class=\"pill\">config: {escape(str(entry))}</span>")
    pill_modules.append(f"<span class=\"pill\">dex: {escape(str(topology.get('dex_count', 0)))}</span>")
    pill_modules.append(
        f"<span class=\"pill\">assets/res: {escape(str(topology.get('resource_asset_count', 0)))}</span>"
    )

    permission_rows = _render_permission_rows(permissions)
    host_pills = _render_indicator_pills(indicators.get("hosts"))
    ws_pills = _render_indicator_pills(indicators.get("ws"))
    ip_pills = _render_indicator_pills(indicators.get("ips"))

    interesting_list = "\n".join(
        f"<li class=\"mono\">{escape(str(item.get('value')))} <span class=\"muted\">#h:{escape(str(item.get('hash')))}</span></li>"
        for item in (indicators.get("interesting") or [])
    ) or ""

    secret_rows = _render_secret_rows(secrets)

    risk_score = escape(str(risk.get("score", 0)))
    risk_band = escape(str(risk.get("band", "Low")))
    risk_factors = "".join(
        f"<span class=\"pill\">{escape(str(factor))}</span>" for factor in risk.get("top_factors", [])
    )

    toolchain = run.get("toolchain", {}) if isinstance(run.get("toolchain"), Mapping) else {}
    toolchain_text = " · ".join(
        (
            f"Androguard {escape(str(toolchain.get('androguard', '—')))}",
            f"aapt2={escape(str(toolchain.get('aapt2', '—')))}",
            f"apksigner={escape(str(toolchain.get('apksigner', '—')))}",
        )
    )

    permissions_table = "\n".join(permission_rows) or _empty_table_row(3)
    secrets_table = "\n".join(secret_rows) or _empty_table_row(4)

    host_hashes = escape(str(network.get("host_hashes_csv", "—")))

    html_parts = [
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        f"<title>Static Analysis — {escape(str(app.get('name') or 'Unknown'))} ({escape(str(app.get('package') or '—'))})</title>",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<style>",
        CSS_BLOCK,
        "</style>",
        "</head>",
        "<body>",
        "<header>",
        f"  <h1>Static Analysis — {escape(str(app.get('name') or 'Unknown'))}</h1>",
        f"  <div class=\"muted\">{escape(str(app.get('package') or '—'))} • {escape(str(app.get('version_name') or '—'))} ({escape(str(app.get('version_code') or '—'))}) • {escape(str(run.get('timestamp_utc', '—')))} UTC</div>",
        "</header>",
        "<main style=\"padding:16px 24px 24px\">",
        "  <div class=\"grid\">",
        "    <section class=\"card\">",
        "      <h2>Base APK Summary</h2>",
        "      <div class=\"kvs\">",
        f"        <div>App name</div><div>{escape(str(app.get('name') or '—'))}</div>",
        f"        <div>Package</div><div class=\"mono\">{escape(str(app.get('package') or '—'))}</div>",
        f"        <div>Version</div><div>{escape(str(app.get('version_name') or '—'))} ({escape(str(app.get('version_code') or '—'))})</div>",
        f"        <div>Main activity</div><div class=\"mono\">{escape(str(app.get('main_activity') or '—'))}</div>",
        f"        <div>Size</div><div>{escape(str(identity.get('size_human', '0 B')))} ({escape(str(identity.get('size_bytes', 0)))} bytes)</div>",
        f"        <div>MD5</div><div class=\"mono\">{escape(str(identity.get('hashes', {}).get('md5', '—')))}</div>",
        f"        <div>SHA1</div><div class=\"mono\">{escape(str(identity.get('hashes', {}).get('sha1', '—')))}</div>",
        f"        <div>SHA256</div><div class=\"mono\">{escape(str(identity.get('hashes', {}).get('sha256', '—')))}</div>",
        "      </div>",
        f"      <div style=\"margin-top:12px\">Result: <span class=\"badge {badge_class}\">{badge_text}</span> &nbsp; P0={escape(str(result.get('p0', 0)))} P1={escape(str(result.get('p1', 0)))} P2={escape(str(result.get('p2', 0)))}</div>",
        "    </section>",
        "    <section class=\"card\">",
        "      <h2>Risk</h2>",
        f"      <div class=\"score\">{risk_score}</div>",
        f"      <div class=\"muted\" style=\"margin:4px 0 10px\">{risk_band}</div>",
        f"      <div>{risk_factors}</div>",
        "    </section>",
        "  </div>",
        "  <section class=\"card section\">",
        "    <h2>Topology</h2>",
        f"    <div>Modules: {' '.join(pill_modules)}</div>",
        "  </section>",
        "  <section class=\"card section\">",
        "    <h2>Permissions</h2>",
        "    <table>",
        "      <thead><tr><th>Permission</th><th>Namespace</th><th>Risk</th></tr></thead>",
        "      <tbody>",
        permissions_table,
        "      </tbody>",
        "    </table>",
        "  </section>",
        "  <section class=\"card section\">",
        "    <h2>Indicators</h2>",
        f"    <div><strong>Hosts</strong>: {host_pills or '—'}</div>",
        f"    <div style=\"margin-top:8px\"><strong>IPs</strong>: {ip_pills or '—'}</div>",
        f"    <div style=\"margin-top:8px\"><strong>WS/WSS</strong>: {ws_pills or '—'}</div>",
        "    <div style=\"margin-top:8px\"><strong>Interesting strings</strong>:",
        f"      <ul>{interesting_list}</ul>",
        "    </div>",
        "  </section>",
        "  <section class=\"card section\">",
        "    <h2>Network & TLS</h2>",
        "    <div class=\"kvs\">",
        f"      <div>http / https / ws</div><div>{escape(str(network.get('http_count', 0)))} / {escape(str(network.get('https_count', 0)))} / {escape(str(network.get('ws_count', 0)))}</div>",
        f"      <div>usesCleartextTraffic</div><div>{escape(str(network.get('uses_cleartext', '—')))}</div>",
        f"      <div>NetworkSecurityConfig</div><div class=\"mono\">{escape(str(network.get('nsc', '—')))}</div>",
        f"      <div>Pinning</div><div>{escape(str(network.get('pinning', '—')))}</div>",
        f"      <div>Host hashes</div><div class=\"mono\">{host_hashes}</div>",
        "    </div>",
        "  </section>",
        "  <section class=\"card section\">",
        "    <h2>Secrets & Credentials</h2>",
        "    <table>",
        "      <thead><tr><th>Type</th><th>Location</th><th>Value (hash)</th><th>Severity</th></tr></thead>",
        "      <tbody>",
        secrets_table,
        "      </tbody>",
        "    </table>",
        "  </section>",
        "  <section class=\"card section\">",
        "    <h2>Provenance</h2>",
        "    <div class=\"kvs\">",
        f"      <div>Profile</div><div>{escape(str(run.get('profile', 'quick')))}</div>",
        f"      <div>Verbosity</div><div>{escape(str(run.get('verbosity', 'summary')))}</div>",
        f"      <div>Evidence limit</div><div>{escape(str(run.get('evidence_limit', '—')))}</div>",
        f"      <div>Toolchain</div><div class=\"mono\">{toolchain_text}</div>",
        f"      <div>Seed</div><div class=\"mono\">{escape(str(run.get('seed', '—')))}</div>",
        "    </div>",
        "  </section>",
        "</main>",
        f"<footer>Generated by ScytaleDroid {escape(str(run.get('version', app_config.APP_VERSION)))} — Static report (HTML) mirrored from JSON source.</footer>",
        "</body>",
        "</html>",
    ]

    return "\n".join(html_parts)


def save_html_report(
    report: StaticAnalysisReport,
    view: Mapping[str, Any] | None = None,
    *,
    output_root: Path | None = None,
    mode: str | None = None,
) -> Path:
    """Persist a rendered HTML report for *report* and return the file path."""

    if view is None:
        view = build_report_view(report)
    html_content = render_html_report(view)

    manifest = report.manifest
    metadata = report.metadata or {}

    package = _slugify(
        _first_non_empty(
            manifest.package_name,
            metadata.get("package_name"),
            "artifact",
        )
    )
    artifact = _artifact_slug(metadata.get("artifact") or report.file_name)
    resolved_mode = _normalize_html_mode(mode or getattr(app_config, "STATIC_HTML_MODE", "latest"))
    latest_path, archive_path = _resolve_output_paths(
        report,
        package=package,
        artifact=artifact,
        output_root=Path(output_root or app_config.OUTPUT_DIR),
    )

    if resolved_mode in {"latest", "both"}:
        latest_path.parent.mkdir(parents=True, exist_ok=True)
        latest_path.write_text(html_content, encoding="utf-8")
    if resolved_mode in {"archive", "both"} and archive_path is not None:
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_text(html_content, encoding="utf-8")

    return latest_path if resolved_mode in {"latest", "both"} else archive_path or latest_path


def _render_permission_rows(permissions: Sequence[Mapping[str, Any]]) -> list[str]:
    rows: list[str] = []
    for entry in permissions:
        rows.append(
            "        <tr>"
            f"<td class=\"mono\">{escape(str(entry.get('display_name', '—')))}</td>"
            f"<td class=\"mono muted\">{escape(str(entry.get('namespace', '—')))}</td>"
            f"<td>{escape(str(entry.get('risk', 'Low')))}</td>"
            "</tr>"
        )
    return rows


def _render_indicator_pills(values: Any) -> str:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return ""
    pills = [f"<span class=\"pill mono\">{escape(str(value))}</span>" for value in values if value]
    return "".join(pills)


def _render_secret_rows(secrets: Sequence[Mapping[str, Any]]) -> list[str]:
    rows: list[str] = []
    for entry in secrets:
        rows.append(
            "        <tr>"
            f"<td>{escape(str(entry.get('type', 'secret')))}</td>"
            f"<td class=\"mono\">{escape(str(entry.get('location', '—')))}</td>"
            f"<td class=\"mono\">{escape(str(entry.get('value_hash', '—')))}</td>"
            f"<td>{escape(str(entry.get('severity', 'P1')))}</td>"
            "</tr>"
        )
    return rows


def _empty_table_row(colspan: int) -> str:
    return f"        <tr><td colspan=\"{colspan}\">—</td></tr>"


def _slugify(value: str) -> str:
    safe = [char if char.isalnum() or char in {"_", "-", "."} else "-" for char in value]
    return "".join(safe).strip("-") or "artifact"


def _artifact_slug(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "artifact"
    return _slugify(Path(raw).stem)


def _first_non_empty(*candidates: Any) -> Any:
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value
        if value not in (None, ""):
            return value
    return ""


def _coerce_timestamp(timestamp: str | None) -> str:
    if not timestamp:
        return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return parsed.astimezone(UTC).strftime("%Y%m%d-%H%M%S")


def _normalize_html_mode(mode: str) -> str:
    normalized = str(mode or "latest").strip().lower()
    return normalized if normalized in {"latest", "archive", "both"} else "latest"


def _resolve_output_paths(
    report: StaticAnalysisReport,
    *,
    package: str,
    artifact: str,
    output_root: Path,
) -> tuple[Path, Path | None]:
    latest_path = output_root / "reports" / "static" / "latest" / package / f"{artifact}.html"

    metadata = report.metadata or {}
    if isinstance(metadata, Mapping):
        session_label = metadata.get("session_stamp") or metadata.get("session_label")
    else:
        session_label = None
    archive_session = _slugify(str(session_label)) if session_label else _coerce_timestamp(report.generated_at)
    archive_path = (
        output_root
        / "reports"
        / "static"
        / "archive"
        / archive_session
        / package
        / f"{artifact}.html"
    )
    return latest_path, archive_path


__all__ = ["render_html_report", "save_html_report"]
