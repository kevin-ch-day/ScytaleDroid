#!/usr/bin/env python3
"""Generate paper-ready Android empirical tables and figures from frozen reports.

The script is read-only with respect to evidence and databases. It joins the
cutoff manifest, static exposure audit, and dynamic runtime exports into a small
15-app analysis package for manuscript tables and figures.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import statistics
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.app_category_policy import (  # noqa: E402
    app_category,
    app_display_name,
)

DEFAULT_CUTOFF_DIR = REPO_ROOT / "output" / "paper" / "dynamic_paper_cutoff_final_20260709T202819Z"
DEFAULT_AUDIT_DIR = REPO_ROOT / "output" / "audit" / "paper_regen_check" / "20260709T160803Z"

COHORT_ORDER = [
    "bbc.mobile.news.ww",
    "com.cnn.mobile.android.phone",
    "com.facebook.katana",
    "com.facebook.orca",
    "com.instagram.android",
    "com.linkedin.android",
    "com.pinterest",
    "com.reddit.frontpage",
    "org.thoughtcrime.securesms",
    "com.snapchat.android",
    "org.telegram.messenger",
    "com.guardian",
    "com.zhiliaoapp.musically",
    "com.whatsapp",
    "com.twitter.android",
]


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _num(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    return int(_num(value, default))


def _split_ids(value: Any) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _select_static_rows(rows: list[dict[str, str]], cutoff_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    by_pkg: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_pkg.setdefault(row.get("package_name", ""), []).append(row)

    selected: dict[str, dict[str, str]] = {}
    for cutoff in cutoff_rows:
        pkg = cutoff.get("package_name", "")
        version_code = str(cutoff.get("selected_version_code") or "")
        candidates = by_pkg.get(pkg, [])
        exact = [row for row in candidates if str(row.get("version_code") or "") == version_code]
        pool = exact or candidates
        if not pool:
            continue
        selected[pkg] = max(pool, key=lambda row: _int(row.get("static_run_id")))
    return selected


def _select_risk_rows(rows: list[dict[str, str]], cutoff_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    by_pkg: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_pkg.setdefault(row.get("package_name", ""), []).append(row)
    selected: dict[str, dict[str, str]] = {}
    for cutoff in cutoff_rows:
        pkg = cutoff.get("package_name", "")
        pool = by_pkg.get(pkg, [])
        if pool:
            selected[pkg] = max(pool, key=lambda row: _int(row.get("run_id")))
    return selected


def _index_by(rows: list[dict[str, str]], key: str) -> dict[str, dict[str, str]]:
    return {row.get(key, ""): row for row in rows if row.get(key)}


def _rank(values: list[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(indexed):
        j = i
        while j + 1 < len(indexed) and indexed[j + 1][1] == indexed[i][1]:
            j += 1
        avg = (i + j + 2) / 2.0
        for k in range(i, j + 1):
            ranks[indexed[k][0]] = avg
        i = j + 1
    return ranks


def _pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 2 or len(xs) != len(ys):
        return None
    mx = statistics.mean(xs)
    my = statistics.mean(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]
    denom = math.sqrt(sum(x * x for x in dx) * sum(y * y for y in dy))
    if denom == 0:
        return None
    return sum(x * y for x, y in zip(dx, dy, strict=True)) / denom


def _spearman(xs: list[float], ys: list[float]) -> float | None:
    return _pearson(_rank(xs), _rank(ys))


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines) + "\n"


def _latex_escape(value: Any) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def _latex_label(value: Any) -> str:
    return "".join(ch for ch in str(value) if ch.isalnum() or ch in {":", "_", "-", "."})


def _latex_table(caption: str, label: str, headers: list[str], rows: list[list[Any]]) -> str:
    spec = "l" * len(headers)
    body = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{" + _latex_escape(caption) + "}",
        r"\label{" + _latex_label(label) + "}",
        r"\small",
        r"\begin{tabular}{" + spec + "}",
        r"\hline",
        " & ".join(_latex_escape(h) for h in headers) + r" \\",
        r"\hline",
    ]
    for row in rows:
        body.append(" & ".join(_latex_escape(cell) for cell in row) + r" \\")
    body.extend([r"\hline", r"\end{tabular}", r"\end{table*}", ""])
    return "\n".join(body)


def _load_inputs(cutoff_dir: Path, audit_dir: Path, static_report_dir: Path | None = None) -> dict[str, Any]:
    static_report_dir = static_report_dir if static_report_dir and static_report_dir.exists() else None
    return {
        "cutoff_summary": _read_json(cutoff_dir / "summary.json") or {},
        "cutoff_manifest": _read_csv(cutoff_dir / "paper_freeze_manifest.csv"),
        "static_exposure": _read_csv(audit_dir / "static_exposure" / "static_exposure_vectors.csv"),
        "risk_rows": _read_csv(audit_dir / "static_baseline_tables" / "per_app_explainability.csv"),
        "static_report_metrics": _read_csv(static_report_dir / "data" / "app_static_metrics.csv") if static_report_dir else [],
        "paper1_score_inputs": _read_csv(static_report_dir / "tables" / "paper1_score_model_inputs.csv") if static_report_dir else [],
        "paper1_manifest_components": _read_csv(static_report_dir / "tables" / "paper1_manifest_component_parity.csv") if static_report_dir else [],
        "paper1_network_storage": _read_csv(static_report_dir / "tables" / "paper1_network_storage_parity.csv") if static_report_dir else [],
        "dynamic_app": _read_csv(audit_dir / "dynamic_paper_exports" / "per_app_summary.csv"),
        "dynamic_run": _read_csv(audit_dir / "dynamic_paper_exports" / "per_run_summary.csv"),
        "runtime_rollup": _read_csv(audit_dir / "dynamic_pcap_behavior_ml" / "app_feature_rollup.csv"),
        "baseline_stats": _read_csv(audit_dir / "dynamic_pcap_behavior_ml" / "baseline_vs_interactive_stats.csv"),
        "runtime_metric_summary": _read_csv(audit_dir / "dynamic_pcap_behavior_ml" / "cross_app_metric_summary.csv"),
        "runtime_summary": _read_json(audit_dir / "dynamic_pcap_behavior_ml" / "summary.json") or {},
    }


def _build_dataset(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    cutoff_rows = list(inputs["cutoff_manifest"])
    static_by_pkg = _select_static_rows(inputs["static_exposure"], cutoff_rows)
    report_metrics_by_pkg = _index_by(inputs.get("static_report_metrics", []), "package_name")
    paper1_inputs_by_pkg = _index_by(inputs.get("paper1_score_inputs", []), "package_name")
    paper1_manifest_by_pkg = _index_by(inputs.get("paper1_manifest_components", []), "package_name")
    paper1_network_by_pkg = _index_by(inputs.get("paper1_network_storage", []), "package_name")
    dynamic_by_pkg = _index_by(inputs["dynamic_app"], "package")
    rollup_by_pkg = _index_by(inputs["runtime_rollup"], "package_name")

    rows: list[dict[str, Any]] = []
    for cutoff in sorted(
        cutoff_rows,
        key=lambda row: COHORT_ORDER.index(row.get("package_name", ""))
        if row.get("package_name", "") in COHORT_ORDER
        else 999,
    ):
        pkg = cutoff.get("package_name", "")
        static = static_by_pkg.get(pkg, {})
        report_metrics = report_metrics_by_pkg.get(pkg, {})
        paper1_inputs = paper1_inputs_by_pkg.get(pkg, {})
        paper1_manifest = paper1_manifest_by_pkg.get(pkg, {})
        paper1_network = paper1_network_by_pkg.get(pkg, {})
        dynamic = dynamic_by_pkg.get(pkg, {})
        rollup = rollup_by_pkg.get(pkg, {})
        display = app_display_name(pkg, cutoff.get("app") or static.get("display_name") or pkg)
        total_findings = _int(report_metrics.get("detector_findings") or static.get("total_static_findings"))
        high_findings = _int(paper1_inputs.get("severity_high_count") or static.get("high_or_critical_findings"))
        medium_findings = _int(paper1_inputs.get("severity_medium_count"))
        priority_findings = high_findings + medium_findings
        static_input_count = sum(
            _int(paper1_inputs.get(key))
            for key in (
                "severity_high_count",
                "severity_medium_count",
                "masvs_privacy_count",
                "masvs_platform_non_alias_count",
                "masvs_network_count",
                "masvs_storage_count",
                "dangerous_permissions",
                "special_access_permissions",
                "exported_non_alias_components_without_permission_guard",
                "network_security_findings",
                "storage_related_findings",
                "api_key_indicators",
                "high_entropy_indicators",
            )
        )
        row = {
            "app": display,
            "package_name": pkg,
            "category": app_category(pkg, static.get("category") or "Consumer app"),
            "version_code": cutoff.get("selected_version_code", ""),
            "version_name": cutoff.get("selected_version_name", ""),
            "base_apk_sha256": cutoff.get("selected_base_apk_sha256", ""),
            "static_run_ids": cutoff.get("selected_static_run_ids", ""),
            "dynamic_run_count": len(_split_ids(cutoff.get("selected_dynamic_run_ids"))),
            "strict_idle_count": _int(cutoff.get("strict_idle_count")),
            "quiescent_fg_count": _int(cutoff.get("quiescent_fg_count")),
            "baseline_count": _int(cutoff.get("baseline_count")),
            "interactive_count": _int(cutoff.get("interactive_count")),
            "valid_pcap_count": _int(cutoff.get("valid_pcap_count")),
            "qa_valid_count": _int(cutoff.get("qa_valid_count")),
            "status": cutoff.get("status", ""),
            "selected_relation": cutoff.get("selected_relation", ""),
            "build_candidates_seen": _int(cutoff.get("build_candidates_seen")),
            "static_run_id_used": report_metrics.get("static_run_ids") or static.get("static_run_id", ""),
            "static_session": report_metrics.get("static_session_stamp") or static.get("session_stamp", ""),
            "static_score_status": paper1_inputs.get("score_status") or "legacy_score_not_used_for_claims",
            "static_exposure_input_count": static_input_count,
            "static_priority_finding_count": priority_findings,
            "total_static_findings": total_findings,
            "high_or_critical_findings": high_findings,
            "medium_static_findings": medium_findings,
            "network_findings": _int(paper1_inputs.get("network_security_findings") or static.get("network_findings")),
            "masvs_privacy_count": _int(paper1_inputs.get("masvs_privacy_count") or static.get("masvs_privacy_count")),
            "masvs_platform_count": _int(paper1_inputs.get("masvs_platform_non_alias_count") or static.get("masvs_platform_count")),
            "masvs_network_count": _int(paper1_inputs.get("masvs_network_count") or static.get("masvs_network_count")),
            "masvs_storage_count": _int(paper1_inputs.get("masvs_storage_count") or static.get("masvs_storage_count")),
            "permission_total": _int(paper1_inputs.get("total_declared_permissions") or static.get("permission_total")),
            "dangerous_permission_count": _int(paper1_inputs.get("dangerous_permissions") or static.get("dangerous_permission_count")),
            "special_access_permission_count": _int(paper1_inputs.get("special_access_permissions")),
            "custom_permission_count": _int(paper1_inputs.get("custom_permissions")),
            "exported_non_alias_components_without_permission_guard": _int(paper1_inputs.get("exported_non_alias_components_without_permission_guard")),
            "fileprovider_count": _int(paper1_manifest.get("fileprovider_like_provider_count") or static.get("fileprovider_count")),
            "provider_acl_findings": _int(static.get("provider_acl_findings")),
            "exported_provider_count": _int(static.get("exported_provider_count")),
            "cleartext_traffic_permitted": paper1_network.get("cleartext_traffic_permitted", ""),
            "legacy_external_storage_requested": paper1_network.get("legacy_external_storage_requested", ""),
            "android_backup_enabled": paper1_network.get("android_backup_enabled", ""),
            "observed_domain_count": _int(dynamic.get("observed_domain_count")),
            "service_count": _int(dynamic.get("service_count")),
            "signal_count": _int(dynamic.get("signal_count")),
            "unresolved_service_count": _int(dynamic.get("unresolved_service_count")),
            "median_unique_ja4_count": _num(rollup.get("median_unique_ja4_count")),
            "median_unique_ja3_count": _num(rollup.get("median_unique_ja3_count")),
            "baseline_stability": _num(rollup.get("baseline_stability")),
            "interactive_broadening": _num(rollup.get("interactive_broadening")),
            "strongest_shift_metric": rollup.get("strongest_shift_metric", ""),
            "strongest_shift_p_value": rollup.get("strongest_shift_p_value", ""),
            "strongest_shift_effect_band": rollup.get("strongest_shift_effect_band", ""),
            "service_families_observed": rollup.get("service_families_observed", ""),
            "inference_readiness": rollup.get("inference_readiness", ""),
        }
        rows.append(row)
    return rows


def _dataset_fields() -> list[str]:
    return [
        "app",
        "package_name",
        "category",
        "version_code",
        "version_name",
        "base_apk_sha256",
        "static_run_ids",
        "dynamic_run_count",
        "strict_idle_count",
        "quiescent_fg_count",
        "baseline_count",
        "interactive_count",
        "valid_pcap_count",
        "qa_valid_count",
        "status",
        "selected_relation",
        "build_candidates_seen",
        "static_run_id_used",
        "static_session",
        "static_score_status",
        "static_exposure_input_count",
        "static_priority_finding_count",
        "total_static_findings",
        "high_or_critical_findings",
        "medium_static_findings",
        "network_findings",
        "masvs_privacy_count",
        "masvs_platform_count",
        "masvs_network_count",
        "masvs_storage_count",
        "permission_total",
        "dangerous_permission_count",
        "special_access_permission_count",
        "custom_permission_count",
        "exported_non_alias_components_without_permission_guard",
        "fileprovider_count",
        "provider_acl_findings",
        "exported_provider_count",
        "cleartext_traffic_permitted",
        "legacy_external_storage_requested",
        "android_backup_enabled",
        "observed_domain_count",
        "service_count",
        "signal_count",
        "unresolved_service_count",
        "median_unique_ja4_count",
        "median_unique_ja3_count",
        "baseline_stability",
        "interactive_broadening",
        "strongest_shift_metric",
        "strongest_shift_p_value",
        "strongest_shift_effect_band",
        "service_families_observed",
        "inference_readiness",
    ]


def _write_data_dictionary(path: Path) -> None:
    rows = [
        {"field": "strict_idle_count", "meaning": "Valid no-touch background/idle baseline runs selected for the cutoff evidence bundle.", "source": "paper_freeze_manifest.csv"},
        {"field": "quiescent_fg_count", "meaning": "Valid no-touch foreground runs with app-driven activity; not counted as strict idle.", "source": "paper_freeze_manifest.csv"},
        {"field": "interactive_count", "meaning": "Valid manual or scripted interaction runs selected for the cutoff evidence bundle.", "source": "paper_freeze_manifest.csv"},
        {"field": "valid_pcap_count", "meaning": "Selected dynamic runs with packet-capture evidence available.", "source": "paper_freeze_manifest.csv"},
        {"field": "static_score_status", "meaning": "Status of static score use. Approved report bundles mark score inputs ready but formula unapproved.", "source": "paper1_score_model_inputs.csv"},
        {"field": "static_exposure_input_count", "meaning": "Descriptive sum of selected static score-model input counts. This is not a risk score.", "source": "paper1_score_model_inputs.csv"},
        {"field": "static_priority_finding_count", "meaning": "High plus medium static finding count for the selected app build.", "source": "paper1_score_model_inputs.csv"},
        {"field": "masvs_*_count", "meaning": "Static finding counts mapped to MASVS-oriented areas.", "source": "static_exposure_vectors.csv"},
        {"field": "observed_domain_count", "meaning": "Distinct observed domains in valid dynamic evidence exports.", "source": "per_app_summary.csv"},
        {"field": "service_count", "meaning": "Resolved service/provider families in valid dynamic evidence exports.", "source": "per_app_summary.csv"},
        {"field": "median_unique_ja4_count", "meaning": "Median JA4 diversity signal from PCAP behavior rollup.", "source": "app_feature_rollup.csv"},
    ]
    _write_csv(path, rows, ["field", "meaning", "source"])


def _make_figures(rows: list[dict[str, Any]], figures_dir: Path) -> list[dict[str, str]]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, Rectangle

    figures_dir.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, str]] = []

    def save_all(name: str) -> None:
        for ext in ("png", "pdf", "svg"):
            plt.savefig(figures_dir / f"{name}.{ext}", bbox_inches="tight", dpi=300)
        written.append({"name": name, "png": str(figures_dir / f"{name}.png"), "pdf": str(figures_dir / f"{name}.pdf"), "svg": str(figures_dir / f"{name}.svg")})
        plt.close()

    # Figure 1: study pipeline.
    fig, ax = plt.subplots(figsize=(7.2, 2.2))
    ax.axis("off")
    boxes = [
        ("APK harvest\nbase + splits", 0.02),
        ("Static analysis\nmanifest, MASVS,\nstrings, IPC", 0.27),
        ("Runtime capture\nstrict idle, QFG,\ninteractive PCAP", 0.52),
        ("Cutoff evidence\n15 build-backed\napp bundles", 0.77),
    ]
    for text, x in boxes:
        ax.add_patch(Rectangle((x, 0.28), 0.2, 0.48, fill=False, linewidth=1.2, edgecolor="#334155"))
        ax.text(x + 0.1, 0.52, text, ha="center", va="center", fontsize=8)
    for x in (0.22, 0.47, 0.72):
        ax.add_patch(FancyArrowPatch((x, 0.52), (x + 0.05, 0.52), arrowstyle="->", mutation_scale=12, linewidth=1.0))
    ax.set_title("Build-backed static/runtime evidence pipeline", fontsize=10)
    save_all("fig1_study_pipeline")

    labels = [row["app"] for row in rows]
    # Figure 2: static exposure heatmap.
    metrics = [
        ("Perm.", "permission_total"),
        ("Danger", "dangerous_permission_count"),
        ("High", "high_or_critical_findings"),
        ("Priv.", "masvs_privacy_count"),
        ("Plat.", "masvs_platform_count"),
        ("Net.", "masvs_network_count"),
        ("Stor.", "masvs_storage_count"),
        ("Prov.", "provider_acl_findings"),
    ]
    matrix: list[list[float]] = []
    for row in rows:
        values = [_num(row[key]) for _, key in metrics]
        matrix.append(values)
    normalized: list[list[float]] = []
    for i, _metric in enumerate(metrics):
        col = [line[i] for line in matrix]
        maxv = max(col) if col else 0.0
        for r, value in enumerate(col):
            if len(normalized) <= r:
                normalized.append([])
            normalized[r].append(value / maxv if maxv else 0.0)
    fig, ax = plt.subplots(figsize=(7.4, 5.4))
    im = ax.imshow(normalized, aspect="auto", cmap="viridis")
    ax.set_xticks(range(len(metrics)), [name for name, _ in metrics], rotation=35, ha="right", fontsize=8)
    ax.set_yticks(range(len(labels)), labels, fontsize=8)
    ax.set_title("Normalized static exposure indicators by app", fontsize=10)
    fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02, label="Normalized within metric")
    save_all("fig2_static_exposure_heatmap")

    # Figure 3: runtime evidence coverage by app.
    y = list(range(len(labels)))
    strict = [_int(row["strict_idle_count"]) for row in rows]
    qfg = [_int(row["quiescent_fg_count"]) for row in rows]
    interactive = [_int(row["interactive_count"]) for row in rows]
    fig, ax = plt.subplots(figsize=(7.4, 5.0))
    ax.barh(y, strict, color="#2563eb", label="Strict idle")
    ax.barh(y, qfg, left=strict, color="#f59e0b", label="QFG")
    left2 = [a + b for a, b in zip(strict, qfg, strict=True)]
    ax.barh(y, interactive, left=left2, color="#16a34a", label="Interactive")
    ax.set_yticks(y, labels, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel("Selected valid runs")
    ax.set_title("Runtime evidence classes by app")
    ax.legend(loc="lower right", fontsize=8)
    save_all("fig3_runtime_coverage_by_app")

    # Figure 4: static finding/input volume vs runtime coverage.
    fig, ax = plt.subplots(figsize=(5.8, 4.0))
    xs = [_num(row["static_priority_finding_count"]) for row in rows]
    ys = [_num(row["valid_pcap_count"]) for row in rows]
    sizes = [40 + 10 * _num(row["interactive_count"]) for row in rows]
    ax.scatter(xs, ys, s=sizes, color="#0f766e", alpha=0.8, edgecolor="white", linewidth=0.5)
    for row, x, yv in zip(rows, xs, ys, strict=True):
        ax.annotate(str(row["app"]), (x, yv), fontsize=6, xytext=(3, 2), textcoords="offset points")
    ax.set_xlabel("High + medium static findings")
    ax.set_ylabel("Selected PCAP-backed runs")
    ax.set_title("Static finding volume and runtime evidence depth")
    ax.grid(True, linewidth=0.3, alpha=0.4)
    save_all("fig4_static_runtime_scatter")

    return written


def _build_tables(rows: list[dict[str, Any]]) -> dict[str, list[list[Any]]]:
    cohort = [
        [
            row["app"],
            row["category"],
            row["package_name"],
            row["version_name"] or row["version_code"],
            row["valid_pcap_count"],
            f"{row['strict_idle_count']}/{row['quiescent_fg_count']}/{row['interactive_count']}",
        ]
        for row in rows
    ]
    static = [
        [
            row["app"],
            row["total_static_findings"],
            row["static_priority_finding_count"],
            row["dangerous_permission_count"],
            row["exported_non_alias_components_without_permission_guard"],
            row["masvs_privacy_count"],
            row["masvs_platform_count"],
            row["masvs_network_count"],
            row["provider_acl_findings"],
        ]
        for row in rows
    ]
    dynamic = [
        [
            row["app"],
            row["strict_idle_count"],
            row["quiescent_fg_count"],
            row["interactive_count"],
            row["valid_pcap_count"],
            row["observed_domain_count"],
            row["service_count"],
            row["strongest_shift_metric"],
            row["strongest_shift_effect_band"],
        ]
        for row in rows
    ]
    cross_layer: list[list[Any]] = []
    for row in rows:
        note_parts: list[str] = []
        if _num(row["high_or_critical_findings"]) >= 2:
            note_parts.append("high-priority static findings")
        if _num(row["observed_domain_count"]) >= 40:
            note_parts.append("broad observed domain surface")
        if _num(row["quiescent_fg_count"]) > 0:
            note_parts.append("QFG foreground baseline present")
        if _num(row["interactive_count"]) >= 4:
            note_parts.append("strong interactive coverage")
        if note_parts:
            cross_layer.append(
                [
                    row["app"],
                    row["static_priority_finding_count"],
                    row["valid_pcap_count"],
                    row["observed_domain_count"],
                    "; ".join(note_parts[:2]),
                ]
            )
    cross_layer.sort(key=lambda line: (-_num(line[1]), -_num(line[2]), str(line[0])))
    return {
        "cohort": cohort,
        "static": static,
        "dynamic": dynamic,
        "cross_layer": cross_layer[:10],
    }


def _write_tables(rows: list[dict[str, Any]], tables_dir: Path, latex_dir: Path) -> None:
    tables_dir.mkdir(parents=True, exist_ok=True)
    latex_dir.mkdir(parents=True, exist_ok=True)
    tables = _build_tables(rows)
    specs = {
        "table1_cohort": (
            ["App", "Category", "Package", "Version", "PCAPs", "Idle/QFG/Int"],
            tables["cohort"],
            "Fifteen-app cohort and selected cutoff evidence.",
            "tab:cohort_cutoff",
        ),
        "table2_static_findings": (
            ["App", "Findings", "High+Med", "Danger Perm.", "Unguarded Comp.", "Privacy", "Platform", "Network", "Provider ACL"],
            tables["static"],
            "Static exposure summary for selected app builds.",
            "tab:static_exposure",
        ),
        "table3_dynamic_coverage": (
            ["App", "Idle", "QFG", "Int", "PCAPs", "Domains", "Services", "Shift Metric", "Effect"],
            tables["dynamic"],
            "Runtime evidence coverage and selected behavior indicators.",
            "tab:dynamic_coverage",
        ),
        "table4_cross_layer_findings": (
            ["App", "High+Med", "PCAPs", "Domains", "Interpretation cue"],
            tables["cross_layer"],
            "Cross-layer examples linking static posture and runtime coverage.",
            "tab:cross_layer",
        ),
    }
    latex_blocks: list[str] = []
    markdown_blocks: list[str] = ["# Generated Tables\n"]
    for name, (headers, table_rows, caption, label) in specs.items():
        csv_rows = [dict(zip(headers, row, strict=True)) for row in table_rows]
        _write_csv(tables_dir / f"{name}.csv", csv_rows, headers)
        md = _md_table(headers, table_rows)
        (tables_dir / f"{name}.md").write_text(md, encoding="utf-8")
        tex = _latex_table(caption, label, headers, table_rows)
        (tables_dir / f"{name}.tex").write_text(tex, encoding="utf-8")
        latex_blocks.append(tex)
        markdown_blocks.extend([f"\n## {caption}\n", md])
    (latex_dir / "table_inputs.tex").write_text("\n".join(latex_blocks), encoding="utf-8")
    (latex_dir / "table_inputs_markdown.md").write_text("\n".join(markdown_blocks), encoding="utf-8")


def _write_latex_figure_inputs(figures: list[dict[str, str]], latex_dir: Path) -> None:
    captions = {
        "fig1_study_pipeline": "Static and runtime evidence pipeline used to assemble build-backed app bundles.",
        "fig2_static_exposure_heatmap": "Normalized static exposure indicators across the 15-app cohort.",
        "fig3_runtime_coverage_by_app": "Selected runtime evidence classes by app. QFG is reported separately from strict idle.",
        "fig4_static_runtime_scatter": "High- and medium-severity static findings compared with PCAP-backed runtime evidence depth.",
    }
    blocks: list[str] = []
    for fig in figures:
        name = fig["name"]
        blocks.extend(
            [
                r"\begin{figure}[t]",
                r"\centering",
                rf"\includegraphics[width=\columnwidth]{{assets/figures/{name}.pdf}}",
                rf"\caption{{{_latex_escape(captions.get(name, name))}}}",
                rf"\label{{{_latex_label(f'fig:{name}')}}}",
                r"\end{figure}",
                "",
            ]
        )
    (latex_dir / "figure_inputs.tex").write_text("\n".join(blocks), encoding="utf-8")


def _write_combined_latex_inputs(latex_dir: Path) -> None:
    blocks = [
        "% Generated support snippets from ScytaleDroid cutoff-window and static audit outputs.",
        "% These snippets are optional support material; keep manuscript claims aligned with the 14-day cutoff-window model.",
        "",
    ]
    for name in ("results_insert.tex", "paper2_dynamic_insert.tex", "table_inputs.tex", "figure_inputs.tex"):
        path = latex_dir / name
        if path.exists():
            blocks.append(path.read_text(encoding="utf-8").strip())
            blocks.append("")
    (latex_dir / "empirical_tables_figures_latex.tex").write_text("\n".join(blocks), encoding="utf-8")


def _write_app_evidence_bundle(rows: list[dict[str, Any]], latex_dir: Path) -> None:
    table_rows = [
        [
            row["app"],
            row["version_name"] or row["version_code"],
            row["strict_idle_count"],
            row["quiescent_fg_count"],
            row["interactive_count"],
            row["valid_pcap_count"],
            row["static_priority_finding_count"],
        ]
        for row in rows
    ]
    text = "\n".join(
        [
            "# App Evidence Bundle",
            "",
            "High+Med is the descriptive count of high- and medium-severity static findings for the selected app build. It is not a composite score.",
            "",
            _md_table(["App", "Version", "Strict idle", "QFG", "Interactive", "PCAPs", "High+Med"], table_rows),
        ]
    )
    (latex_dir / "app_evidence_bundle.md").write_text(text, encoding="utf-8")


def _format_p(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        number = float(text)
    except ValueError:
        return text
    if number < 0.001:
        return f"{number:.2e}"
    return f"{number:.3f}".rstrip("0").rstrip(".")


def _safe_round(value: Any, digits: int = 3) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(round(float(text), digits))
    except ValueError:
        return text


def _write_paper2_dynamic_bridge(
    rows: list[dict[str, Any]],
    inputs: dict[str, Any],
    tables_dir: Path,
    latex_dir: Path,
    report_dir: Path,
) -> dict[str, Any]:
    """Write a Paper 2-style dynamic bridge without claiming exact RDI reproduction."""

    runtime_summary = dict(inputs.get("runtime_summary") or {})
    metric_rows = list(inputs.get("runtime_metric_summary") or [])
    rollup_by_pkg = _index_by(inputs.get("runtime_rollup", []), "package_name")

    method_rows = [
        {
            "concept": "Non-root runtime measurement",
            "paper2_method": "Package-filtered traffic capture on non-root Android devices.",
            "current_mapping": "Current dynamic exports use local PCAP-backed runs and derived domain, service, TLS, and traffic-shape features.",
            "safe_claim": "Runtime behavior was analyzed without decrypted payload inspection.",
            "caveat": "Claims are limited to captured metadata/features and selected app windows.",
        },
        {
            "concept": "Idle versus interaction",
            "paper2_method": "Controlled idle baselines and interactive/manual app sessions.",
            "current_mapping": "Current evidence separates strict idle, quiescent foreground, and interactive captures.",
            "safe_claim": "Strict idle, QFG, and interactive observations are distinct evidence classes.",
            "caveat": "QFG is not strict idle; it captures no-touch foreground app-driven activity.",
        },
        {
            "concept": "Baseline-relative deviation",
            "paper2_method": "Baseline-trained unsupervised model and Runtime Deviation Index (RDI).",
            "current_mapping": "Current exports provide baseline-vs-interactive metric deltas, effect bands, permutation p-values, and app-level anomaly/deviation features.",
            "safe_claim": "The current package supports Paper 2-style baseline-relative runtime-deviation interpretation.",
            "caveat": "Do not call these exact RDI values unless fixed-window RDI artifacts are regenerated and selected.",
        },
        {
            "concept": "Static/dynamic relationship",
            "paper2_method": "Static exposure indicators contextualize, but do not predict, runtime deviation.",
            "current_mapping": "Static high/medium finding counts and runtime evidence depth are reported descriptively at app level.",
            "safe_claim": "Static exposure and observed runtime behavior are complementary evidence layers.",
            "caveat": "Do not infer causality or monotonic prediction from static posture to dynamic deviation.",
        },
    ]
    _write_csv(
        tables_dir / "paper2_dynamic_method_bridge.csv",
        method_rows,
        ["concept", "paper2_method", "current_mapping", "safe_claim", "caveat"],
    )

    metric_fields = [
        "metric",
        "apps_compared",
        "apps_positive_delta",
        "apps_negative_delta",
        "apps_zero_delta",
        "apps_p_le_0_10",
        "apps_p_le_0_05",
        "apps_large_effect",
        "median_delta",
        "median_abs_cliffs_delta",
        "interpretation",
    ]
    metric_rows_sorted = sorted(
        metric_rows,
        key=lambda row: (
            -_int(row.get("apps_large_effect")),
            -_int(row.get("apps_p_le_0_05")),
            str(row.get("metric") or ""),
        ),
    )
    _write_csv(tables_dir / "paper2_baseline_interactive_metric_summary.csv", metric_rows_sorted, metric_fields)

    app_proxy_rows: list[dict[str, Any]] = []
    for row in rows:
        rollup = rollup_by_pkg.get(str(row.get("package_name") or ""), {})
        app_proxy_rows.append(
            {
                "app": row["app"],
                "package_name": row["package_name"],
                "baseline_runs": rollup.get("baseline_runs", row.get("baseline_count", "")),
                "interactive_runs": rollup.get("interactive_runs", row.get("interactive_count", "")),
                "analysis_included_runs": rollup.get("analysis_included_runs", ""),
                "comparison_depth": rollup.get("comparison_depth", ""),
                "inference_readiness": rollup.get("inference_readiness", row.get("inference_readiness", "")),
                "median_unique_ja4_count": _safe_round(rollup.get("median_unique_ja4_count", row.get("median_unique_ja4_count"))),
                "median_top_ja4_share": _safe_round(rollup.get("median_top_ja4_share")),
                "baseline_stability": _safe_round(rollup.get("baseline_stability", row.get("baseline_stability"))),
                "interactive_broadening": _safe_round(rollup.get("interactive_broadening", row.get("interactive_broadening"))),
                "strongest_shift_metric": rollup.get("strongest_shift_metric", row.get("strongest_shift_metric", "")),
                "strongest_shift_p_value": _format_p(rollup.get("strongest_shift_p_value", row.get("strongest_shift_p_value", ""))),
                "strongest_shift_effect_band": rollup.get("strongest_shift_effect_band", row.get("strongest_shift_effect_band", "")),
                "interpretation": rollup.get("interpretation", ""),
            }
        )
    app_proxy_fields = [
        "app",
        "package_name",
        "baseline_runs",
        "interactive_runs",
        "analysis_included_runs",
        "comparison_depth",
        "inference_readiness",
        "median_unique_ja4_count",
        "median_top_ja4_share",
        "baseline_stability",
        "interactive_broadening",
        "strongest_shift_metric",
        "strongest_shift_p_value",
        "strongest_shift_effect_band",
        "interpretation",
    ]
    _write_csv(tables_dir / "paper2_app_runtime_deviation_proxy.csv", app_proxy_rows, app_proxy_fields)

    top_metrics = metric_rows_sorted[:4]
    top_metric_table = [
        [
            metric.get("metric", ""),
            metric.get("apps_compared", ""),
            metric.get("apps_positive_delta", ""),
            metric.get("apps_p_le_0_05", ""),
            metric.get("apps_large_effect", ""),
            _safe_round(metric.get("median_abs_cliffs_delta")),
        ]
        for metric in top_metrics
    ]
    top_app_rows = [
        [
            row["app"],
            row["baseline_runs"],
            row["interactive_runs"],
            row["strongest_shift_metric"],
            row["strongest_shift_effect_band"],
            row["strongest_shift_p_value"],
        ]
        for row in app_proxy_rows
        if row.get("strongest_shift_metric")
    ][:10]
    latex_blocks = [
        "% Paper 2-style dynamic behavior bridge. This is baseline-relative runtime evidence, not an exact RDI reproduction.",
        _latex_table(
            "Baseline-relative runtime metric shifts across apps.",
            "tab:dynamic_metric_shifts",
            ["Metric", "Apps", "+Delta", "p<=0.05", "Large", "|Cliff|"],
            top_metric_table,
        ),
        _latex_table(
            "App-level dynamic-deviation proxy summary.",
            "tab:dynamic_deviation_proxy",
            ["App", "Base", "Int", "Strongest shift", "Effect", "p"],
            top_app_rows,
        ),
        (
            "The dynamic behavior exports support a baseline-relative runtime analysis: non-root PCAP-backed "
            "sessions are separated into baseline and interactive observations, "
            "then summarized using traffic-shape and TLS-fingerprint features. The current manuscript reports these "
            "as dynamic-deviation proxy evidence rather than exact Runtime Deviation Index values, because the "
            "selected publication bundle is based on aggregate baseline-vs-interactive feature summaries."
        ),
    ]
    (latex_dir / "paper2_dynamic_insert.tex").write_text("\n\n".join(latex_blocks) + "\n", encoding="utf-8")

    notes = [
        "# Paper 2 Dynamic Behavior Bridge",
        "",
        "This bridge maps the earlier dynamic-analysis concepts onto the current 15-app evidence package without claiming an exact reproduction.",
        "",
        "## Current Dynamic Coverage",
        "",
        f"- Total dynamic runs scanned by the runtime audit: {runtime_summary.get('total_runs', '')}.",
        f"- Stats-eligible runs: {runtime_summary.get('stats_eligible_runs', '')}.",
        f"- Local PCAP-available runs: {runtime_summary.get('local_pcap_available_runs', '')}.",
        f"- Apps with stats-eligible runs: {runtime_summary.get('apps_with_stats_eligible_runs', '')}.",
        f"- Apps with interactive comparison: {runtime_summary.get('apps_with_interactive_comparison', '')}.",
        f"- Apps inference-ready: {runtime_summary.get('apps_inference_ready', '')}.",
        "",
        "## Safe Wording",
        "",
        "- Use: baseline-relative runtime behavior.",
        "- Use: dynamic-deviation proxy based on PCAP-derived traffic-shape and TLS-fingerprint features.",
        "- Use: static exposure and runtime behavior are complementary evidence layers.",
        "- Avoid: exact RDI reproduction, payload inspection, malware labeling, causal attribution, or static posture predicting runtime deviation.",
        "",
        "## Highest-Signal Metric Shifts",
        "",
        _md_table(["Metric", "Apps", "+Delta", "p<=0.05", "Large", "|Cliff|"], top_metric_table),
    ]
    (report_dir / "paper2_publication_use_notes.md").write_text("\n".join(notes), encoding="utf-8")

    return {
        "runtime_total_runs": runtime_summary.get("total_runs"),
        "runtime_stats_eligible_runs": runtime_summary.get("stats_eligible_runs"),
        "runtime_apps_with_interactive_comparison": runtime_summary.get("apps_with_interactive_comparison"),
        "runtime_apps_inference_ready": runtime_summary.get("apps_inference_ready"),
        "metric_summary_rows": len(metric_rows),
        "app_proxy_rows": len(app_proxy_rows),
    }


def _status_from_source(source_path: Path | None, fallback_exists: bool) -> str:
    if source_path is not None and source_path.exists():
        return "exact_available"
    if fallback_exists:
        return "proxy_available"
    return "missing"


def _write_paper2_reproduction_alignment(
    *,
    inputs: dict[str, Any],
    tables_dir: Path,
    report_dir: Path,
) -> dict[str, Any]:
    """Map Paper 2 PDF assets to current exact or proxy regeneration inputs."""

    phase_e_table_1 = REPO_ROOT / "output" / "_internal" / "publication" / "baseline" / "tables" / "table_1_rdi_prevalence.csv"
    phase_e_table_7 = REPO_ROOT / "output" / "_internal" / "publication" / "baseline" / "tables" / "table_7_exposure_deviation_summary.csv"
    publication_tables = REPO_ROOT / "output" / "publication" / "tables"
    interaction_table = publication_tables / "interaction_consistency_summary.csv"

    metric_rows = list(inputs.get("runtime_metric_summary") or [])
    rollup_rows = list(inputs.get("runtime_rollup") or [])
    dynamic_rows = list(inputs.get("dynamic_app") or [])
    static_rows = list(inputs.get("static_report_metrics") or inputs.get("static_exposure") or [])

    has_metric_proxy = bool(metric_rows)
    has_runtime_proxy = bool(rollup_rows or dynamic_rows)
    has_static_proxy = bool(static_rows)
    has_static_dynamic_proxy = has_runtime_proxy and has_static_proxy

    rows = [
        {
            "paper2_asset": "Table I",
            "paper2_label": "Comparison of dynamic and time-series analysis approaches",
            "exact_required_input": "Manuscript literature review sources",
            "current_regeneration_source": "Manuscript-maintained text/table",
            "status": "manuscript_only",
            "safe_current_use": "Keep as literature-review context if the references are still current and cited.",
            "caveat": "Not generated from ScytaleDroid evidence.",
        },
        {
            "paper2_asset": "Figure 1",
            "paper2_label": "Framework overview",
            "exact_required_input": "Manuscript diagram source",
            "current_regeneration_source": "fig1_study_pipeline.{png,pdf,svg}",
            "status": "proxy_available",
            "safe_current_use": "Use as an updated pipeline diagram for the current evidence workflow.",
            "caveat": "It is not the exact original Paper 2 figure.",
        },
        {
            "paper2_asset": "Table II",
            "paper2_label": "Per-app Runtime Deviation Index for idle and interactive execution",
            "exact_required_input": str(phase_e_table_1),
            "current_regeneration_source": "paper2_app_runtime_deviation_proxy.csv",
            "status": _status_from_source(phase_e_table_1, has_runtime_proxy),
            "safe_current_use": "Use exact RDI only when the Phase E table is present; otherwise use the proxy table with explicit wording.",
            "caveat": "Proxy rows are baseline-vs-interactive feature shifts, not exact RDI values.",
        },
        {
            "paper2_asset": "Table III",
            "paper2_label": "Phase-level distribution and dispersion diagnostics from per-app mean RDI",
            "exact_required_input": str(phase_e_table_1),
            "current_regeneration_source": "paper2_baseline_interactive_metric_summary.csv",
            "status": _status_from_source(phase_e_table_1, has_metric_proxy),
            "safe_current_use": "Use current metric summary for directional runtime broadening claims.",
            "caveat": "Do not report Paper 2 RDI mean, SD, CV, Shapiro, or variance-ratio values unless exact RDI rows are regenerated.",
        },
        {
            "paper2_asset": "Table IV",
            "paper2_label": "Paired effect size for interaction-induced deviation shifts",
            "exact_required_input": str(phase_e_table_1),
            "current_regeneration_source": "paper2_baseline_interactive_metric_summary.csv",
            "status": _status_from_source(phase_e_table_1, has_metric_proxy),
            "safe_current_use": "Use current effect-band counts descriptively.",
            "caveat": "Cohen's dz requires exact paired per-app RDI deltas.",
        },
        {
            "paper2_asset": "Table V",
            "paper2_label": "Descriptive statistics of per-app deviation shifts",
            "exact_required_input": str(phase_e_table_1),
            "current_regeneration_source": "paper2_baseline_interactive_metric_summary.csv",
            "status": _status_from_source(phase_e_table_1, has_metric_proxy),
            "safe_current_use": "Use current median deltas and Cliff's delta summaries as proxy evidence.",
            "caveat": "Do not copy the original n, mean, median, IQR, Wilcoxon, or n+/n- RDI values without the exact RDI table.",
        },
        {
            "paper2_asset": "Table VI",
            "paper2_label": "Consistency between scripted and manual interaction modes",
            "exact_required_input": str(interaction_table),
            "current_regeneration_source": "paper2_app_runtime_deviation_proxy.csv",
            "status": _status_from_source(interaction_table, has_runtime_proxy),
            "safe_current_use": "Use only as a descriptive note unless scripted/manual RDI rows are regenerated.",
            "caveat": "The current proxy table does not reproduce Spearman rho, mean absolute delta, RMSE, or modality-specific RDI.",
        },
        {
            "paper2_asset": "Table VII",
            "paper2_label": "Static exposure score components used for contextual reporting",
            "exact_required_input": str(phase_e_table_7),
            "current_regeneration_source": "table2_static_findings.csv",
            "status": _status_from_source(phase_e_table_7, has_static_proxy),
            "safe_current_use": "Use descriptive static exposure components; avoid unapproved composite static scores.",
            "caveat": "Current publication assets intentionally avoid a composite static score unless a reviewed formula is selected.",
        },
        {
            "paper2_asset": "Figure 2",
            "paper2_label": "Per-app deviation shifts",
            "exact_required_input": str(phase_e_table_1),
            "current_regeneration_source": "paper2_baseline_interactive_metric_summary.csv",
            "status": _status_from_source(phase_e_table_1, has_metric_proxy),
            "safe_current_use": "Use current dynamic metric-shift summaries as a replacement figure/table concept.",
            "caveat": "Exact delta-D bar/point plot requires per-app RDI deltas.",
        },
        {
            "paper2_asset": "Figure 3",
            "paper2_label": "Static posture versus interactive RDI for social media apps",
            "exact_required_input": f"{phase_e_table_1} + {phase_e_table_7}",
            "current_regeneration_source": "fig4_static_runtime_scatter.png",
            "status": "exact_available" if phase_e_table_1.exists() and phase_e_table_7.exists() else ("proxy_available" if has_static_dynamic_proxy else "missing"),
            "safe_current_use": "Use only as a descriptive static/runtime evidence-depth visual.",
            "caveat": "The current scatter is not static score versus interactive RDI.",
        },
        {
            "paper2_asset": "Figure 4",
            "paper2_label": "Static posture versus interactive RDI for messaging apps",
            "exact_required_input": f"{phase_e_table_1} + {phase_e_table_7}",
            "current_regeneration_source": "fig4_static_runtime_scatter.png",
            "status": "exact_available" if phase_e_table_1.exists() and phase_e_table_7.exists() else ("proxy_available" if has_static_dynamic_proxy else "missing"),
            "safe_current_use": "Use only as a descriptive static/runtime evidence-depth visual.",
            "caveat": "The current scatter is not category-filtered static score versus interactive RDI.",
        },
    ]

    fields = [
        "paper2_asset",
        "paper2_label",
        "exact_required_input",
        "current_regeneration_source",
        "status",
        "safe_current_use",
        "caveat",
    ]
    _write_csv(tables_dir / "paper2_original_asset_alignment.csv", rows, fields)

    status_counts = dict(Counter(row["status"] for row in rows))
    md_rows = [
        [
            row["paper2_asset"],
            row["paper2_label"],
            row["status"],
            row["current_regeneration_source"],
            row["caveat"],
        ]
        for row in rows
    ]
    report = [
        "# Paper 2 Original Asset Alignment",
        "",
        "This file maps the uploaded Paper 2 PDF tables and figures to the evidence currently available in this checkout.",
        "",
        "Statuses:",
        "",
        "- `exact_available`: the original RDI/static input artifact is present.",
        "- `proxy_available`: current ScytaleDroid data can support a related, clearly caveated replacement.",
        "- `manuscript_only`: the item is literature or diagram material, not a generated evidence artifact.",
        "- `missing`: neither an exact source nor a safe proxy was found.",
        "",
        f"Status counts: `{json.dumps(status_counts, sort_keys=True)}`",
        "",
        _md_table(["Asset", "Paper 2 label", "Status", "Current source", "Caveat"], md_rows),
        "## Bottom Line",
        "",
        "The current checkout can produce a Paper 2-style dynamic behavior bridge, but it should not claim exact reproduction of the original RDI tables unless the frozen Phase E RDI prevalence and static-deviation tables are restored or regenerated.",
    ]
    (report_dir / "paper2_original_asset_alignment.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    return {
        "rows": len(rows),
        "status_counts": status_counts,
        "exact_rdi_table_present": phase_e_table_1.exists(),
        "exact_static_dynamic_table_present": phase_e_table_7.exists(),
        "alignment_csv": str((tables_dir / "paper2_original_asset_alignment.csv").resolve()),
        "alignment_report": str((report_dir / "paper2_original_asset_alignment.md").resolve()),
    }


def _write_stats(rows: list[dict[str, Any]], path: Path) -> dict[str, Any]:
    xs = [_num(row["static_priority_finding_count"]) for row in rows]
    pcap = [_num(row["valid_pcap_count"]) for row in rows]
    domains = [_num(row["observed_domain_count"]) for row in rows]
    rho_pcap = _spearman(xs, pcap)
    rho_domains = _spearman(xs, domains)
    payload = {
        "n_apps": len(rows),
        "apps_with_build_backed_cutoff_evidence": len(rows),
        "true_evidence_holes": sum(1 for row in rows if _int(row["valid_pcap_count"]) == 0),
        "workflow_ready_apps": sum(1 for row in rows if str(row.get("status")) == "ready"),
        "apps_needing_more_interactive_depth": sum(
            1 for row in rows if "interactive" in str(row.get("status") or "").lower()
        ),
        "total_selected_valid_pcaps": sum(_int(row["valid_pcap_count"]) for row in rows),
        "total_strict_idle_runs": sum(_int(row["strict_idle_count"]) for row in rows),
        "total_qfg_runs": sum(_int(row["quiescent_fg_count"]) for row in rows),
        "total_interactive_runs": sum(_int(row["interactive_count"]) for row in rows),
        "static_score_status_counts": dict(Counter(str(row.get("static_score_status") or "unknown") for row in rows)),
        "spearman_static_priority_findings_vs_pcap_count": None if rho_pcap is None else round(rho_pcap, 4),
        "spearman_static_priority_findings_vs_observed_domain_count": None if rho_domains is None else round(rho_domains, 4),
        "statistical_note": "Correlations are descriptive at app level (n=15) and should not be interpreted as causal.",
    }
    rows_out = [{"metric": key, "value": value} for key, value in payload.items()]
    _write_csv(path, rows_out, ["metric", "value"])
    return payload


def _write_reports(rows: list[dict[str, Any]], stats: dict[str, Any], report_dir: Path, source_paths: dict[str, str]) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    findings = [
        "# Empirical Findings Draft Notes",
        "",
        f"- Apps with build-backed cutoff evidence: {stats['apps_with_build_backed_cutoff_evidence']}/{stats['n_apps']}.",
        f"- True evidence holes: {stats['true_evidence_holes']}.",
        f"- Workflow-ready apps: {stats['workflow_ready_apps']}/{stats['n_apps']}; apps needing more interactive depth: {stats['apps_needing_more_interactive_depth']}.",
        f"- Selected PCAP-backed dynamic runs: {stats['total_selected_valid_pcaps']}.",
        f"- Runtime evidence classes: strict idle={stats['total_strict_idle_runs']}, QFG={stats['total_qfg_runs']}, interactive={stats['total_interactive_runs']}.",
        f"- Static priority-finding count vs PCAP-count Spearman rho: {stats['spearman_static_priority_findings_vs_pcap_count']}.",
        f"- Static priority-finding count vs observed-domain-count Spearman rho: {stats['spearman_static_priority_findings_vs_observed_domain_count']}.",
        "",
        "Use these results as descriptive cohort evidence. Do not claim payload inspection, causal attribution, or complete coverage of every future app build.",
    ]
    (report_dir / "empirical_findings.md").write_text("\n".join(findings) + "\n", encoding="utf-8")
    recs = [
        "# Manuscript Asset Recommendations",
        "",
        "- Use `table1_cohort` early in the methodology/results transition.",
        "- Use `table2_static_findings` for the static exposure results.",
        "- Use `table3_dynamic_coverage` to separate strict idle, QFG, and interactive evidence.",
        "- Use `fig2_static_exposure_heatmap` and `fig3_runtime_coverage_by_app` as the highest-value visuals.",
        "- Use `fig4_static_runtime_scatter` only with cautious language: it compares evidence dimensions; it does not prove prediction.",
        "",
        "Source files:",
    ]
    recs.extend(f"- {key}: `{value}`" for key, value in source_paths.items())
    (report_dir / "artifact_recommendations.md").write_text("\n".join(recs) + "\n", encoding="utf-8")


def _copy_to_paper(output_dir: Path, paper_root: Path) -> list[str]:
    copied: list[str] = []
    fig_dst = paper_root / "assets" / "figures"
    gen_dst = paper_root / "generated"
    fig_dst.mkdir(parents=True, exist_ok=True)
    gen_dst.mkdir(parents=True, exist_ok=True)
    for path in (output_dir / "figures").glob("fig*.*"):
        target = fig_dst / path.name
        shutil.copy2(path, target)
        copied.append(str(target))
    for name in (
        "figure_inputs.tex",
        "table_inputs.tex",
        "table_inputs_markdown.md",
        "results_insert.tex",
        "paper2_dynamic_insert.tex",
        "empirical_tables_figures_latex.tex",
        "app_evidence_bundle.md",
    ):
        src = output_dir / "latex" / name
        if src.exists():
            target = gen_dst / name
            shutil.copy2(src, target)
            copied.append(str(target))
    for name in (
        "paper2_publication_use_notes.md",
        "paper2_original_asset_alignment.md",
    ):
        src = output_dir / "report" / name
        if src.exists():
            target = gen_dst / name
            shutil.copy2(src, target)
            copied.append(str(target))
    return copied


def _write_results_insert(rows: list[dict[str, Any]], stats: dict[str, Any], latex_dir: Path) -> None:
    text = rf"""% Auto-generated descriptive results block.
The final cutoff dataset contained {stats['apps_with_build_backed_cutoff_evidence']} of {stats['n_apps']} Android consumer applications with build-backed evidence bundles and {stats['true_evidence_holes']} true evidence holes. The selected runtime evidence included {stats['total_selected_valid_pcaps']} PCAP-backed valid runs: {stats['total_strict_idle_runs']} strict idle runs, {stats['total_qfg_runs']} quiescent foreground runs, and {stats['total_interactive_runs']} interactive runs. QFG captures are reported separately from strict idle because they represent no-touch foreground observations in which app-driven network activity continued.

At the app level, the descriptive Spearman association between high/medium static finding count and selected PCAP count was {stats['spearman_static_priority_findings_vs_pcap_count']}; the association between high/medium static finding count and observed domain count was {stats['spearman_static_priority_findings_vs_observed_domain_count']}. These app-level associations are descriptive only and should not be interpreted as causal or predictive evidence. No composite static scoring value is reported because no reviewed formula is approved for this publication profile.
"""
    (latex_dir / "results_insert.tex").write_text(text, encoding="utf-8")


def generate_assets(
    *,
    cutoff_dir: Path,
    audit_dir: Path,
    output_dir: Path,
    static_report_dir: Path | None = None,
    copy_to_paper: Path | None = None,
) -> dict[str, Any]:
    inputs = _load_inputs(cutoff_dir, audit_dir, static_report_dir)
    if not inputs["cutoff_manifest"]:
        raise SystemExit(f"Missing or empty cutoff manifest: {cutoff_dir / 'paper_freeze_manifest.csv'}")

    rows = _build_dataset(inputs)
    data_dir = output_dir / "data"
    figures_dir = output_dir / "figures"
    tables_dir = output_dir / "tables"
    latex_dir = output_dir / "latex"
    report_dir = output_dir / "report"
    for directory in (data_dir, figures_dir, tables_dir, latex_dir, report_dir):
        directory.mkdir(parents=True, exist_ok=True)

    _write_csv(data_dir / "analysis_dataset.csv", rows, _dataset_fields())
    _write_data_dictionary(data_dir / "analysis_dictionary.csv")
    stats = _write_stats(rows, data_dir / "statistical_results.csv")
    figures = _make_figures(rows, figures_dir)
    _write_tables(rows, tables_dir, latex_dir)
    paper2_bridge = _write_paper2_dynamic_bridge(rows, inputs, tables_dir, latex_dir, report_dir)
    paper2_alignment = _write_paper2_reproduction_alignment(
        inputs=inputs,
        tables_dir=tables_dir,
        report_dir=report_dir,
    )
    _write_latex_figure_inputs(figures, latex_dir)
    _write_results_insert(rows, stats, latex_dir)
    _write_combined_latex_inputs(latex_dir)
    _write_app_evidence_bundle(rows, latex_dir)

    source_paths = {
        "cutoff_manifest": str((cutoff_dir / "paper_freeze_manifest.csv").resolve()),
        "cutoff_summary": str((cutoff_dir / "summary.json").resolve()),
        "static_exposure": str((audit_dir / "static_exposure" / "static_exposure_vectors.csv").resolve()),
        "static_report": str(static_report_dir.resolve()) if static_report_dir else "",
        "static_score_inputs": str((static_report_dir / "tables" / "paper1_score_model_inputs.csv").resolve()) if static_report_dir else "",
        "dynamic_per_app": str((audit_dir / "dynamic_paper_exports" / "per_app_summary.csv").resolve()),
        "dynamic_rollup": str((audit_dir / "dynamic_pcap_behavior_ml" / "app_feature_rollup.csv").resolve()),
        "dynamic_metric_summary": str((audit_dir / "dynamic_pcap_behavior_ml" / "cross_app_metric_summary.csv").resolve()),
        "dynamic_pcap_summary": str((audit_dir / "dynamic_pcap_behavior_ml" / "summary.json").resolve()),
    }
    _write_reports(rows, stats, report_dir, source_paths)

    copied: list[str] = []
    if copy_to_paper is not None:
        copied = _copy_to_paper(output_dir, copy_to_paper)

    summary = {
        "status": "OK",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "output_dir": str(output_dir.resolve()),
        "cutoff_dir": str(cutoff_dir.resolve()),
        "audit_dir": str(audit_dir.resolve()),
        "apps": len(rows),
        "figures": figures,
        "tables": sorted(str(path) for path in tables_dir.glob("*.csv")),
        "stats": stats,
        "paper2_dynamic_bridge": paper2_bridge,
        "paper2_original_asset_alignment": paper2_alignment,
        "copied_to_paper": copied,
    }
    _write_json(output_dir / "analysis_summary.json", summary)
    _write_json(
        output_dir / "analysis_manifest.json",
        {
            "tool": "scripts/publication/generate_android_empirical_assets.py",
            "generated_at_utc": summary["generated_at_utc"],
            "source_paths": source_paths,
            "outputs": {
                "dataset": str((data_dir / "analysis_dataset.csv").resolve()),
                "statistics": str((data_dir / "statistical_results.csv").resolve()),
                "latex_dir": str(latex_dir.resolve()),
                "figures_dir": str(figures_dir.resolve()),
                "tables_dir": str(tables_dir.resolve()),
            },
            "notes": [
                "Read-only derived report; no evidence, APK, DB, or runtime collection mutation.",
                "Prior papers are not cited or used as source evidence by this generator.",
            ],
        },
    )
    return summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cutoff-dir", default=str(DEFAULT_CUTOFF_DIR), help="Final dynamic cutoff report directory.")
    parser.add_argument(
        "--audit-dir",
        default=str(DEFAULT_AUDIT_DIR),
        help="Audit directory containing static_exposure, static_baseline_tables, and dynamic exports.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPO_ROOT / "output" / "paper" / f"android_empirical_analysis_{_stamp()}"),
        help="Output directory for derived tables, figures, and LaTeX snippets.",
    )
    parser.add_argument(
        "--static-report-dir",
        default=None,
        help="Optional static_exposure_privacy report bundle. When provided, Paper 1-style score-input tables replace legacy static scoring fields.",
    )
    parser.add_argument(
        "--copy-to-paper",
        default=None,
        help="Optional LaTeX repo root to receive generated figures and LaTeX snippets.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = generate_assets(
        cutoff_dir=Path(args.cutoff_dir).expanduser().resolve(),
        audit_dir=Path(args.audit_dir).expanduser().resolve(),
        output_dir=Path(args.output_dir).expanduser().resolve(),
        static_report_dir=Path(args.static_report_dir).expanduser().resolve() if args.static_report_dir else None,
        copy_to_paper=Path(args.copy_to_paper).expanduser().resolve() if args.copy_to_paper else None,
    )
    print(json.dumps({"status": summary["status"], "output_dir": summary["output_dir"], "apps": summary["apps"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
