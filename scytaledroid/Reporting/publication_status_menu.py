"""Publication archive status assembly for the reporting menu."""

from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    resolve_dataset_freeze_read_path,
)


def fetch_publication_status() -> dict[str, object]:
    """Return a compact publication status snapshot."""

    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
        run_freeze_readiness_audit,
    )
    from scytaledroid.Publication.publication_contract import lint_publication_bundle
    from scytaledroid.Reporting.services.publication_status import (
        fetch_latest_analysis_snapshot,
    )

    status: dict[str, object] = {
        "freeze_audit_result": "unknown",
        "paper_audit_result": "unknown",
        "can_freeze": False,
        "evidence_quota_counted": None,
        "evidence_quota_expected": None,
        "freeze_dataset_hash": None,
        "publication_ready": False,
        "publication_root_label": "output/publication",
        "publication_tables_label": "0",
        "publication_figures_label": "0",
        "results_numbers_label": "missing",
        "exports_label": "missing",
        "qa_label": "missing",
        "analysis_ready": False,
        "analysis_label": "missing",
        "analysis_cohort_label": None,
        "footer": "",
    }

    try:
        audit = run_freeze_readiness_audit()
        status["freeze_audit_result"] = str(audit.result)
        status["paper_audit_result"] = str(audit.result)
        status["can_freeze"] = bool(audit.can_freeze)
        try:
            status["evidence_quota_expected"] = int(audit.expected_valid_runs)
        except Exception:
            status["evidence_quota_expected"] = None
    except Exception:
        pass

    try:
        analysis_snapshot = fetch_latest_analysis_snapshot()
    except Exception:
        analysis_snapshot = None
    if analysis_snapshot:
        status["analysis_ready"] = bool(analysis_snapshot.get("ready"))
        status["analysis_label"] = str(analysis_snapshot.get("summary_label") or "missing")
        status["analysis_cohort_label"] = str(analysis_snapshot.get("cohort_id") or "").strip() or None

    freeze_path = resolve_dataset_freeze_read_path()
    if freeze_path.exists():
        try:
            payload = json.loads(freeze_path.read_text(encoding="utf-8"))
            status["freeze_dataset_hash"] = payload.get("freeze_dataset_hash")
            included = payload.get("included_run_ids") or []
            status["evidence_quota_counted"] = int(len(included)) if isinstance(included, list) else None
        except Exception:
            status["freeze_dataset_hash"] = None

    pub_root = Path(app_config.OUTPUT_DIR) / "publication"
    status["publication_root_label"] = str(_relative_path(pub_root))
    lint = lint_publication_bundle(pub_root)
    tables_dir = pub_root / "tables"
    figs_dir = pub_root / "figures"
    results_numbers = pub_root / "appendix" / "results_section_V.md"
    paste_blocks = pub_root / "appendix" / "publication_paste_blocks.md"
    paste_blocks_legacy = pub_root / "appendix" / "paper2_ieee_paste_blocks.md"
    qa_dir = pub_root / "qa"
    exports = [
        Path(app_config.DATA_DIR) / "archive" / "dynamic_run_summary.csv",
        Path(app_config.DATA_DIR) / "archive" / "pcap_features.csv",
        Path(app_config.DATA_DIR) / "archive" / "protocol_ledger.csv",
    ]

    if tables_dir.exists():
        status["publication_tables_label"] = str(len(list(tables_dir.glob("*.csv"))))
    if figs_dir.exists():
        paper_figs = []
        for path in figs_dir.glob("*.png"):
            stem = path.stem.lower()
            if stem.startswith(("fig_b1", "fig_b2", "fig_b3", "fig_b4")):
                paper_figs.append(path)
        status["publication_figures_label"] = str(len(paper_figs))
    if results_numbers.exists() or paste_blocks.exists() or paste_blocks_legacy.exists():
        status["results_numbers_label"] = "present"
    if all(path.exists() for path in exports):
        status["exports_label"] = "present"
    if qa_dir.exists() and (qa_dir / "qa_stats_validation.json").exists():
        status["qa_label"] = "present"

    status["publication_ready"] = bool(lint.ok)
    if not status["publication_ready"]:
        first = lint.errors[0] if lint.errors else "unknown"
        status["footer"] = f"Publication bundle NOT READY ({first}). Run: 1) Regenerate artifacts, then 5) Write bundle."
    else:
        status["footer"] = ""
    if status.get("analysis_cohort_label"):
        db_hint = f"DB cohort: {status['analysis_cohort_label']}"
        status["footer"] = f"{status['footer']} {db_hint}".strip()

    return status


def _relative_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


__all__ = ["fetch_publication_status"]
