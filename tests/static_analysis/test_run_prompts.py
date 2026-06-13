from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.core import run_prompts


def test_prompt_advanced_options_can_disable_split_scan(monkeypatch) -> None:
    params = RunParameters(
        profile="full",
        scope="profile",
        scope_label="Research Dataset Alpha",
        scan_splits=True,
    )

    monkeypatch.setattr(run_prompts, "prompt_int", lambda _label, default, **_kwargs: default)
    monkeypatch.setattr(run_prompts, "prompt_float", lambda _label, default, **_kwargs: default)
    monkeypatch.setattr(run_prompts, "prompt_choice", lambda _label, _options, *, default: default)
    monkeypatch.setattr(
        run_prompts.prompt_utils,
        "prompt_text",
        lambda _label, default="", **_kwargs: default,
    )

    yes_no_answers = {
        "Modify advanced options?": True,
        "Reuse disk cache": params.reuse_cache,
        "Verbose output": params.verbose_output,
        "Artifact detail output": params.artifact_detail,
        "Split APK scan (scan base + split APKs)": False,
        "Dry-run (no persistence)": params.dry_run,
        "Refresh permission snapshot after detector run": params.permission_snapshot_refresh,
    }
    monkeypatch.setattr(
        run_prompts.prompt_utils,
        "prompt_yes_no",
        lambda label, default=False: yes_no_answers.get(label, default),
    )

    updated = run_prompts.prompt_advanced_options(params)

    assert updated.scan_splits is False
    summary = dict(run_prompts._summarise_params(updated))
    assert summary["Split APK scan"] == "No"

