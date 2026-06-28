from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.menus import process_guard


def test_dynamic_menu_code_paths_follow_dynamicanalysis_root() -> None:
    menu_file = Path(process_guard.__file__).resolve().parent / "dynamic_menu.py"

    paths = process_guard.dynamic_menu_code_paths(menu_file)

    assert set(paths) == {
        "dynamic_menu.py",
        "guided_run.py",
        "manual.py",
        "manual_templates.py",
        "paper_eligibility.py",
    }
    assert all(path.exists() for path in paths.values())
    assert paths["guided_run.py"].as_posix().endswith("/DynamicAnalysis/controllers/guided_run.py")
    assert paths["manual.py"].as_posix().endswith("/DynamicAnalysis/scenarios/manual.py")


def test_warn_if_dynamic_menu_code_changed_reports_changed_files(monkeypatch) -> None:
    menu_file = Path(process_guard.__file__).resolve().parent / "dynamic_menu.py"
    start_signature = {
        "dynamic_menu.py": "same",
        "guided_run.py": "same",
        "manual.py": "same",
        "manual_templates.py": "same",
        "paper_eligibility.py": "same",
    }
    monkeypatch.setattr(
        process_guard,
        "build_dynamic_menu_code_signature",
        lambda _menu_file: {
            "dynamic_menu.py": "same",
            "guided_run.py": "changed",
            "manual.py": "same",
            "manual_templates.py": "same",
            "paper_eligibility.py": "same",
        },
    )
    emitted: list[tuple[str, str]] = []
    monkeypatch.setattr(
        process_guard.status_messages,
        "print_status",
        lambda message, *, level="info": emitted.append((level, message)),
    )

    process_guard.warn_if_dynamic_menu_code_changed(
        menu_file=menu_file,
        start_signature=start_signature,
    )

    assert emitted == [
        (
            "warn",
            "Code changed on disk since this Dynamic Analysis menu started (guided_run.py).",
        ),
        (
            "warn",
            "Exit ScytaleDroid completely (Main Menu -> 0) and restart to apply the new templates/logic.",
        ),
    ]
