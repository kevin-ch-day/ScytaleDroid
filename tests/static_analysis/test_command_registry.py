from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.commands import COMMANDS, get_command, iter_commands
from scytaledroid.StaticAnalysis.cli.commands.models import SelectionMode


def test_command_registry_contains_only_scan_commands_with_unique_ids():
    ids = [cmd.id for cmd in COMMANDS]

    assert len(ids) == len(set(ids))
    assert {cmd.kind for cmd in COMMANDS} == {"scan", "readonly"}


def test_static_menu_command_layout_reflects_pruned_contract():
    commands = tuple(iter_commands("scan"))
    by_id = {cmd.id: cmd for cmd in commands}

    assert set(by_id) == {"1", "2", "3", "4"}
    assert by_id["4"].section == "history"
    assert by_id["4"].selection_mode is SelectionMode.DIFF_LAST
    drilldown = get_command("D")
    assert drilldown is not None
    assert drilldown.kind == "readonly"
    assert drilldown.section == "tools"
    assert get_command("5") is None
    assert get_command("6") is None
