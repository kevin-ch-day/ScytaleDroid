from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import colors, table_utils


def test_render_table_accepts_coloured_cells(force_color, capsys):
    palette = colors.get_palette()
    coloured_state = colors.apply("● DEVICE", palette.success, bold=True)

    table_utils.render_table(
        ["Device", "State"],
        [("moto g 5G", coloured_state)],
        padding=1,
        accent_first_column=False,
    )

    output = capsys.readouterr().out.strip().splitlines()
    assert len(output) == 3
    assert "moto g 5g" in colors.strip(output[2]).lower()
    assert "● DEVICE" in colors.strip(output[2])
