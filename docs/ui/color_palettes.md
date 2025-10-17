# CLI Colour Palettes

ScytaleDroid ships with a small set of ANSI colour palettes that keep the
terminal UI readable across dark, light, and high-contrast themes. This note
explains how palettes are discovered, how the code is organised, and how to
tune colours for local workflows.

## Built-in presets

The canonical palette definitions live in
`scytaledroid/Utils/DisplayUtils/colors/presets.py`. Each preset is an instance
of the `Palette` dataclass defined in
`scytaledroid/Utils/DisplayUtils/colors/models.py`; the attributes map to
individual UI affordances (menu keys, badges, prompt text, etc.).

Three presets are bundled today:

| Name | Purpose |
| --- | --- |
| `fedora-dark` | Default theme optimised for dark terminals. |
| `fedora-light` | Light-background variant with matching contrast ratios. |
| `high-contrast` | Monochrome-friendly option with bold accents. |

Aliases declared in `presets.py` (for example `light` → `fedora-light`) keep the
environment variables ergonomic.

## Environment detection

Palette selection is centralised in
`scytaledroid/Utils/DisplayUtils/colors/environment.py`. When the application
starts, `detect_palette_name()` inspects the following hints:

1. `SCYTALE_UI_THEME` – explicit override (e.g. `fedora-light`).
2. `SCYTALE_UI_HIGH_CONTRAST` – any truthy value forces `high-contrast`.
3. `GTK_THEME` – heuristics that map `*-dark` / `*-light` to Fedora variants.
4. `COLORFGBG` – terminal background detection as a final fallback.

The palette module wires these hints through `register_palette()` so custom
themes can participate in the same workflow.

## Runtime registry

`scytaledroid/Utils/DisplayUtils/colors/palette.py` maintains a registry of
palettes and exposes helpers used throughout the CLI:

* `available_palettes()` – discover the palette names registered at runtime.
* `set_palette_by_name("fedora-light")` – switch interactively.
* `palette_context(palette)` – temporarily apply a palette for structured
  rendering.

### Adding custom palettes

External scripts or configuration modules can register new palettes:

```python
from dataclasses import replace
from scytaledroid.Utils.DisplayUtils import colors

# Clone the current palette and tweak accent colours.
custom = replace(colors.get_palette(), accent=("38;5;200",))
colors.register_palette("local-accent", custom, aliases=["la"])

# Activate via name or alias.
colors.set_palette_by_name("local-accent")
```

Registered palettes participate in environment detection; for example setting
`SCYTALE_UI_THEME=local-accent` will activate the custom theme on start-up.
Palettes registered at runtime can be removed with
`colors.unregister_palette("local-accent")`.

## ANSI helpers

The low-level functions that apply colour codes live in
`scytaledroid/Utils/DisplayUtils/colors/ansi.py`. They are reused by menu
renderers, table helpers, and status messages:

* `apply(text, palette.warning)` wraps a string in ANSI escape sequences.
* `highlight(text)` uses the palette’s highlight styling for emphasis.
* `strip(text)` removes colour codes before logging or exporting.

Together, the registry + presets + ANSI helpers keep UI styling predictable
while allowing analysts to tailor colours to their terminal setup.

