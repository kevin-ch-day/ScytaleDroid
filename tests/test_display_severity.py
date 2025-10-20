from collections import Counter

from scytaledroid.Utils.DisplayUtils import colors
from scytaledroid.Utils.DisplayUtils import severity, summary_cards


def test_normalise_counts_maps_aliases():
    counts = {"H": 2, "p2": 3, "Info": 1, "critical": 4, "unknown": 99}
    normalised = severity.normalise_counts(counts)
    assert normalised["high"] == 2
    assert normalised["medium"] == 3
    assert normalised["info"] == 1
    assert normalised["critical"] == 4
    assert normalised["low"] == 0


def test_severity_summary_items_emits_card_items():
    items = severity.severity_summary_items({"M": 2, "L": 1})
    assert len(items) == 5
    labels = [item.label for item in items]
    assert labels == ["Critical", "High", "Medium", "Low", "Info"]
    medium = next(item for item in items if item.label == "Medium")
    assert medium.value == 2
    assert medium.value_style == "severity_medium"


def test_format_severity_strip_short_labels_with_colour():
    strip = severity.format_severity_strip(Counter({"H": 1, "I": 0}), include_zero=True)
    text = colors.strip(strip)
    assert "H:1" in text
    assert "I:0" in text
    assert text.strip()  # ensure non-empty content even if colours disabled


def test_summary_card_integration_uses_auto_styles():
    items = severity.severity_summary_items({"H": 1, "L": 2})
    card = summary_cards.format_summary_card("Test", items, subtitle="demo", width=60)
    stripped = colors.strip(card)
    assert "High" in stripped
    assert "Low" in stripped
    assert "demo" in stripped
