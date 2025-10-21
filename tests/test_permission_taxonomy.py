from scytaledroid.Database.db_func.permissions import permission_support, taxonomy


def test_seed_signal_catalog_normalizes_band_and_stage(monkeypatch):
    """Signal seeding should coerce band/stage to canonical tokens."""

    captured: list[tuple[str, dict[str, object]]] = []

    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **kwargs):
        text = " ".join(query.split())
        if "SELECT signal_key" in text:
            return []
        captured.append((text, params or {}))
        return None

    monkeypatch.setattr(permission_support, "run_sql", fake_run_sql)

    payload = {
        "signal_key": "perm_declared_camera",
        "display_name": "Camera",
        "description": "Declared camera usage",
        "default_weight": 1.0,
        "default_band": "HIGH",  # upper-case should be normalized
        "stage": "Declared",  # mixed-case should be normalized
    }

    status = permission_support.seed_signal_catalog([payload])

    assert status == {"inserted": 1, "updated": 0}
    assert captured, "expected INSERT call"
    insert_params = captured[0][1]
    assert insert_params["default_band"] == "high"
    assert insert_params["stage"] == "declared"


def test_fetch_permission_map_returns_band(monkeypatch):
    rows = [
        {"perm_name": "android.permission.CAMERA", "group_key": "camera", "band": "high", "notes": None, "updated_at": None}
    ]

    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **kwargs):
        assert "band" in query.lower()
        return rows

    monkeypatch.setattr(taxonomy, "run_sql", fake_run_sql)

    result = taxonomy.fetch_permission_map()

    assert result == rows
    assert result[0]["band"] == "high"
