import json


def test_paper_provenance_includes_locked_constants():
    from scytaledroid.DynamicAnalysis.ml import artifact_bundle_writer as writer
    from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config

    payload = writer._paper_provenance(freeze_sha256="abc123")
    assert payload["window_size_s"] == str(config.WINDOW_SIZE_S)
    assert payload["window_stride_s"] == str(config.WINDOW_STRIDE_S)
    assert payload["min_windows_baseline"] == str(config.MIN_WINDOWS_BASELINE)
    assert payload["min_pcap_bytes_fallback"] == str(config.MIN_PCAP_BYTES_FALLBACK)
    assert payload["np_percentile_method"] == str(config.NP_PERCENTILE_METHOD)


def test_phrase_lint_report_flags_prohibited_phrases(tmp_path):
    from scytaledroid.DynamicAnalysis.ml import artifact_bundle_writer as writer

    target = tmp_path / "report.txt"
    target.write_text("This section references outbound traffic trends.", encoding="utf-8")
    out = tmp_path / "lint.json"
    writer._write_phrase_lint_report(target_paths=(target,), out_path=out)
    payload = json.loads(out.read_text(encoding="utf-8"))

    assert payload["ok"] is False
    assert any(v["phrase"] == "outbound traffic" for v in payload["violations"])


def test_table_8_model_comparison_metrics_writes_required_columns(tmp_path, monkeypatch):
    from scytaledroid.DynamicAnalysis.ml import artifact_bundle_writer as writer

    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    prevalence = data_dir / "anomaly_prevalence_per_app_phase.csv"
    overlap = data_dir / "model_overlap_per_run.csv"

    prevalence.write_text(
        "package_name,phase,model,flagged_pct,training_mode\n"
        "com.example,interactive,isolation_forest,0.40,union_fallback\n"
        "com.example,interactive,one_class_svm,0.30,union_fallback\n",
        encoding="utf-8",
    )
    overlap.write_text(
        "package_name,run_id,phase,interaction_tag,training_mode,windows_total,iforest_flagged,ocsvm_flagged,both_flagged,either_flagged,jaccard,ml_schema_version\n"
        "com.example,r1,interactive,normal,union_fallback,10,4,3,2,5,0.4,1\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(writer, "dataset_tables_dir", lambda: data_dir)
    tables_dir = tmp_path / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    csv_path, _, _ = writer._write_table_8_model_comparison_metrics(
        tables_dir,
        provenance={"freeze_anchor": "x"},
    )

    text = csv_path.read_text(encoding="utf-8")
    assert "spearman_rho_if_vs_ocsvm" in text
    assert "mean_abs_delta_flagged_pct" in text
    assert "agreement_pct_jointly_flagged" in text
    assert "comparability" in text
    assert "degraded comparability" in text
