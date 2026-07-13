# Paper 2 v2 Claim Map

Status: **NOT READY**.

| Claim | Current status | Evidence | Caveat |
| --- | --- | --- | --- |
| The current locked package contains 15 apps and 112 included runs. | Supported | `publication_results_v2.json`, `paper2_qa_v2.json` | Pre-CNN-update lock only. |
| Inclusion/exclusion accounting is exact. | Supported | `paper2_excluded_runs_v2.csv`, QA `exclusion_accounting.status=OK` | Candidate count has changed with new evidence: 288 candidates, 112 included, 176 excluded. |
| Static/dynamic identity alignment is exact for the current lock. | Supported | `paper2_static_alignment_v2.csv` | Static session names are not yet exported; static run IDs and hashes are present. |
| Scored window counts reconcile for included runs. | Supported | `paper2_window_reconciliation_v2.csv` | Raw pre-drop rows are represented by plan metadata, not separate raw feature-row files. |
| Interactive RDI exceeds baseline RDI for all 15 apps under pooled IF. | Supported for current lock | independent validation manifest | Does not prove general behavior outside this lock. |
| The paired Wilcoxon result is W=0, two-sided exact p=0.00006103515625. | Supported for current lock | independent validation manifest | Use two-sided result unless directional hypothesis is pre-registered. |
| Baseline traffic is stable. | Not safe | Not yet available | Need held-out baseline and baseline-to-baseline validation. |
| Isolation Forest improves beyond simple volume metrics. | Not safe | Not yet available | Need simple baselines and feature ablation. |
| The method is time-series/sequence modeling. | Not safe without rewording | Not yet available | Need temporal-order controls. Prefer "windowed runtime network behavior" for now. |
| CNN build 19407005 should replace CNN build 19250507. | Not decided | CNN audit confirms 8 valid local runs | Requires one anchor rebuild and normal selection algorithm result. |
