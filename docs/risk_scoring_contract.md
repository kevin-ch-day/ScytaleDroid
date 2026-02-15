# Risk Scoring Contract

Authoritative score store: `risk_scores` (not transient run payloads).

## Formula + Bounds
- Composite score range: `0..100` (hard cap).
- Base contributors (from `scytaledroid/StaticAnalysis/risk/scoring.py`):
  - Secrets:
    - `P0` secret: `+45` each
    - `P1` secret: `+25` each
    - Secrets subtotal cap: `75`
  - Cleartext traffic: `+20` if HTTP endpoints exist and manifest allows cleartext with `INTERNET`.
  - High-risk permissions: `+5` each, cap `20`.
- Band thresholds:
  - `High` if score `>= 70`
  - `Medium` if score `>= 40`
  - `Low` otherwise

## Persisted Breakdown (Corpus Tables)
- `risk_scores.risk_score` and `risk_scores.risk_grade` are canonical.
- Persisted dimension columns:
  - `dangerous`
  - `signature`
  - `vendor`
- Aggregate scripts must read these columns directly from `risk_scores`.

## Explainability Output Contract
- Per-app explainability artifact must contain:
  - `package_name`
  - `session_stamp`
  - `scope_label`
  - `risk_score`
  - `risk_grade`
  - `breakdown`:
    - `dangerous`
    - `signature`
    - `vendor`
  - `top_contributors` (top N static findings):
    - `rule_id`, `title`, `severity`, `detector`, `evidence_hash`
- Contract target: an operator must answer “why score=X” in under 60 seconds from one JSON artifact plus DB row lookup.
