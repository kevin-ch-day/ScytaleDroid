# String Intelligence Exploratory Mode

The string intelligence pipeline now exposes an **exploratory mode** so analysts can
validate collection quality, inspect ranges, and spot anomalous runs before
sifting through scored findings.

> **Note:** Exploratory summaries now lean on the normalised string index plus
> the aggregate helpers in
> `scytaledroid/StaticAnalysis/modules/string_analysis/`. Regex catalogs and
> signal tags are centralised under `constants.py` / `matcher.py`, so tuning a
> provider or keyword automatically surfaces here without touching the CLI
> renderer.

```
python -m scytaledroid.StaticAnalysis.cli.renderer --explore --profile full <apk-report.json>
```

When `--explore` is enabled, the renderer emits:

* **Provenance summary** – APK hash, splits, locale distribution, and per-source
  string counts for the run.
* **Metrics block** – totals for decoded payloads, documentary noise ratio,
  unknown string share, and top tag frequencies.
* **Issue flags** – heuristics derived during collection that highlight likely
  problems (e.g., cleartext endpoints, low base64 yield, AWS key pairs). Each
  issue is prefixed with a severity token (`[HIGH]`, `[MEDIUM]`, `[INFO]`).
* **Derived constants** – reconstructed hosts/URLs from constant-folded string
  pieces are marked with `derived=True` and include the SHA set of contributing
  fragments via `derived_from` so analysts can trace the original literals.
* **Evidence samples** – the top three non-documentary hits with offsets and
  previews to jump directly into APK contents.

## Issue flag catalogue

The extractor surfaces the following issue flags. They are available on
`CollectionMetrics.issue_flags` for programmatic consumers and rendered in the
CLI output automatically.

| Slug | Severity | Trigger |
| --- | --- | --- |
| `cleartext_endpoints` | HIGH | Non-local HTTP/WS endpoints discovered. |
| `cleartext_websocket` | HIGH | WebSocket endpoints transmitted over cleartext. |
| `aws_pairs` | HIGH | Access key ID + secret pairs within 200 bytes. |
| `jwt_near_auth` | MEDIUM | JWT-like tokens within an authorization context. |
| `base64_low_yield` | INFO | 5+ base64 candidates with <5% decode success. |
| `base64_failures` | INFO | 10+ failed base64 decodes in one run. |
| `doc_noise` | INFO | Documentary noise exceeds 50% of collected strings. |
| `unknown_bucket` | MEDIUM | Unknown-kind strings exceed 15% of the corpus. |
| `auth_proximity` | MEDIUM | Strings within 32 bytes of auth keywords. |
| `obfuscation` | INFO | Low-vowel dex tokens suggesting obfuscation. |
| `large_decoded_payloads` | INFO | Decoded payload volume unusually large. |

Additional informational entries are appended when sensitive strings are found
only in **non-base splits** or locale-qualified resources.

## Programmatic access

The updated `CollectionMetrics` dataclass now tracks:

* `auth_close_hits` – count of strings flagged within 32 bytes of auth keywords.
* `issue_flags` – tuple of `ExploratoryIssue` instances containing slug,
  severity, and message.

Downstream tooling can serialise these metrics via
`normalise_index(...).metrics.issue_flags` to power dashboards or gating rules.

## Sample output

```
Exploratory SNI  com.example.app 1.0.0
apk=3edff3b9c41d4a6d splits=2 strings: total=18742 (asset=544 dex=9201 res=8997)
doc_noise_ratio=0.27 decoded_yield_rate=0.32 (21/66) obfuscation_hint=false
Endpoints (non-doc): http_nonlocal=3 ws_cleartext=1 ip_literals_public=1 graphql=2 grpc=1
Secrets: aws_pairs=1 jwt_near_auth=0 base64_candidates=66 decoded=21 decode_fail=45
Cloud: s3_buckets=1 firebase_projects=1 unknown_kind=14 unknown_ratio=0.07
Splits: base=18012 feature.video=730
Top tags: endpoint=8, aws-pair=1, encoded=21
Potential issues:
  - [HIGH] Non-local cleartext endpoints observed (3)
  - [HIGH] AWS key pairs detected (1)
  - [MEDIUM] 1 strings appear within 32 bytes of auth keywords
Samples (evidence):
  http://t.co/1.1/resolve?...  classes.dex@1048576
  aws_access_key_id"...  assets/creds.json@25413379
  ws://edge.example/ws  res/raw/streams.bin@4943
```

Use these heuristics to spot noisy allowlist gaps, decode problems, or
high-signal secrets before diving into detailed findings and scoring. For the
schema that receives persisted string evidence, consult
`static_analysis_data_model.md`.
