# Paper #2 Capture Policy v1

This document defines the paper-critical dynamic collection contract referenced by:
- `operator.capture_policy_version`
- `dataset.capture_policy_version`

Version: `1`

## Locked Requirements

1. Windowing
- `window_size_s = 10`
- `window_stride_s = 5`
- percentile threshold = `95` (NumPy method pinned to `linear`)

2. Baseline quality gates
- `MIN_WINDOWS_BASELINE = 30`
- `MIN_PCAP_BYTES = 50000`

3. Per-run validity minimum
- `MIN_WINDOWS_PER_RUN = 20`

4. Identity contract (paper mode)
- package name + version code
- base APK SHA-256
- artifact set hash
- signer set hash

5. Signer set hash algorithm
- extract signer digests from package metadata
- normalize to lowercase hex
- deduplicate
- sort lexicographically
- join with `|` delimiter
- compute SHA-256 of joined string

6. Run intent taxonomy
- `baseline_idle`
- `interaction_scripted`
- `interaction_manual`

7. Enforcement
- pre-run hard gates must pass
- freeze build must reject mismatched capture policy versions
- paper gate must reject missing/mismatched capture policy versions

