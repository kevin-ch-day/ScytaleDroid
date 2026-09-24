# Read-only frozen pilot verification

Use `scripts/dynamic/verify_pilot.py` to check a sealed
`MALWARE_DYNAMIC_PILOT_V1` packet before an execution decision. It is an offline
operator diagnostic, not part of the frozen measurement instrument or an
execution controller. It never parses APKs, opens a DB, makes provider requests,
installs packages, starts a VM, or grants execution authorization.

```bash
.venv/bin/python scripts/dynamic/verify_pilot.py \
  --packet /path/to/sealed/pilot \
  --expect-manifest-sha256 TRUSTED_MANIFEST_SHA256 \
  --quarantine /path/to/Android_Malware_Quarantine
```

Obtain the manifest digest from the independently retained handoff, not by
blindly hashing an unknown packet. The tool checks packet seals, proposal and
cohort identity, exclusions, baseline hashes, static eligibility, assessment
identity digests/revision references, all21 instrument sources, and the exact
48-window seeded matched schedule. With `--quarantine`, it additionally hashes
the eight opaque payload files. APK parsing is never performed on the host.
Source root defaults to this checkout and can be overridden with `--source-root`.

Exit0 means those checks passed with selected payload hashes verified. Exit3
means packet checks passed but quarantine bytes were not requested/checked.
Exit2 means verification failed. All reports keep `execution_authorized=false`.
Passing does not establish current database state, accepted labels, install or
launch success, runtime containment readiness, or scientific countability.
Public runtime binaries, VM boot files and Android images are outside this
source verifier's scope and still require the existing instrument checks.

The report includes exact per-SHA evidence gaps and aggregate family, permission
projection, and processing states from frozen records. It does not convert
source claims into governed labels, treat missing projection as absent declared
permissions, or fix catalog metadata. It uses no arbitrary paths from a manifest:
relative paths are bounded, symlinks/nonregular files are rejected, duplicate
JSON keys/checksum entries fail, and input/file-count/total-size bounds apply.
It assumes the operator does not concurrently replace input directories during
verification. Checksums establish consistency with the supplied pin, not a
cryptographic signature or independent provenance endorsement.

Write output into a new audit packet using shell redirection; do not place new
results inside an already sealed pilot. Existing frozen packets and revisions
must remain unchanged.
