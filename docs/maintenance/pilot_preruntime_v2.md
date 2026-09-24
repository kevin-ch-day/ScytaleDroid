# Pre-runtime pilot freeze verification

`scripts/dynamic/verify_preruntime_v2.py` verifies an additive pre-runtime evidence
freeze while preserving the original pilot. It delegates original packet, opaque
APK-byte, 21-file instrument and schedule checks to `verify_pilot`; it then checks
the separately pinned V2 manifest, permission ledgers, assessment bodies, original
revision mapping, revision chains, evidence cutoffs and prespecified analysis files.

```bash
python scripts/dynamic/verify_preruntime_v2.py \
  --packet /path/to/PILOT_PRE_RUNTIME_V2 \
  --original-packet /path/to/MALWARE_PILOT_PREEXECUTION \
  --expect-manifest-sha256 REVIEWED_EXTERNAL_SHA256 \
  --quarantine /path/to/Android_Malware_Quarantine
```

The pin must come from an independently reviewed record. Reading a pin from the
same mutable directory only checks internal consistency. This command performs no
DB access, APK parsing, installation or execution. It does not prove current DB
freshness or execution-driver readiness. A pass never authorizes execution.

Static declaration projections have separate source provenance. They must not be
counted as recovered VirusTotal observations. Preserve exact declaration strings,
unresolved semantics and the original pre-runtime assessment cutoff.
