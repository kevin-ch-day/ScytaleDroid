"""ML module for Paper #2 (unsupervised, offline, evidence-pack driven).

Primary contract (PM-locked):
- ML runs as a batch command over frozen evidence packs (DB-free).
- Inputs are immutable evidence-pack artifacts.
- Outputs are versioned under analysis/ml/v<ml_schema_version>/.
"""

from .evidence_pack_ml_orchestrator import run_ml_on_evidence_packs

# Paper #2 entrypoint (authoritative). Experimental pipeline scaffolding lives under
# scytaledroid/DynamicAnalysis/ml/experimental/ and is intentionally not exported.
__all__ = ["run_ml_on_evidence_packs"]
