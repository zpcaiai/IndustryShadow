from shadow_sandbox.common import canonical_digest

from .metrics import ReleaseGateResult


def certification_payload(gate: ReleaseGateResult) -> dict[str, object]:
    return {
        "gate_id": gate.gate_id,
        "passed": gate.passed,
        "bundle_digest": gate.bundle_digest,
        "certification_digest": gate.certification_digest,
        "signature_input": canonical_digest(gate),
    }
