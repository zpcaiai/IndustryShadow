from .entities import DiagnosisResult


def inconclusive(quality_state: str, reason: str, next_step: str) -> DiagnosisResult:
    return DiagnosisResult("INCONCLUSIVE", (), quality_state, 0.0, (reason,), (next_step,))
