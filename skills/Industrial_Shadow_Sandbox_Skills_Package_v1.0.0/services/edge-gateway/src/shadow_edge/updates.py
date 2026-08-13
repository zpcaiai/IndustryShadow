from shadow_sandbox.common import DomainError, canonical_digest


def verify_update(payload: bytes, declared_digest: str) -> None:
    if canonical_digest(payload.hex()) != declared_digest:
        raise DomainError("UPDATE_DIGEST_MISMATCH", "edge update digest mismatch")
