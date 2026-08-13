from shadow_sandbox.common import canonical_digest, canonical_json


def content_hash(payload) -> str:
    return canonical_digest(payload)


__all__ = ["canonical_digest", "canonical_json", "content_hash"]
