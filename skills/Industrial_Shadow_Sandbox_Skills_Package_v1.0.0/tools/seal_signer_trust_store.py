from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json
from shadow_sandbox.operations.trust_store import SignerTrustStore


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".trust-store-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and digest-seal a public assessor/approver trust store"
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise DomainError("TRUST_STORE_INVALID", "trust store input must be an object")
    if value.get("digest") not in {None, ""}:
        raise DomainError(
            "TRUST_STORE_ALREADY_SEALED",
            "input digest must be absent or empty to prevent accidental stale resealing",
        )
    payload = {**value, "digest": ""}
    payload["digest"] = canonical_digest(payload)
    validated = SignerTrustStore(payload)
    _atomic_write(args.output, payload)
    print(
        canonical_json(
            {
                "store_id": validated.store_id,
                "signers": len(validated.signers),
                "digest": validated.digest,
                "output": str(args.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
