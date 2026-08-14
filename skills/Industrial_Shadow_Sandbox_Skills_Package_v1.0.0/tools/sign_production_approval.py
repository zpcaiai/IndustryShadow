from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.operations.trust_store import SignerTrustStore

from tools.build_production_closure import (
    REQUIRED_SIGNATORY_ROLES,
    verify_signatories,
)

APPROVAL_KEYS = frozenset(
    {
        "schema_version",
        "acceptance_run_id",
        "release_digest",
        "trust_store_digest",
        "gate_digests",
        "attestation_digests",
        "release_coordinates",
        "scope",
        "exclusions",
        "approval_digest",
    }
)
SIGNATURE_FILE_KEYS = frozenset({"schema_version", "approval_digest", "signatories"})


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".production-signatories-", dir=path.parent
    )
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


def validate_approval(value: Any, trust_store: SignerTrustStore) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != APPROVAL_KEYS
        or value.get("schema_version") != 2
    ):
        raise DomainError(
            "CLOSURE_APPROVAL_INVALID", "approval request fields are invalid"
        )
    claimed = str(value.get("approval_digest", ""))
    payload = {key: item for key, item in value.items() if key != "approval_digest"}
    if claimed != canonical_digest(payload):
        raise DomainError(
            "CLOSURE_APPROVAL_DIGEST_INVALID", "approval request digest is invalid"
        )
    if value.get("trust_store_digest") != trust_store.digest:
        raise DomainError(
            "CLOSURE_APPROVAL_TRUST_MISMATCH",
            "approval request and trust store do not match",
        )
    return value


def sign_approval(
    approval: Mapping[str, Any],
    *,
    identity: str,
    role: str,
    private_key_path: str | Path,
    trust_store: SignerTrustStore,
) -> dict[str, Any]:
    validate_approval(approval, trust_store)
    if role not in REQUIRED_SIGNATORY_ROLES or not identity.strip():
        raise DomainError(
            "CLOSURE_SIGNATORY_INVALID", "signatory identity or role is invalid"
        )
    key_source = Path(private_key_path)
    key_path = key_source.resolve(strict=True)
    if (
        key_source.is_symlink()
        or not key_path.is_file()
        or key_path.stat().st_nlink != 1
        or not 1 <= key_path.stat().st_size <= 1024 * 1024
        or stat.S_IMODE(key_path.stat().st_mode) & 0o077
    ):
        raise DomainError(
            "CLOSURE_KEY_PERMISSIONS_INVALID",
            "closure signing key must not be accessible to group or other users",
        )
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None
        )
    except Exception as error:
        raise DomainError(
            "CLOSURE_KEY_INVALID", "could not load closure signing key"
        ) from error
    if not isinstance(private, Ed25519PrivateKey):
        raise DomainError("CLOSURE_KEY_INVALID", "closure key must be Ed25519")
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signed_at = utc_now()
    public_key_b64 = base64.b64encode(public).decode("ascii")
    trust_store.verify_signer(
        identity=identity,
        purpose=f"closure_{role}",
        public_key_b64=public_key_b64,
        signed_at=signed_at,
    )
    approval_digest = str(approval["approval_digest"])
    return {
        "identity": identity,
        "role": role,
        "approved": True,
        "signed_at": signed_at,
        "approval_digest": approval_digest,
        "public_key_b64": public_key_b64,
        "signature_b64": base64.b64encode(
            private.sign(approval_digest.encode("ascii"))
        ).decode("ascii"),
    }


def signature_file(
    approval_digest: str,
    values: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "approval_digest": approval_digest,
        "signatories": [dict(item) for item in values],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sign one digest-bound production approval as one authorized owner"
    )
    parser.add_argument("--approval-request", type=Path, required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument(
        "--role", choices=tuple(sorted(REQUIRED_SIGNATORY_ROLES)), required=True
    )
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--trust-root-attestation", type=Path, required=True)
    parser.add_argument("--trust-root-public-key", type=Path, required=True)
    parser.add_argument("--trust-root-key-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--append",
        action="store_true",
        help="append a distinct second signature to an existing output file",
    )
    args = parser.parse_args()

    trust_store = SignerTrustStore.load_verified(
        args.trust_store,
        root_attestation_path=args.trust_root_attestation,
        root_public_key_path=args.trust_root_public_key,
        expected_root_key_sha256=args.trust_root_key_sha256,
    )
    if (
        args.approval_request.is_symlink()
        or not args.approval_request.is_file()
        or args.approval_request.stat().st_nlink != 1
        or not 1 <= args.approval_request.stat().st_size <= 4 * 1024 * 1024
    ):
        raise DomainError(
            "CLOSURE_APPROVAL_INVALID", "approval request must be a safe regular file"
        )
    approval_value = json.loads(args.approval_request.read_text(encoding="utf-8"))
    approval = validate_approval(approval_value, trust_store)
    existing: list[Mapping[str, Any]] = []
    if args.append:
        if (
            args.output.is_symlink()
            or not args.output.is_file()
            or args.output.stat().st_nlink != 1
            or not 1 <= args.output.stat().st_size <= 4 * 1024 * 1024
        ):
            raise DomainError(
                "CLOSURE_SIGNATURE_FILE_INVALID",
                "existing signature file must be a safe regular file",
            )
        try:
            current = json.loads(args.output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(
                "CLOSURE_SIGNATURE_FILE_INVALID",
                "append requires an existing valid signature file",
            ) from error
        if (
            not isinstance(current, Mapping)
            or set(current) != SIGNATURE_FILE_KEYS
            or current.get("schema_version") != 1
            or current.get("approval_digest") != approval["approval_digest"]
            or not isinstance(current.get("signatories"), list)
        ):
            raise DomainError(
                "CLOSURE_SIGNATURE_FILE_INVALID", "existing signature file is invalid"
            )
        existing = list(current["signatories"])
    elif args.output.exists():
        raise DomainError(
            "CLOSURE_SIGNATURE_FILE_EXISTS",
            "refusing to overwrite an existing signature file without --append",
        )

    record = sign_approval(
        approval,
        identity=args.identity,
        role=args.role,
        private_key_path=args.private_key,
        trust_store=trust_store,
    )
    if any(
        item.get("identity") == record["identity"] or item.get("role") == record["role"]
        for item in existing
        if isinstance(item, Mapping)
    ):
        raise DomainError(
            "CLOSURE_SIGNATORY_INVALID", "identity and role must be distinct"
        )
    values = [*existing, record]
    if len(values) == len(REQUIRED_SIGNATORY_ROLES):
        verify_signatories(values, str(approval["approval_digest"]), trust_store)
        status = "verified"
    elif len(values) < len(REQUIRED_SIGNATORY_ROLES):
        status = "pending_second_signature"
    else:
        raise DomainError("CLOSURE_SIGNATORY_INVALID", "too many closure signatories")
    _atomic_write(args.output, signature_file(str(approval["approval_digest"]), values))
    print(
        canonical_json(
            {
                "status": status,
                "signatories": len(values),
                "approval_digest": approval["approval_digest"],
                "output": str(args.output),
            }
        )
    )
    return 0 if status == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
