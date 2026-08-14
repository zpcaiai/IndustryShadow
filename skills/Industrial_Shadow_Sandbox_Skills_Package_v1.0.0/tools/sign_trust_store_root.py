from __future__ import annotations

import argparse
import base64
import hashlib
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, canonical_digest, canonical_json, utc_now
from shadow_sandbox.operations.trust_store import SignerTrustStore


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise DomainError("TRUST_ROOT_INVALID", "refusing to overwrite root attestation")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".trust-root-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, path)
        os.unlink(temporary)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Root-sign an assessor trust store")
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--public-key-output",
        type=Path,
        required=True,
        help="write the separately distributable root public key in PEM form",
    )
    args = parser.parse_args()
    if (
        args.trust_store.is_symlink()
        or not args.trust_store.is_file()
        or args.trust_store.stat().st_nlink != 1
        or not 1 <= args.trust_store.stat().st_size <= 4 * 1024 * 1024
    ):
        raise DomainError("TRUST_ROOT_INVALID", "trust store must be a safe regular file")
    SignerTrustStore.load(args.trust_store)
    key_path = args.private_key
    if (
        key_path.is_symlink()
        or not key_path.is_file()
        or key_path.stat().st_nlink != 1
        or not 1 <= key_path.stat().st_size <= 1024 * 1024
        or stat.S_IMODE(key_path.stat().st_mode) & 0o077
    ):
        raise DomainError("TRUST_ROOT_INVALID", "root private key permissions are invalid")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise DomainError("TRUST_ROOT_INVALID", "root private key must be Ed25519")
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payload = {
        "schema_version": 1,
        "trust_store_sha256": hashlib.sha256(args.trust_store.read_bytes()).hexdigest(),
        "root_key_sha256": hashlib.sha256(public).hexdigest(),
        "signed_at": utc_now(),
    }
    result = {
        **payload,
        "signature_b64": base64.b64encode(
            private.sign(canonical_digest(payload).encode("ascii"))
        ).decode("ascii"),
    }
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_output = args.public_key_output
    if public_output.resolve(strict=False) == args.output.resolve(strict=False):
        raise DomainError(
            "TRUST_ROOT_INVALID", "root attestation and public key outputs must differ"
        )
    if public_output.exists() or public_output.is_symlink():
        raise DomainError("TRUST_ROOT_INVALID", "refusing to overwrite root public key")
    public_output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".trust-root-public-", dir=public_output.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(public_pem)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.link(temporary, public_output)
        os.unlink(temporary)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    try:
        _write(args.output, result)
    except Exception:
        public_output.unlink(missing_ok=True)
        raise
    print(
        canonical_json(
            {
                "root_key_sha256": payload["root_key_sha256"],
                "output": str(args.output),
                "public_key_output": str(public_output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
