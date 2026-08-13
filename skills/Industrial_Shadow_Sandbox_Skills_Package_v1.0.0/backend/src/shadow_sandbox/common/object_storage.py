from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import DomainError

OBJECT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")


@dataclass(frozen=True, slots=True)
class ObjectRef:
    key: str
    size: int
    sha256: str
    content_type: str
    etag: str | None = None
    version_id: str | None = None
    encryption: str | None = None


class ObjectStorage(Protocol):
    def put_bytes(self, key: str, data: bytes, *, content_type: str) -> ObjectRef: ...

    def get_bytes(self, key: str, *, maximum_bytes: int = 64 * 1024 * 1024) -> bytes: ...

    def delete(self, key: str) -> None: ...


def validate_object_key(key: str) -> str:
    if (
        not OBJECT_KEY.fullmatch(key)
        or "//" in key
        or any(part in {"", ".", ".."} for part in key.split("/"))
    ):
        raise DomainError("OBJECT_KEY_INVALID", "object key is outside the registered namespace")
    return key


class LocalObjectStorage:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        candidate = (self.root / validate_object_key(key)).resolve()
        if self.root not in candidate.parents:
            raise DomainError("OBJECT_KEY_INVALID", "object path escaped the storage root")
        return candidate

    def put_bytes(self, key: str, data: bytes, *, content_type: str) -> ObjectRef:
        if not isinstance(data, bytes):
            raise DomainError("OBJECT_DATA_INVALID", "object payload must be bytes")
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()
        descriptor, temporary = tempfile.mkstemp(prefix=".upload-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return ObjectRef(key, len(data), digest, content_type, digest)

    def get_bytes(self, key: str, *, maximum_bytes: int = 64 * 1024 * 1024) -> bytes:
        path = self._path(key)
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise DomainError("OBJECT_NOT_FOUND", "object was not found", status=404) from exc
        if size > maximum_bytes:
            raise DomainError("OBJECT_TOO_LARGE", "object exceeds the read limit", status=413)
        return path.read_bytes()

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            return


class S3ObjectStorage:
    def __init__(
        self,
        bucket: str,
        *,
        region: str | None = None,
        endpoint_url: str | None = None,
        prefix: str = "industrial-shadow",
        kms_key_id: str | None = None,
        kms_encryption_context: dict[str, str] | None = None,
        client: Any | None = None,
    ) -> None:
        if not bucket or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            raise DomainError("OBJECT_BUCKET_INVALID", "S3 bucket name is invalid", status=503)
        self.bucket = bucket
        self.prefix = validate_object_key(prefix).rstrip("/")
        self.kms_key_id = kms_key_id
        self.kms_encryption_context = dict(kms_encryption_context or {})
        resolved_client = client
        if resolved_client is None:
            try:
                import boto3
            except ImportError as exc:
                raise DomainError(
                    "S3_DEPENDENCY_UNAVAILABLE", "install the object-storage dependency", status=503
                ) from exc
            resolved_client = boto3.client("s3", region_name=region, endpoint_url=endpoint_url)
        self.client: Any = resolved_client

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{validate_object_key(key)}"

    def put_bytes(self, key: str, data: bytes, *, content_type: str) -> ObjectRef:
        if not isinstance(data, bytes):
            raise DomainError("OBJECT_DATA_INVALID", "object payload must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        encryption: dict[str, Any]
        if self.kms_key_id:
            encryption = {
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": self.kms_key_id,
                "BucketKeyEnabled": True,
            }
            if self.kms_encryption_context:
                context = json.dumps(
                    self.kms_encryption_context, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                encryption["SSEKMSEncryptionContext"] = base64.b64encode(context).decode("ascii")
        else:
            encryption = {"ServerSideEncryption": "AES256"}
        response = self.client.put_object(
            Bucket=self.bucket,
            Key=self._key(key),
            Body=data,
            ContentType=content_type,
            Metadata={"sha256": digest},
            **encryption,
        )
        return ObjectRef(
            key,
            len(data),
            digest,
            content_type,
            str(response.get("ETag", "")).strip('"'),
            response.get("VersionId"),
            str(response.get("ServerSideEncryption") or encryption["ServerSideEncryption"]),
        )

    def get_bytes(self, key: str, *, maximum_bytes: int = 64 * 1024 * 1024) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(key))
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code in {"NoSuchKey", "404", "NotFound"}:
                raise DomainError("OBJECT_NOT_FOUND", "object was not found", status=404) from exc
            raise DomainError(
                "OBJECT_STORAGE_UNAVAILABLE", "object storage read failed", status=503
            ) from exc
        length = int(response.get("ContentLength", 0))
        if length > maximum_bytes:
            response["Body"].close()
            raise DomainError("OBJECT_TOO_LARGE", "object exceeds the read limit", status=413)
        body = response["Body"]
        try:
            data = body.read(maximum_bytes + 1)
        finally:
            body.close()
        if len(data) > maximum_bytes:
            raise DomainError("OBJECT_TOO_LARGE", "object exceeds the read limit", status=413)
        expected = response.get("Metadata", {}).get("sha256")
        if expected and hashlib.sha256(data).hexdigest() != expected:
            raise DomainError("OBJECT_INTEGRITY_FAILED", "object checksum mismatch", status=503)
        if self.kms_key_id and response.get("ServerSideEncryption") != "aws:kms":
            raise DomainError(
                "OBJECT_ENCRYPTION_INVALID", "object is not KMS encrypted", status=503
            )
        if self.kms_key_id and response.get("SSEKMSKeyId") != self.kms_key_id:
            raise DomainError(
                "OBJECT_KMS_KEY_INVALID",
                "object is encrypted with an unexpected KMS key",
                status=503,
            )
        return data

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=self._key(key))


def create_object_storage(
    backend: str,
    *,
    local_root: str | Path,
    bucket: str | None = None,
    region: str | None = None,
    endpoint_url: str | None = None,
    prefix: str = "industrial-shadow",
    kms_key_id: str | None = None,
    kms_encryption_context: dict[str, str] | None = None,
) -> ObjectStorage:
    if backend == "local":
        return LocalObjectStorage(local_root)
    if backend == "s3" and bucket:
        return S3ObjectStorage(
            bucket,
            region=region,
            endpoint_url=endpoint_url,
            prefix=prefix,
            kms_key_id=kms_key_id,
            kms_encryption_context=kms_encryption_context,
        )
    raise DomainError(
        "OBJECT_STORAGE_CONFIG_INVALID", "object storage backend is invalid", status=503
    )
