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
from urllib.parse import urlsplit

from .models import DomainError

OBJECT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
STREAM_CHUNK_BYTES = 1024 * 1024
SINGLE_PUT_MAX_BYTES = 64 * 1024 * 1024
MULTIPART_PART_BYTES = 16 * 1024 * 1024


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

    def put_file(self, key: str, source: str | Path, *, content_type: str) -> ObjectRef: ...

    def get_bytes(self, key: str, *, maximum_bytes: int = 64 * 1024 * 1024) -> bytes: ...

    def get_version_bytes(
        self,
        key: str,
        *,
        version_id: str,
        maximum_bytes: int = 64 * 1024 * 1024,
        expected_sha256: str | None = None,
    ) -> bytes: ...

    def get_file(
        self,
        key: str,
        destination: str | Path,
        *,
        maximum_bytes: int,
        expected_sha256: str | None = None,
        version_id: str | None = None,
    ) -> ObjectRef: ...

    def delete(self, key: str) -> None: ...


def sha256_file(path: str | Path) -> tuple[str, int]:
    """Hash a regular file with bounded memory and return its byte count."""
    source = Path(path)
    if not source.is_file():
        raise DomainError("OBJECT_FILE_INVALID", "object source must be a regular file")
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as handle:
        while chunk := handle.read(STREAM_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


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

    def put_file(self, key: str, source: str | Path, *, content_type: str) -> ObjectRef:
        source_path = Path(source)
        if not source_path.is_file():
            raise DomainError("OBJECT_FILE_INVALID", "object source must be a regular file")
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".upload-", dir=path.parent)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as writer, source_path.open("rb") as reader:
                while chunk := reader.read(STREAM_CHUNK_BYTES):
                    writer.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        value = digest.hexdigest()
        return ObjectRef(key, size, value, content_type, value)

    def get_bytes(self, key: str, *, maximum_bytes: int = 64 * 1024 * 1024) -> bytes:
        path = self._path(key)
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise DomainError("OBJECT_NOT_FOUND", "object was not found", status=404) from exc
        if size > maximum_bytes:
            raise DomainError("OBJECT_TOO_LARGE", "object exceeds the read limit", status=413)
        return path.read_bytes()

    def get_version_bytes(
        self,
        key: str,
        *,
        version_id: str,
        maximum_bytes: int = 64 * 1024 * 1024,
        expected_sha256: str | None = None,
    ) -> bytes:
        raise DomainError("OBJECT_VERSION_UNSUPPORTED", "local storage has no object versions")

    def get_file(
        self,
        key: str,
        destination: str | Path,
        *,
        maximum_bytes: int,
        expected_sha256: str | None = None,
        version_id: str | None = None,
    ) -> ObjectRef:
        if version_id is not None:
            raise DomainError("OBJECT_VERSION_UNSUPPORTED", "local storage has no object versions")
        source = self._path(key)
        if not source.is_file():
            raise DomainError("OBJECT_NOT_FOUND", "object was not found", status=404)
        size = source.stat().st_size
        if maximum_bytes < 1 or size > maximum_bytes:
            raise DomainError("OBJECT_TOO_LARGE", "object exceeds the read limit", status=413)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".download-", dir=destination_path.parent)
        digest = hashlib.sha256()
        copied = 0
        try:
            with os.fdopen(descriptor, "wb") as writer, source.open("rb") as reader:
                while chunk := reader.read(STREAM_CHUNK_BYTES):
                    copied += len(chunk)
                    if copied > maximum_bytes:
                        raise DomainError(
                            "OBJECT_TOO_LARGE", "object exceeds the read limit", status=413
                        )
                    writer.write(chunk)
                    digest.update(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            actual = digest.hexdigest()
            if expected_sha256 and actual != expected_sha256:
                raise DomainError("OBJECT_INTEGRITY_FAILED", "object checksum mismatch", status=503)
            os.replace(temporary, destination_path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return ObjectRef(key, copied, actual, "application/octet-stream", actual)

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
        require_https_endpoint: bool | None = None,
    ) -> None:
        if not bucket or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            raise DomainError("OBJECT_BUCKET_INVALID", "S3 bucket name is invalid", status=503)
        self.bucket = bucket
        self.region = region
        production_endpoint = (
            os.environ.get("SHADOW_ENVIRONMENT", "").lower() == "production"
            if require_https_endpoint is None
            else require_https_endpoint
        )
        if endpoint_url:
            endpoint = urlsplit(endpoint_url)
            if (
                not endpoint.hostname
                or endpoint.username
                or endpoint.password
                or endpoint.query
                or endpoint.fragment
                or (production_endpoint and endpoint.scheme != "https")
                or endpoint.scheme not in {"http", "https"}
            ):
                raise DomainError(
                    "OBJECT_STORAGE_ENDPOINT_INVALID",
                    "object storage endpoint must be an approved HTTPS origin",
                    status=503,
                )
        self.endpoint_url = endpoint_url
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

    def _encryption(self) -> dict[str, Any]:
        if not self.kms_key_id:
            return {"ServerSideEncryption": "AES256"}
        encryption: dict[str, Any] = {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms_key_id,
            "BucketKeyEnabled": True,
        }
        if self.kms_encryption_context:
            context = json.dumps(
                self.kms_encryption_context, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            encryption["SSEKMSEncryptionContext"] = base64.b64encode(context).decode("ascii")
        return encryption

    def _validate_encryption(self, response: dict[str, Any]) -> None:
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

    def put_bytes(self, key: str, data: bytes, *, content_type: str) -> ObjectRef:
        if not isinstance(data, bytes):
            raise DomainError("OBJECT_DATA_INVALID", "object payload must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        encryption = self._encryption()
        response = self.client.put_object(
            Bucket=self.bucket,
            Key=self._key(key),
            Body=data,
            ContentType=content_type,
            Metadata={"sha256": digest},
            **encryption,
        )
        version_id = response.get("VersionId")
        head_arguments: dict[str, Any] = {"Bucket": self.bucket, "Key": self._key(key)}
        if version_id:
            head_arguments["VersionId"] = version_id
        try:
            head = self.client.head_object(**head_arguments)
        except Exception as exc:
            raise DomainError(
                "OBJECT_STORAGE_UNAVAILABLE", "object storage readback failed", status=503
            ) from exc
        self._validate_encryption(head)
        if (
            int(head.get("ContentLength", -1)) != len(data)
            or head.get("Metadata", {}).get("sha256") != digest
            or (version_id and head.get("VersionId") != version_id)
        ):
            raise DomainError(
                "OBJECT_INTEGRITY_FAILED", "uploaded object metadata mismatch", status=503
            )
        return ObjectRef(
            key,
            len(data),
            digest,
            content_type,
            str(response.get("ETag", "")).strip('"'),
            head.get("VersionId") or version_id,
            str(head.get("ServerSideEncryption", "")),
        )

    def put_file(self, key: str, source: str | Path, *, content_type: str) -> ObjectRef:
        source_path = Path(source)
        digest, size = sha256_file(source_path)
        full_key = self._key(key)
        extra = {
            "ContentType": content_type,
            "Metadata": {"sha256": digest},
            **self._encryption(),
        }
        upload_id: str | None = None
        try:
            if size <= SINGLE_PUT_MAX_BYTES:
                with source_path.open("rb") as handle:
                    response = self.client.put_object(
                        Bucket=self.bucket,
                        Key=full_key,
                        Body=handle,
                        ContentLength=size,
                        **extra,
                    )
            else:
                initiated = self.client.create_multipart_upload(
                    Bucket=self.bucket,
                    Key=full_key,
                    **extra,
                )
                upload_id = str(initiated["UploadId"])
                parts: list[dict[str, object]] = []
                with source_path.open("rb") as handle:
                    part_number = 1
                    while chunk := handle.read(MULTIPART_PART_BYTES):
                        uploaded = self.client.upload_part(
                            Bucket=self.bucket,
                            Key=full_key,
                            UploadId=upload_id,
                            PartNumber=part_number,
                            Body=chunk,
                        )
                        parts.append({"ETag": str(uploaded["ETag"]), "PartNumber": part_number})
                        part_number += 1
                response = self.client.complete_multipart_upload(
                    Bucket=self.bucket,
                    Key=full_key,
                    UploadId=upload_id,
                    MultipartUpload={"Parts": parts},
                )
                upload_id = None
            version_id = response.get("VersionId")
            head_arguments: dict[str, Any] = {"Bucket": self.bucket, "Key": full_key}
            if version_id:
                head_arguments["VersionId"] = version_id
            head = self.client.head_object(**head_arguments)
        except Exception as exc:
            if upload_id:
                try:
                    self.client.abort_multipart_upload(
                        Bucket=self.bucket,
                        Key=full_key,
                        UploadId=upload_id,
                    )
                except Exception:  # noqa: BLE001,S110 - preserve the original upload failure
                    pass
            raise DomainError(
                "OBJECT_STORAGE_UNAVAILABLE", "object storage upload failed", status=503
            ) from exc
        self._validate_encryption(head)
        if (
            int(head.get("ContentLength", -1)) != size
            or head.get("Metadata", {}).get("sha256") != digest
            or (version_id and head.get("VersionId") != version_id)
        ):
            raise DomainError(
                "OBJECT_INTEGRITY_FAILED", "uploaded object metadata mismatch", status=503
            )
        return ObjectRef(
            key,
            size,
            digest,
            content_type,
            str(head.get("ETag", "")).strip('"'),
            head.get("VersionId") or version_id,
            str(head.get("ServerSideEncryption", "")),
        )

    def get_bytes(self, key: str, *, maximum_bytes: int = 64 * 1024 * 1024) -> bytes:
        return self._get_bytes(key, maximum_bytes=maximum_bytes)

    def get_version_bytes(
        self,
        key: str,
        *,
        version_id: str,
        maximum_bytes: int = 64 * 1024 * 1024,
        expected_sha256: str | None = None,
    ) -> bytes:
        if not version_id:
            raise DomainError("OBJECT_VERSION_INVALID", "an exact object version is required")
        return self._get_bytes(
            key,
            maximum_bytes=maximum_bytes,
            version_id=version_id,
            expected_sha256=expected_sha256,
        )

    def _get_bytes(
        self,
        key: str,
        *,
        maximum_bytes: int,
        version_id: str | None = None,
        expected_sha256: str | None = None,
    ) -> bytes:
        arguments: dict[str, Any] = {"Bucket": self.bucket, "Key": self._key(key)}
        if version_id:
            arguments["VersionId"] = version_id
        try:
            response = self.client.get_object(**arguments)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code in {"NoSuchKey", "NoSuchVersion", "404", "NotFound"}:
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
        if version_id and response.get("VersionId") != version_id:
            raise DomainError(
                "OBJECT_VERSION_INVALID", "object storage returned an unexpected version", status=503
            )
        expected = response.get("Metadata", {}).get("sha256")
        actual = hashlib.sha256(data).hexdigest()
        if not expected or actual != expected or (expected_sha256 and actual != expected_sha256):
            raise DomainError("OBJECT_INTEGRITY_FAILED", "object checksum mismatch", status=503)
        self._validate_encryption(response)
        return data

    def get_file(
        self,
        key: str,
        destination: str | Path,
        *,
        maximum_bytes: int,
        expected_sha256: str | None = None,
        version_id: str | None = None,
    ) -> ObjectRef:
        if maximum_bytes < 1:
            raise DomainError("OBJECT_TOO_LARGE", "object read limit must be positive", status=413)
        arguments: dict[str, Any] = {"Bucket": self.bucket, "Key": self._key(key)}
        if version_id:
            arguments["VersionId"] = version_id
        try:
            response = self.client.get_object(**arguments)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code in {"NoSuchKey", "NoSuchVersion", "404", "NotFound"}:
                raise DomainError("OBJECT_NOT_FOUND", "object was not found", status=404) from exc
            raise DomainError(
                "OBJECT_STORAGE_UNAVAILABLE", "object storage read failed", status=503
            ) from exc
        body = response["Body"]
        try:
            self._validate_encryption(response)
            if version_id and response.get("VersionId") != version_id:
                raise DomainError(
                    "OBJECT_VERSION_INVALID",
                    "object storage returned an unexpected version",
                    status=503,
                )
            length = int(response.get("ContentLength", 0))
            if length > maximum_bytes:
                raise DomainError("OBJECT_TOO_LARGE", "object exceeds the read limit", status=413)
            destination_path = Path(destination)
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(
                prefix=".download-", dir=destination_path.parent
            )
            digest = hashlib.sha256()
            size = 0
            try:
                with os.fdopen(descriptor, "wb") as writer:
                    while chunk := body.read(STREAM_CHUNK_BYTES):
                        size += len(chunk)
                        if size > maximum_bytes:
                            raise DomainError(
                                "OBJECT_TOO_LARGE",
                                "object exceeds the read limit",
                                status=413,
                            )
                        writer.write(chunk)
                        digest.update(chunk)
                    writer.flush()
                    os.fsync(writer.fileno())
                actual = digest.hexdigest()
                metadata_digest = response.get("Metadata", {}).get("sha256")
                if not metadata_digest or metadata_digest != actual:
                    raise DomainError(
                        "OBJECT_INTEGRITY_FAILED",
                        "object checksum metadata mismatch",
                        status=503,
                    )
                if expected_sha256 and expected_sha256 != actual:
                    raise DomainError(
                        "OBJECT_INTEGRITY_FAILED", "object checksum mismatch", status=503
                    )
                os.replace(temporary, destination_path)
            except Exception:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                raise
        finally:
            body.close()
        return ObjectRef(
            key,
            size,
            actual,
            str(response.get("ContentType", "application/octet-stream")),
            str(response.get("ETag", "")).strip('"'),
            response.get("VersionId") or version_id,
            str(response.get("ServerSideEncryption", "")),
        )

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
    require_https_endpoint: bool | None = None,
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
            require_https_endpoint=require_https_endpoint,
        )
    raise DomainError(
        "OBJECT_STORAGE_CONFIG_INVALID", "object storage backend is invalid", status=503
    )
