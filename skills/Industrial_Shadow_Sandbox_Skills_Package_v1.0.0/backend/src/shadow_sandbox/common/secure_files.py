from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import DomainError


def read_private_file(
    path_value: str | Path,
    *,
    maximum_bytes: int = 1024 * 1024,
    code: str = "PRIVATE_FILE_INVALID",
) -> bytes:
    """Read one owner-only regular file through a single non-following descriptor."""
    if not 1 <= maximum_bytes <= 16 * 1024 * 1024:
        raise DomainError(code, "private file size policy is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    cloexec = getattr(os, "O_CLOEXEC", None)
    if nofollow is None or cloexec is None:
        raise DomainError(code, "secure private-file descriptors are unavailable")
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(path_value), os.O_RDONLY | nofollow | cloexec)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or not 1 <= before.st_size <= maximum_bytes
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
        ):
            raise DomainError(
                code,
                "private input must be a single-link 0400/0600 regular file within the size limit",
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > maximum_bytes
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
        ):
            raise DomainError(code, "private input changed while it was being read")
        return payload
    except DomainError:
        raise
    except OSError as error:
        raise DomainError(code, "private input cannot be opened safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_private_json_object(
    path_value: str | Path,
    *,
    maximum_bytes: int = 1024 * 1024,
    code: str = "PRIVATE_JSON_INVALID",
) -> Mapping[str, Any]:
    try:
        value = json.loads(
            read_private_file(
                path_value,
                maximum_bytes=maximum_bytes,
                code=code,
            ).decode("utf-8")
        )
    except DomainError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DomainError(code, "private JSON input is invalid") from error
    if not isinstance(value, Mapping):
        raise DomainError(code, "private JSON input must be an object")
    return value
