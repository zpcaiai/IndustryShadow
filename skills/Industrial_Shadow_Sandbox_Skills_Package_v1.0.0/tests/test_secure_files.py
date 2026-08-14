from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from shadow_sandbox.common.models import DomainError
from shadow_sandbox.common.secure_files import (
    read_private_file,
    read_private_json_object,
)


class SecureFileTests(unittest.TestCase):
    def test_private_json_is_read_from_one_owner_only_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.json"
            path.write_text(json.dumps({"token": "test-only"}), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(
                {"token": "test-only"},
                read_private_json_object(path),
            )

    def test_symlink_hardlink_and_permissive_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "secret.json"
            source.write_text("{}", encoding="utf-8")
            source.chmod(0o600)
            symlink = root / "symlink.json"
            symlink.symlink_to(source)
            hardlink = root / "hardlink.json"
            os.link(source, hardlink)
            for path in (source, symlink, hardlink):
                with self.subTest(path=path.name), self.assertRaises(DomainError):
                    read_private_file(path)

            permissive = root / "permissive.json"
            permissive.write_text("{}", encoding="utf-8")
            permissive.chmod(0o640)
            with self.assertRaises(DomainError):
                read_private_file(permissive)

    def test_empty_oversized_and_non_object_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in (
                ("empty.json", b""),
                ("oversized.json", b"x" * 17),
            ):
                path = root / name
                path.write_bytes(payload)
                path.chmod(0o400)
                with self.subTest(name=name), self.assertRaises(DomainError):
                    read_private_file(path, maximum_bytes=16)

            array = root / "array.json"
            array.write_text("[]", encoding="utf-8")
            array.chmod(0o400)
            with self.assertRaises(DomainError):
                read_private_json_object(array)


if __name__ == "__main__":
    unittest.main()
