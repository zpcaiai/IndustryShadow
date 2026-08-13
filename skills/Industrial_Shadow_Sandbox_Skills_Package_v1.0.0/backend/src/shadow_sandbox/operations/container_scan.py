from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from shadow_sandbox.common.models import DomainError, utc_now

from .evidence import GateCheck, GateEvidence, complete

IMAGE_DIGEST = re.compile(r"^[^@\s]+@sha256:[a-f0-9]{64}$")
SCOUT_VERSION = re.compile(r"(?m)^version:\s*(v?\d+\.\d+\.\d+(?:[-+][^\s]+)?)\s*$")

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class DockerScoutImageProbe:
    """Run Docker Scout against one immutable image and retain its SARIF report."""

    def __init__(
        self,
        repository_root: str | Path,
        *,
        candidate_image: str,
        report_path: str | Path,
        credentials_file: str | Path,
        run_command: CommandRunner = subprocess.run,
    ) -> None:
        self.root = Path(repository_root).resolve(strict=True)
        self.candidate_image = candidate_image
        candidate_report = Path(report_path)
        if not candidate_report.is_absolute():
            candidate_report = self.root / candidate_report
        report_parent = candidate_report.parent.resolve(strict=True)
        if self.root not in report_parent.parents and report_parent != self.root:
            raise DomainError(
                "CONTAINER_SCAN_REPORT_INVALID",
                "container scan report must be inside the repository",
            )
        if candidate_report.is_symlink():
            raise DomainError(
                "CONTAINER_SCAN_REPORT_INVALID",
                "container scan report must not be a symlink",
            )
        self.report_path = candidate_report
        self.credentials_file = Path(credentials_file).resolve(strict=True)
        self.run_command = run_command

    def _credentials(self) -> tuple[str, str]:
        mode = stat.S_IMODE(self.credentials_file.stat().st_mode)
        if mode & 0o077:
            raise DomainError(
                "CONTAINER_SCAN_CREDENTIAL_PERMISSIONS",
                "Docker Scout credentials must not be readable by group or other users",
            )
        try:
            value = json.loads(self.credentials_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(
                "CONTAINER_SCAN_CREDENTIAL_INVALID",
                "Docker Scout credentials are invalid",
            ) from error
        if not isinstance(value, Mapping) or set(value) != {
            "username",
            "personal_access_token",
        }:
            raise DomainError(
                "CONTAINER_SCAN_CREDENTIAL_INVALID",
                "Docker Scout credentials require username and personal_access_token",
            )
        username = str(value.get("username", "")).strip()
        access_value = str(value.get("personal_access_token", ""))
        if not username or not access_value or "\n" in username or "\n" in access_value:
            raise DomainError(
                "CONTAINER_SCAN_CREDENTIAL_INVALID",
                "Docker Scout credential values are invalid",
            )
        return username, access_value

    @staticmethod
    def _sarif_results(payload: Any) -> list[Mapping[str, Any]]:
        if not isinstance(payload, Mapping) or payload.get("version") != "2.1.0":
            raise DomainError(
                "CONTAINER_SCAN_REPORT_INVALID", "Docker Scout did not emit SARIF 2.1.0"
            )
        runs = payload.get("runs")
        if not isinstance(runs, list) or not runs:
            raise DomainError(
                "CONTAINER_SCAN_REPORT_INVALID", "Docker Scout SARIF runs are missing"
            )
        results: list[Mapping[str, Any]] = []
        for run in runs:
            if not isinstance(run, Mapping):
                raise DomainError(
                    "CONTAINER_SCAN_REPORT_INVALID", "Docker Scout SARIF run is invalid"
                )
            tool = run.get("tool")
            driver = tool.get("driver") if isinstance(tool, Mapping) else None
            if not isinstance(driver, Mapping) or not str(driver.get("name", "")).strip():
                raise DomainError(
                    "CONTAINER_SCAN_REPORT_INVALID", "Docker Scout SARIF tool is missing"
                )
            run_results = run.get("results", [])
            if not isinstance(run_results, list) or any(
                not isinstance(item, Mapping) for item in run_results
            ):
                raise DomainError(
                    "CONTAINER_SCAN_REPORT_INVALID", "Docker Scout SARIF results are invalid"
                )
            results.extend(run_results)
        return results

    def run(self) -> GateEvidence:
        started = utc_now()
        if not IMAGE_DIGEST.fullmatch(self.candidate_image):
            raise DomainError(
                "CONTAINER_SCAN_IMAGE_INVALID",
                "container scan requires an immutable image digest reference",
            )
        username, access_value = self._credentials()
        self.report_path.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="industrial-shadow-docker-config-") as directory:
            os.chmod(directory, 0o700)
            environment = {**os.environ, "DOCKER_CONFIG": directory}
            login = self.run_command(
                [
                    "docker",
                    "login",
                    "docker.io",
                    "--username",
                    username,
                    "--password-stdin",
                ],
                input=access_value + "\n",
                capture_output=True,
                text=True,
                timeout=60,
                env=environment,
                check=False,
            )
            if login.returncode != 0:
                raise DomainError(
                    "CONTAINER_SCAN_AUTH_FAILED", "Docker Scout authentication failed"
                )
            version_result = self.run_command(
                ["docker", "scout", "version"],
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
                check=False,
            )
            version_match = SCOUT_VERSION.search(version_result.stdout)
            if version_result.returncode != 0 or version_match is None:
                raise DomainError("CONTAINER_SCAN_UNAVAILABLE", "Docker Scout CLI is unavailable")
            scan = self.run_command(
                [
                    "docker",
                    "scout",
                    "cves",
                    "--only-severity",
                    "critical,high",
                    "--format",
                    "sarif",
                    "--output",
                    str(self.report_path),
                    "--exit-code",
                    self.candidate_image,
                ],
                capture_output=True,
                text=True,
                timeout=1800,
                env=environment,
                check=False,
            )
        if scan.returncode not in {0, 2}:
            raise DomainError("CONTAINER_SCAN_EXECUTION_FAILED", "Docker Scout image scan failed")
        if not self.report_path.is_file() or self.report_path.is_symlink():
            raise DomainError(
                "CONTAINER_SCAN_REPORT_INVALID", "Docker Scout SARIF report is missing"
            )
        try:
            payload = json.loads(self.report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(
                "CONTAINER_SCAN_REPORT_INVALID", "Docker Scout SARIF report is invalid"
            ) from error
        results = self._sarif_results(payload)
        report_bytes = self.report_path.read_bytes()
        findings = len(results)
        return complete(
            "container_scan",
            started_at=started,
            coordinates={
                "candidate_image": self.candidate_image,
                "scanner": "docker-scout",
                "scanner_version": version_match.group(1),
                "severity_policy": "critical,high",
                "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            },
            checks=(
                GateCheck("docker_scout_authenticated", True),
                GateCheck("immutable_image_reference", True),
                GateCheck("sarif_contract", True),
                GateCheck(
                    "no_critical_or_high_vulnerabilities",
                    findings == 0 and scan.returncode == 0,
                    {"findings": findings},
                ),
            ),
            metrics={
                "critical_or_high_findings": findings,
                "report_bytes": len(report_bytes),
                "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                "scanner_version": version_match.group(1),
            },
        )


class DockerScoutReleaseProbe:
    """Require clean Docker Scout results for both release runtime images."""

    def __init__(
        self,
        repository_root: str | Path,
        *,
        backend_image: str,
        web_image: str,
        backend_report_path: str | Path,
        credentials_file: str | Path,
        run_command: CommandRunner = subprocess.run,
    ) -> None:
        self.root = Path(repository_root)
        self.backend_image = backend_image
        self.web_image = web_image
        self.backend_report_path = Path(backend_report_path)
        self.credentials_file = credentials_file
        self.run_command = run_command

    def run(self) -> GateEvidence:
        started = utc_now()
        backend_report = self.backend_report_path
        web_report = backend_report.with_name("web-" + backend_report.name)
        values: dict[str, GateEvidence] = {}
        for name, image, report in (
            ("backend", self.backend_image, backend_report),
            ("web", self.web_image, web_report),
        ):
            values[name] = DockerScoutImageProbe(
                self.root,
                candidate_image=image,
                report_path=report,
                credentials_file=self.credentials_file,
                run_command=self.run_command,
            ).run()
        return complete(
            "container_scan",
            started_at=started,
            coordinates={
                "backend_image": self.backend_image,
                "web_image": self.web_image,
                "severity_policy": "critical,high",
                "backend_report_sha256": values["backend"].metrics["report_sha256"],
                "web_report_sha256": values["web"].metrics["report_sha256"],
            },
            checks=(
                GateCheck(
                    "backend_no_critical_or_high_vulnerabilities",
                    values["backend"].status == "PASSED",
                    {"findings": values["backend"].metrics["critical_or_high_findings"]},
                ),
                GateCheck(
                    "web_no_critical_or_high_vulnerabilities",
                    values["web"].status == "PASSED",
                    {"findings": values["web"].metrics["critical_or_high_findings"]},
                ),
            ),
            metrics={
                "images_scanned": 2,
                "critical_or_high_findings": sum(
                    int(values[name].metrics["critical_or_high_findings"])
                    for name in ("backend", "web")
                ),
                "backend_report_sha256": str(values["backend"].metrics["report_sha256"]),
                "web_report_sha256": str(values["web"].metrics["report_sha256"]),
                "scanner_version": str(values["backend"].metrics["scanner_version"]),
            },
        )
