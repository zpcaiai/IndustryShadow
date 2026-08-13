from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now
from shadow_sandbox.evaluation.metrics.entities import EpisodeEvaluationInput
from shadow_sandbox.evaluation.metrics.evaluator import Evaluator
from shadow_sandbox.evaluation.metrics.gate import ReleaseGate
from shadow_sandbox.operations.evidence import GateCheck, GateEvidence, complete
from shadow_sandbox.operations.trust_store import SignerTrustStore
from shadow_sandbox.scenarios import expand_mvp_benchmark

DIGEST = re.compile(r"^[a-f0-9]{64}$")
RESULT_KEYS = frozenset(
    {
        "episode_id",
        "gold_rank",
        "detected",
        "plan_score",
        "critical_step_omitted",
        "unsupported_claims",
        "unapproved_actions",
        "real_write_attempts",
        "gold_leaks",
        "replay_match",
        "report_success",
        "trace_success",
    }
)
REPORT_KEYS = frozenset(
    {
        "schema_version",
        "benchmark_id",
        "assessor",
        "started_at",
        "completed_at",
        "candidate_image",
        "build_digest",
        "simulator_build_digest",
        "suite_digest",
        "bundle_digest",
        "result_digest",
        "evaluation_digest",
        "certification_digest",
        "target_profile_digest",
        "artifacts",
        "limitations",
        "public_key_b64",
        "report_digest",
        "signature_b64",
    }
)
MEASUREMENT_LOG_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "started_at",
        "completed_at",
        "episode_ids",
        "completed_episode_ids",
        "failed_episode_ids",
        "target_profile_digest",
        "result_digest",
    }
)
TARGET_PROFILE_KEYS = frozenset(
    {
        "schema_version",
        "profile_id",
        "collected_at",
        "runner_os",
        "runner_architecture",
        "cpu_count",
        "memory_bytes",
        "orchestrator_version",
        "cluster_uid_digest",
        "candidate_image",
        "build_digest",
        "simulator_build_digest",
    }
)


class FormalBenchmarkImporter:
    """Independently recompute the Gate from signed, sanitized target-run outcomes."""

    def __init__(
        self,
        repository_root: str | Path,
        *,
        candidate_image: str,
        build_digest: str,
        simulator_build_digest: str,
        trust_store: SignerTrustStore | None = None,
        environment_digest: str | None = None,
    ) -> None:
        self.root = Path(repository_root).resolve()
        if not re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", candidate_image):
            raise DomainError(
                "FORMAL_BENCHMARK_BUNDLE_INVALID", "candidate image must be digest pinned"
            )
        if not DIGEST.fullmatch(build_digest) or not DIGEST.fullmatch(simulator_build_digest):
            raise DomainError(
                "FORMAL_BENCHMARK_BUNDLE_INVALID", "build digests must be lowercase SHA-256"
            )
        self.candidate_image = candidate_image
        self.build_digest = build_digest
        self.simulator_build_digest = simulator_build_digest
        self.trust_store = trust_store
        self.environment_digest = environment_digest
        self.episodes = expand_mvp_benchmark()
        self.episodes_by_id = {item.episode_id: item for item in self.episodes}
        self.suite_digest = canonical_digest([asdict(item) for item in self.episodes])
        self.bundle_digest = canonical_digest(
            [
                candidate_image,
                build_digest,
                simulator_build_digest,
                self.suite_digest,
                pump_tank_model().digest,
            ]
        )

    def _artifact(self, item: Mapping[str, Any]) -> tuple[str, Path, GateCheck]:
        if set(item) != {"kind", "path", "sha256"} or not DIGEST.fullmatch(
            str(item.get("sha256", ""))
        ):
            raise DomainError(
                "FORMAL_BENCHMARK_ARTIFACT_INVALID", "artifact fields are invalid"
            )
        kind = str(item.get("kind", ""))
        path = (self.root / str(item.get("path", ""))).resolve(strict=True)
        if self.root not in path.parents or path.is_symlink():
            raise DomainError("FORMAL_BENCHMARK_ARTIFACT_INVALID", "artifact is outside repository")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        return (
            kind,
            path,
            GateCheck(
                "artifact_" + kind,
                bool(kind) and actual == item.get("sha256"),
                {"bytes": path.stat().st_size},
            ),
        )

    @staticmethod
    def _ranked(rank: Any, detected: bool, normal: bool) -> tuple[str, ...]:
        if rank is None:
            return ("candidate",) if detected else ()
        if normal or isinstance(rank, bool) or not isinstance(rank, int) or not 1 <= rank <= 100:
            raise DomainError(
                "FORMAL_BENCHMARK_RESULT_INVALID", "Gold rank is invalid for the Episode"
            )
        if not detected:
            raise DomainError(
                "FORMAL_BENCHMARK_RESULT_INVALID", "a ranked Gold result must be detected"
            )
        return tuple(
            "sealed-gold" if index == rank else f"candidate-{index}" for index in range(1, rank + 1)
        )

    def evaluate_results(self, path: Path) -> tuple[Any, str]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = payload.get("episodes", ()) if isinstance(payload, Mapping) else ()
        if not isinstance(records, list) or len(records) != len(self.episodes):
            raise DomainError(
                "FORMAL_BENCHMARK_RESULT_INVALID", "formal result must contain every Episode"
            )
        inputs: list[EpisodeEvaluationInput] = []
        observed_ids: set[str] = set()
        for record in records:
            if not isinstance(record, Mapping) or set(record) != RESULT_KEYS:
                raise DomainError(
                    "FORMAL_BENCHMARK_RESULT_INVALID", "Episode result fields are invalid"
                )
            episode_id = str(record["episode_id"])
            episode = self.episodes_by_id.get(episode_id)
            if episode is None or episode_id in observed_ids:
                raise DomainError(
                    "FORMAL_BENCHMARK_RESULT_INVALID", "Episode result set is not exact"
                )
            observed_ids.add(episode_id)
            normal = episode.fault_type is None
            boolean_fields = (
                "detected",
                "critical_step_omitted",
                "replay_match",
                "report_success",
                "trace_success",
            )
            integer_fields = (
                "unsupported_claims",
                "unapproved_actions",
                "real_write_attempts",
                "gold_leaks",
            )
            if any(not isinstance(record[name], bool) for name in boolean_fields) or any(
                isinstance(record[name], bool)
                or not isinstance(record[name], int)
                or int(record[name]) < 0
                for name in integer_fields
            ):
                raise DomainError(
                    "FORMAL_BENCHMARK_RESULT_INVALID", "Episode result types are invalid"
                )
            plan_score = record["plan_score"]
            if (
                isinstance(plan_score, bool)
                or not isinstance(plan_score, (int, float))
                or not 0 <= float(plan_score) <= 1
            ):
                raise DomainError(
                    "FORMAL_BENCHMARK_RESULT_INVALID", "Episode plan score is invalid"
                )
            detected = record["detected"]
            ranked = self._ranked(record["gold_rank"], detected, normal)
            inputs.append(
                EpisodeEvaluationInput(
                    episode_id,
                    normal,
                    () if normal else ("sealed-gold",),
                    ranked,
                    detected,
                    float(plan_score),
                    record["critical_step_omitted"],
                    int(record["unsupported_claims"]),
                    int(record["unapproved_actions"]),
                    int(record["real_write_attempts"]),
                    int(record["gold_leaks"]),
                    record["replay_match"],
                    record["report_success"],
                    record["trace_success"],
                    {
                        "fault": episode.fault_type or "normal",
                        "severity": episode.severity or "normal",
                        "load": episode.load,
                    },
                )
            )
        if observed_ids != set(self.episodes_by_id):
            raise DomainError("FORMAL_BENCHMARK_RESULT_INVALID", "Episode result set is incomplete")
        return Evaluator().evaluate("formal-target-benchmark-v1", tuple(inputs)), canonical_digest(
            records
        )

    @staticmethod
    def _json_object(path: Path, code: str) -> Mapping[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DomainError(code, "formal measurement artifact is not valid JSON") from error
        if not isinstance(value, Mapping):
            raise DomainError(code, "formal measurement artifact must be an object")
        return value

    def _validate_target_profile(self, path: Path) -> Mapping[str, Any]:
        profile = self._json_object(path, "FORMAL_TARGET_PROFILE_INVALID")
        try:
            collected = dt.datetime.fromisoformat(
                str(profile.get("collected_at", ""))
            )
        except ValueError as error:
            raise DomainError(
                "FORMAL_TARGET_PROFILE_INVALID", "target profile timestamp is invalid"
            ) from error
        if (
            set(profile) != TARGET_PROFILE_KEYS
            or profile.get("schema_version") != 1
            or not str(profile.get("profile_id", "")).strip()
            or collected.tzinfo is None
            or not str(profile.get("runner_os", "")).strip()
            or not str(profile.get("runner_architecture", "")).strip()
            or isinstance(profile.get("cpu_count"), bool)
            or not isinstance(profile.get("cpu_count"), int)
            or int(profile["cpu_count"]) < 1
            or isinstance(profile.get("memory_bytes"), bool)
            or not isinstance(profile.get("memory_bytes"), int)
            or int(profile["memory_bytes"]) < 512 * 1024 * 1024
            or not str(profile.get("orchestrator_version", "")).strip()
            or not DIGEST.fullmatch(str(profile.get("cluster_uid_digest", "")))
            or profile.get("candidate_image") != self.candidate_image
            or profile.get("build_digest") != self.build_digest
            or profile.get("simulator_build_digest") != self.simulator_build_digest
        ):
            raise DomainError(
                "FORMAL_TARGET_PROFILE_INVALID", "target profile contract is invalid"
            )
        return profile

    def _validate_measurement_log(
        self,
        path: Path,
        *,
        result_digest: str,
        target_profile_digest: str,
    ) -> Mapping[str, Any]:
        log = self._json_object(path, "FORMAL_MEASUREMENT_LOG_INVALID")
        try:
            started = dt.datetime.fromisoformat(
                str(log.get("started_at", ""))
            )
            completed = dt.datetime.fromisoformat(
                str(log.get("completed_at", ""))
            )
        except ValueError as error:
            raise DomainError(
                "FORMAL_MEASUREMENT_LOG_INVALID", "measurement timestamps are invalid"
            ) from error
        expected_ids = set(self.episodes_by_id)
        episode_ids = log.get("episode_ids")
        completed_ids = log.get("completed_episode_ids")
        failed_ids = log.get("failed_episode_ids")
        if (
            set(log) != MEASUREMENT_LOG_KEYS
            or log.get("schema_version") != 1
            or not str(log.get("run_id", "")).strip()
            or started.tzinfo is None
            or completed.tzinfo is None
            or completed < started
            or not isinstance(episode_ids, list)
            or any(not isinstance(item, str) for item in episode_ids)
            or len(episode_ids) != len(set(episode_ids))
            or set(episode_ids) != expected_ids
            or not isinstance(completed_ids, list)
            or any(not isinstance(item, str) for item in completed_ids)
            or len(completed_ids) != len(set(completed_ids))
            or set(completed_ids) != expected_ids
            or failed_ids != []
            or log.get("target_profile_digest") != target_profile_digest
            or log.get("result_digest") != result_digest
        ):
            raise DomainError(
                "FORMAL_MEASUREMENT_LOG_INVALID", "measurement log contract is invalid"
            )
        return log

    @staticmethod
    def _verify_signature(report: Mapping[str, Any]) -> str:
        claimed = str(report.get("report_digest", ""))
        payload = {
            **{key: value for key, value in report.items() if key != "signature_b64"},
            "report_digest": "",
        }
        if claimed != canonical_digest(payload):
            raise DomainError(
                "FORMAL_BENCHMARK_DIGEST_INVALID", "formal benchmark report digest mismatch"
            )
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(str(report["public_key_b64"]), validate=True)
            ).verify(
                base64.b64decode(str(report["signature_b64"]), validate=True),
                claimed.encode("ascii"),
            )
        except Exception as error:
            raise DomainError(
                "FORMAL_BENCHMARK_SIGNATURE_INVALID", "formal benchmark signature is invalid"
            ) from error
        return claimed

    def import_report(self, report: Mapping[str, Any]) -> GateEvidence:
        if set(report) != REPORT_KEYS:
            raise DomainError("FORMAL_BENCHMARK_REPORT_INVALID", "formal report fields are invalid")
        started = str(report.get("started_at") or utc_now())
        completed = str(report.get("completed_at", ""))
        try:
            started_time = dt.datetime.fromisoformat(started)
            completed_time = dt.datetime.fromisoformat(completed)
            valid_times = (
                started_time.tzinfo is not None
                and completed_time.tzinfo is not None
                and completed_time >= started_time
            )
        except ValueError:
            valid_times = False
        limitations = report.get("limitations", ())
        if not isinstance(limitations, list) or any(
            not isinstance(item, str) for item in limitations
        ):
            raise DomainError(
                "FORMAL_BENCHMARK_REPORT_INVALID", "measurement limitations must be a list"
            )
        report_digest = self._verify_signature(report)
        if self.trust_store is None:
            raise DomainError(
                "FORMAL_BENCHMARK_TRUST_REQUIRED",
                "a trusted formal-measurement signer registry is required",
            )
        if not self.environment_digest or not DIGEST.fullmatch(self.environment_digest):
            raise DomainError(
                "FORMAL_BENCHMARK_ENVIRONMENT_REQUIRED",
                "an exact target environment digest is required",
            )
        signer_fingerprint = self.trust_store.verify_signer(
            identity=str(report.get("assessor", "")),
            purpose="formal_measurement",
            public_key_b64=str(report.get("public_key_b64", "")),
            signed_at=completed,
        )
        artifact_values = report.get("artifacts", ())
        if not isinstance(artifact_values, list) or any(
            not isinstance(item, Mapping) for item in artifact_values
        ):
            raise DomainError(
                "FORMAL_BENCHMARK_ARTIFACT_INVALID", "measurement artifacts must be a list"
            )
        artifacts = tuple(self._artifact(item) for item in artifact_values)
        by_kind = {kind: path for kind, path, _check in artifacts}
        required_kinds = {"episode_results", "measurement_log", "target_profile"}
        if len(by_kind) != len(artifacts) or set(by_kind) != required_kinds:
            raise DomainError(
                "FORMAL_BENCHMARK_ARTIFACT_INVALID",
                "exactly one Episode, measurement-log, and target-profile artifact is required",
            )
        evaluation, result_digest = self.evaluate_results(by_kind["episode_results"])
        target_profile_digest = hashlib.sha256(
            by_kind["target_profile"].read_bytes()
        ).hexdigest()
        target_profile = self._validate_target_profile(by_kind["target_profile"])
        measurement_log = self._validate_measurement_log(
            by_kind["measurement_log"],
            result_digest=result_digest,
            target_profile_digest=target_profile_digest,
        )
        gate = ReleaseGate().evaluate(
            "formal-target-benchmark-gate-v1", self.bundle_digest, evaluation
        )
        coordinates_match = (
            report.get("schema_version") == 1
            and bool(str(report.get("benchmark_id", "")).strip())
            and bool(str(report.get("assessor", "")).strip())
            and valid_times
            and report.get("candidate_image") == self.candidate_image
            and report.get("build_digest") == self.build_digest
            and report.get("simulator_build_digest") == self.simulator_build_digest
            and report.get("suite_digest") == self.suite_digest
            and report.get("bundle_digest") == self.bundle_digest
            and report.get("result_digest") == result_digest
            and report.get("evaluation_digest") == evaluation.digest
            and report.get("certification_digest") == gate.certification_digest
            and report.get("target_profile_digest")
            == target_profile_digest
            and report.get("target_profile_digest") == self.environment_digest
            and measurement_log.get("run_id") == report.get("benchmark_id")
            and measurement_log.get("started_at") == started
            and measurement_log.get("completed_at") == completed
        )
        checks = (
            GateCheck("signed_measurement_report", bool(report_digest)),
            GateCheck("trusted_measurement_assessor", bool(signer_fingerprint)),
            GateCheck("exact_candidate_bundle", coordinates_match),
            GateCheck("target_profile_contract", bool(target_profile)),
            GateCheck("measurement_log_contract", bool(measurement_log)),
            *(check for _kind, _path, check in artifacts),
            GateCheck("episode_count", len(self.episodes) >= 150),
            GateCheck("fault_count", evaluation.metrics["fault_episodes"] >= 100),
            GateCheck("normal_count", evaluation.metrics["normal_episodes"] >= 50),
            GateCheck("safety_red_lines", not any(evaluation.red_lines.values())),
            GateCheck("exact_bundle_release_gate", gate.passed),
            GateCheck("no_measurement_limitations", not limitations),
        )
        return complete(
            "benchmark_150",
            started_at=started,
            coordinates={
                "candidate_image": self.candidate_image,
                "build_digest": self.build_digest,
                "simulator_build_digest": self.simulator_build_digest,
                "suite_digest": self.suite_digest,
                "bundle_digest": self.bundle_digest,
                "result_digest": result_digest,
                "target_profile_digest": str(report.get("target_profile_digest", "")),
                "trust_store_digest": self.trust_store.digest,
                "signer_fingerprint": signer_fingerprint,
                "environment_digest": self.environment_digest,
            },
            checks=checks,
            metrics={
                **{key: round(value, 6) for key, value in evaluation.metrics.items()},
                **evaluation.red_lines,
                "episodes": len(self.episodes),
                "completed_episodes": len(measurement_log["completed_episode_ids"]),
                "trust_store_id": self.trust_store.store_id,
            },
            limitations=tuple(limitations),
            completed_at=completed,
        )
