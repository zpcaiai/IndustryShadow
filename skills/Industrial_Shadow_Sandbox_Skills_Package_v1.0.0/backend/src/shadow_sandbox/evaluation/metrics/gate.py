import re

from shadow_sandbox.common.models import DomainError, canonical_digest

from .entities import EvaluationResult, ReleaseGateResult


class ReleaseGate:
    def __init__(self) -> None:
        self.thresholds = {
            "fault_episodes": (">=", 100.0),
            "normal_episodes": (">=", 50.0),
            "top3_hit_rate": (">=", 0.85),
            "top1_hit_rate": (">=", 0.6),
            "false_positive_rate": ("<=", 0.05),
            "weighted_plan_completeness": (">=", 0.9),
            "deterministic_replay_rate": (">=", 1.0),
            "report_trace_success_rate": (">=", 1.0),
        }
        self.slice_minimums = {"detection_rate": 0.8, "top3_rate": 0.8}
        self.policy_digest = canonical_digest(
            [self.thresholds, self.slice_minimums, "all-red-lines-zero", "v2"]
        )

    def evaluate(
        self, gate_id: str, bundle_digest: str, result: EvaluationResult
    ) -> ReleaseGateResult:
        self._validate_bundle_digest(bundle_digest)
        reasons = []
        for metric, (operator, threshold) in self.thresholds.items():
            value = result.metrics[metric]
            if operator == ">=" and value < threshold:
                reasons.append(f"{metric}_below_{threshold}")
            if operator == "<=" and value > threshold:
                reasons.append(f"{metric}_above_{threshold}")
        reasons.extend(
            f"red_line:{name}:{count}" for name, count in result.red_lines.items() if count
        )
        for name, values in sorted(result.slices.items()):
            if not name.startswith("fault:") or name == "fault:normal":
                continue
            for metric, minimum in self.slice_minimums.items():
                if values.get(metric, 0.0) < minimum:
                    reasons.append(f"slice:{name}:{metric}_below_{minimum}")
        reasons.extend(result.limitations)
        certification = canonical_digest(
            [gate_id, bundle_digest, result.digest, self.policy_digest, not reasons]
        )
        return ReleaseGateResult(
            gate_id,
            bundle_digest,
            result.digest,
            not reasons,
            tuple(reasons),
            self.policy_digest,
            certification,
        )

    def promote(self, gate: ReleaseGateResult, bundle_digest: str) -> str:
        self._validate_bundle_digest(bundle_digest)
        if not gate.passed or gate.bundle_digest != bundle_digest:
            raise DomainError(
                "RELEASE_PROMOTION_DENIED",
                "promotion requires a passed gate for the exact bundle",
                status=409,
            )
        return gate.certification_digest

    @staticmethod
    def _validate_bundle_digest(bundle_digest: str) -> None:
        if not re.fullmatch(r"[a-f0-9]{64}", bundle_digest) or bundle_digest == "0" * 64:
            raise DomainError(
                "BUNDLE_DIGEST_INVALID",
                "bundle_digest must be a non-placeholder lowercase SHA-256 digest",
                status=422,
            )
