from dataclasses import asdict

from shadow_sandbox.common.models import canonical_digest

from .diagnosis import diagnosis_metrics
from .entities import EvaluationResult
from .evidence import evidence_red_lines
from .false_positive import false_positive_metrics
from .planning import planning_metrics
from .recovery import recovery_metrics
from .safety import safety_red_lines


class Evaluator:
    VERSION = "evaluator-v1"

    def evaluate(self, evaluation_id: str, episodes) -> EvaluationResult:
        faults = [item for item in episodes if not item.is_normal]
        normals = [item for item in episodes if item.is_normal]
        metrics = {
            "fault_episodes": float(len(faults)),
            "normal_episodes": float(len(normals)),
            **diagnosis_metrics(faults),
            **false_positive_metrics(normals),
            **{
                key: value
                for key, value in planning_metrics(faults).items()
                if key == "weighted_plan_completeness"
            },
            **recovery_metrics(episodes),
        }
        plan = planning_metrics(faults)
        red_lines = {
            "critical_step_omissions": plan["critical_step_omissions"],
            **evidence_red_lines(episodes),
            **safety_red_lines(episodes),
        }
        slices = {}
        for item in episodes:
            for axis, label in item.slice_labels.items():
                bucket = slices.setdefault(
                    f"{axis}:{label}", {"episodes": 0.0, "detected": 0.0, "top3": 0.0}
                )
                bucket["episodes"] += 1
                bucket["detected"] += float(item.detected)
                bucket["top3"] += float(bool(set(item.gold_causes) & set(item.ranked_causes[:3])))
        for bucket in slices.values():
            bucket["detection_rate"] = bucket["detected"] / max(bucket["episodes"], 1)
            bucket["top3_rate"] = bucket["top3"] / max(bucket["episodes"], 1)
        limitations = () if len(episodes) >= 150 else ("corpus_below_150_episodes",)
        return EvaluationResult(
            evaluation_id,
            canonical_digest([asdict(item) for item in episodes]),
            metrics,
            slices,
            red_lines,
            limitations,
            canonical_digest([self.VERSION, sorted(metrics)]),
        )
