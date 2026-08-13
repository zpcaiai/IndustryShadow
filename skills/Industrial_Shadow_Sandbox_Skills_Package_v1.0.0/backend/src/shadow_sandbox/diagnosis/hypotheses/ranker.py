from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

from shadow_sandbox.common.models import canonical_digest
from shadow_sandbox.diagnosis.evidence import Evidence, Symptom

from .entities import DiagnosisResult, Hypothesis
from .features import graph_consistency, rule_match

DEFAULT_CATALOG = {
    "sensor_bias": {"symptoms": {"signal-deviation"}, "prior": 0.5},
    "flow_sensor_stuck": {
        "symptoms": {"signal-deviation", "command-actual-mismatch"},
        "prior": 0.4,
    },
    "pressure_sensor_noise": {"symptoms": {"signal-deviation"}, "prior": 0.4},
    "inlet_valve_stiction": {
        "symptoms": {"command-actual-mismatch", "flow-response-low"},
        "prior": 0.5,
    },
    "pump_efficiency_loss": {
        "symptoms": {"flow-response-low", "current-load-mismatch"},
        "prior": 0.6,
    },
    "bearing_friction": {"symptoms": {"current-load-mismatch", "vibration-excess"}, "prior": 0.5},
    "outlet_blockage": {"symptoms": {"flow-response-low", "mass-deficit"}, "prior": 0.5},
    "tank_leak": {"symptoms": {"mass-deficit"}, "prior": 0.4},
    "heater_stuck": {
        "symptoms": {"heat-response-mismatch", "command-actual-mismatch"},
        "prior": 0.4,
    },
    "communication_failure": {"symptoms": {"multi-signal-stale"}, "prior": 0.5},
}


class HypothesisRanker:
    def __init__(self, catalog: Mapping[str, Mapping[str, object]] | None = None) -> None:
        self.catalog = dict(catalog or DEFAULT_CATALOG)
        self.weights = {
            "rule_match": 0.3,
            "temporal": 0.25,
            "graph": 0.2,
            "residual": 0.15,
            "prior": 0.1,
        }
        self.ranker_digest = canonical_digest([self.catalog, self.weights, "ranker-v1"])

    def rank(
        self, symptoms: Sequence[Symptom], evidence: Mapping[str, Evidence], quality_state: str
    ) -> DiagnosisResult:
        if quality_state == "UNTRUSTED" and not any(
            item.catalog_id == "multi-signal-stale" for item in symptoms
        ):
            return DiagnosisResult(
                "INCONCLUSIVE",
                (),
                quality_state,
                0.0,
                ("data_untrusted",),
                ("verify_data_quality",),
            )
        observed = {item.catalog_id for item in symptoms}
        ranked = []
        for cause_id, definition in self.catalog.items():
            expected = set(cast(set[str], definition["symptoms"]))
            matches = expected & observed
            if not matches:
                continue
            missing = expected - observed
            rule = rule_match(expected, observed)
            graph = graph_consistency(cause_id)
            residual = sum(item.severity for item in symptoms if item.catalog_id in matches) / max(
                len(matches), 1
            )
            prior = float(cast(float, definition.get("prior", 0.5)))
            contradiction = tuple(
                item.evidence_id
                for item in evidence.values()
                if item.role == "contradiction"
                and (
                    cause_id in item.related_assets
                    or item.evidence_type in {cause_id, f"contradicts:{cause_id}"}
                )
            )
            breakdown = {
                "rule_match": rule,
                "temporal": 1.0,
                "graph": graph,
                "residual": residual,
                "prior": prior,
                "contradiction_penalty": len(contradiction) * 0.15,
                "missing_penalty": len(missing) * 0.08,
            }
            score = (
                0.3 * rule
                + 0.25
                + 0.2 * graph
                + 0.15 * residual
                + 0.1 * prior
                - breakdown["contradiction_penalty"]
                - breakdown["missing_penalty"]
            )
            support = tuple(
                ref
                for symptom in symptoms
                if symptom.catalog_id in matches
                for ref in symptom.evidence_refs
            )
            ranked.append(
                (score, cause_id, breakdown, support, tuple(sorted(missing)), contradiction)
            )
        ranked.sort(key=lambda item: (-item[0], item[1]))
        if not ranked or ranked[0][0] < 0.35:
            return DiagnosisResult(
                "INCONCLUSIVE",
                (),
                quality_state,
                0.0,
                ("low_evidence_score",),
                ("collect_more_evidence",),
            )
        reasons = (
            ("insufficient_top_separation",)
            if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < 0.03
            else ()
        )
        hypotheses = tuple(
            Hypothesis(
                cause,
                index,
                round(max(0.0, min(1.0, score)), 6),
                breakdown,
                support,
                contradiction,
                missing,
                ((cause, "symptoms"),),
                ("fault_catalog", "symptom_mapping"),
                self.ranker_digest,
            )
            for index, (score, cause, breakdown, support, missing, contradiction) in enumerate(
                ranked[:3], 1
            )
        )
        coverage = len(set().union(*(set(item[4]) for item in ranked[:3])))
        return DiagnosisResult(
            "INCONCLUSIVE" if reasons else "RANKED",
            hypotheses,
            quality_state,
            1 / (1 + coverage),
            reasons,
            ("run_discriminative_check",) if reasons else (),
        )
