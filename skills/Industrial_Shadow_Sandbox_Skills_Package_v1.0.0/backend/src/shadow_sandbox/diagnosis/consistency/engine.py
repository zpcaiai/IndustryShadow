from .rule_dsl import ConsistencyRule


class ConsistencyEngine:
    def evaluate(self, rule: ConsistencyRule, observation):
        applies = (
            observation.applicability == "APPLICABLE"
            and (observation.normalized_magnitude or 0) >= rule.minimum_magnitude
            and (rule.direction is None or observation.direction == rule.direction)
        )
        return {"code": rule.code, "matched": applies, "residual_digest": observation.digest}
