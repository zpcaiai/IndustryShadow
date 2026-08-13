from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from shadow_sandbox.common.models import (
    DomainError,
    canonical_digest,
    canonical_json,
    utc_now,
)
from shadow_sandbox.operations.evidence import (
    bind_to_acceptance_run,
    failed_execution,
    write_evidence,
)
from shadow_sandbox.operations.production_deployment import (
    KubernetesProductionPublisher,
    ProductionDeploymentPlan,
)

from tools.check_release_evidence import INPUT as CLOSURE_INPUT
from tools.check_release_evidence import main as check_release_evidence

ROOT = Path(__file__).resolve().parents[1]


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise DomainError("PRODUCTION_DEPLOY_CONFIG_MISSING", f"{name} is required")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy one closure-bound release to the approved Kubernetes target"
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-plan.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-evidence.json",
    )
    args = parser.parse_args()
    started = utc_now()
    run_id = "unbound-" + canonical_digest({"started_at": started})[:20]
    release_digest = canonical_digest({"configuration": "incomplete"})
    evidence = None
    try:
        if check_release_evidence() != 0:
            raise DomainError(
                "PRODUCTION_CLOSURE_REQUIRED",
                "verified production closure is required before deployment",
            )
        closure = json.loads(CLOSURE_INPUT.read_text(encoding="utf-8"))
        approval = closure["approval"]
        coordinates = approval["release_coordinates"]
        run_id = str(approval["acceptance_run_id"])
        release_digest = str(approval["release_digest"])
        plan = ProductionDeploymentPlan.load(
            ROOT,
            args.plan,
            candidate_image=str(coordinates["candidate_image"]),
            expected_digest=str(coordinates["deployment_plan_digest"]),
        )
        evidence = KubernetesProductionPublisher(
            plan,
            confirmation=_required("SHADOW_PRODUCTION_DEPLOYMENT_CONFIRMATION"),
        ).run()
        evidence = bind_to_acceptance_run(
            evidence, run_id=run_id, release_digest=release_digest
        )
    except DomainError as error:
        evidence = failed_execution(
            "production_deployment",
            started_at=started,
            error_code=error.code,
            run_id=run_id,
            release_digest=release_digest,
        )
    except Exception:  # noqa: BLE001 - unexpected deployment faults must fail closed
        evidence = failed_execution(
            "production_deployment",
            started_at=started,
            error_code="UNEXPECTED",
            run_id=run_id,
            release_digest=release_digest,
        )
    write_evidence(args.output, evidence)
    print(
        canonical_json(
            {
                "gate": evidence.gate,
                "status": evidence.status,
                "evidence": str(args.output),
                "digest": evidence.digest,
            }
        )
    )
    return 0 if evidence.status == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
