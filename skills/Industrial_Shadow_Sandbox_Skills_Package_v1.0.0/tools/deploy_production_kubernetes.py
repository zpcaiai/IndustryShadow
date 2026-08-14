from __future__ import annotations

import argparse
import hashlib
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


def _signed_target_cluster_digest(
    *,
    environment_digest: str,
    coordinates: dict[str, object],
    plan: ProductionDeploymentPlan,
) -> tuple[str, str]:
    report_path = (
        ROOT / "docs/evidence/batch-24/production/formal-benchmark/report.json"
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    artifacts = report.get("artifacts", ())
    targets = [item for item in artifacts if item.get("kind") == "target_profile"]
    if (
        len(targets) != 1
        or report.get("target_profile_digest") != environment_digest
        or targets[0].get("sha256") != environment_digest
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "closure-bound target profile artifact is missing",
        )
    target_path = (ROOT / str(targets[0].get("path", ""))).resolve(strict=True)
    if ROOT.resolve() not in target_path.parents or target_path.is_symlink():
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile path is unsafe"
        )
    if hashlib.sha256(target_path.read_bytes()).hexdigest() != environment_digest:
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID", "target profile digest mismatch"
        )
    target = json.loads(target_path.read_text(encoding="utf-8"))
    if (
        target.get("candidate_image") != coordinates.get("candidate_image")
        or target.get("build_digest") != coordinates.get("build_digest")
        or target.get("simulator_build_digest")
        != coordinates.get("simulator_build_digest")
        or target.get("deployment_plan_digest")
        != coordinates.get("deployment_plan_digest")
        or target.get("snapshot_object_storage_prefix")
        != plan.snapshot_object_storage_prefix
        or target.get("backup_object_storage_prefix")
        != plan.backup_object_storage_prefix
        or target.get("snapshot_workload_identity_arn_digest")
        != plan.snapshot_workload_identity_arn_digest
        or target.get("backup_workload_identity_arn_digest")
        != plan.backup_workload_identity_arn_digest
        or not isinstance(target.get("cluster_uid_digest"), str)
        or len(target["cluster_uid_digest"]) != 64
        or not isinstance(target.get("kubernetes_api_ca_digest"), str)
        or len(target["kubernetes_api_ca_digest"]) != 64
    ):
        raise DomainError(
            "PRODUCTION_TARGET_PROFILE_INVALID",
            "target profile release coordinates mismatch",
        )
    return str(target["cluster_uid_digest"]), str(target["kubernetes_api_ca_digest"])


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
        "--journal",
        type=Path,
        default=ROOT
        / "docs/evidence/batch-24/production-deployment/deployment-journal.json",
    )
    parser.add_argument(
        "--rollback-only",
        action="store_true",
        help="resume a prior-bundle rollback without applying the candidate bundle",
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
        cluster_uid_digest, api_ca_digest = _signed_target_cluster_digest(
            environment_digest=str(coordinates["environment_digest"]),
            coordinates=coordinates,
            plan=plan,
        )
        publisher = KubernetesProductionPublisher(
            plan,
            confirmation=_required("SHADOW_PRODUCTION_DEPLOYMENT_CONFIRMATION"),
            context=_required("SHADOW_KUBERNETES_CONTEXT"),
            expected_cluster_uid_digest=cluster_uid_digest,
            expected_kubernetes_api_ca_digest=api_ca_digest,
            journal_path=args.journal,
        )
        evidence = (
            publisher.resume_rollback() if args.rollback_only else publisher.run()
        )
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
