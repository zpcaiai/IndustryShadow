from __future__ import annotations

import argparse
from pathlib import Path

from shadow_sandbox.common.models import canonical_json
from shadow_sandbox.operations.backup_receipt_collector import (
    collect_completed_backup_receipt,
    load_signed_backup_receipt_expectations,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Collect one completed production backup receipt from an exact Kubernetes Job"
        )
    )
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--job-uid", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--build-digest", required=True)
    parser.add_argument("--simulator-build-digest", required=True)
    parser.add_argument("--environment-digest", required=True)
    parser.add_argument("--deployment-plan-digest", required=True)
    parser.add_argument("--formal-report", type=Path, required=True)
    parser.add_argument("--deployment-plan", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--trust-root-attestation", type=Path, required=True)
    parser.add_argument("--trust-root-public-key", type=Path, required=True)
    parser.add_argument("--trust-root-key-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    expectations = load_signed_backup_receipt_expectations(
        repository_root=ROOT,
        formal_report_path=arguments.formal_report,
        deployment_plan_path=arguments.deployment_plan,
        candidate_image=arguments.candidate_image,
        build_digest=arguments.build_digest,
        simulator_build_digest=arguments.simulator_build_digest,
        environment_digest=arguments.environment_digest,
        deployment_plan_digest=arguments.deployment_plan_digest,
        trust_store_path=arguments.trust_store,
        trust_root_attestation_path=arguments.trust_root_attestation,
        trust_root_public_key_path=arguments.trust_root_public_key,
        trust_root_key_sha256=arguments.trust_root_key_sha256,
    )
    receipt = collect_completed_backup_receipt(
        context=arguments.context,
        namespace=arguments.namespace,
        job_name=arguments.job_name,
        job_uid=arguments.job_uid,
        expectations=expectations,
        output_path=arguments.output,
    )
    print(
        canonical_json(
            {
                "schema_version": 1,
                "status": "collected",
                "receipt_digest": receipt.receipt_digest,
                "output": str(arguments.output),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
