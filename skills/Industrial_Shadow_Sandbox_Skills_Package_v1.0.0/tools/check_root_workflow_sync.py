"""Fail closed when repository-visible workflows drift from package templates."""

from __future__ import annotations

import difflib
import re
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parent.parent
PACKAGE_RELATIVE = PACKAGE_ROOT.relative_to(REPOSITORY_ROOT).as_posix()
TEMPLATE_DIRECTORY = PACKAGE_ROOT / ".github" / "workflows"
ROOT_WORKFLOW_DIRECTORY = REPOSITORY_ROOT / ".github" / "workflows"

WORKFLOWS = {
    "ci.yml": "ci.yml",
    "release.yml": "release.yml",
    "production-acceptance.yml": "production-acceptance.yml",
    "production-closure.yml": "production-closure.yml",
    "production-deploy.yml": "production-deploy.yml",
    "recertification.yml": "scheduled-closure-revalidation.yml",
}

ACTION_PATH_KEYS = {
    "cache-dependency-path",
    "context",
    "file",
    "output-file",
    "path",
    "sbom-path",
    "subject-path",
}

WORKFLOW_PATH_BINDINGS = {
    "production-acceptance.yml": (".github/workflows/release.yml",),
    "production-closure.yml": (".github/workflows/production-acceptance.yml",),
    "production-deploy.yml": (
        ".github/workflows/production-closure.yml",
        ".github/workflows/production-deploy.yml",
    ),
    "scheduled-closure-revalidation.yml": (".github/workflows/production-closure.yml",),
}

ARTIFACT_BINDING_FRAGMENTS = {
    "ci.yml": ("evidence-refresh-${{ github.run_id }}-${{ github.run_attempt }}",),
    "release.yml": (
        "release-verification-${{ github.run_id }}-${{ github.run_attempt }}",
        "immutable-release-candidate-${{ github.run_id }}-${{ github.run_attempt }}",
    ),
    "production-acceptance.yml": (
        (
            "immutable-release-candidate-${{ inputs.release_run_id }}-"
            "${{ steps.release-run.outputs.run_attempt }}"
        ),
        "production-acceptance-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
    ),
    "production-closure.yml": (
        (
            "production-acceptance-evidence-${{ inputs.acceptance_run_id }}-"
            "${{ steps.acceptance-run.outputs.run_attempt }}"
        ),
        "production-closure-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
    ),
    "production-deploy.yml": (
        'artifact_expected_name="production-closure-evidence-$CLOSURE_RUN_ID-$run_attempt"',
        "name: ${{ steps.closure-run.outputs.artifact_name }}",
        'artifact_name="production-deployment-evidence-$PRIOR_DEPLOYMENT_RUN_ID-$run_attempt"',
        (
            "name: production-deployment-evidence-"
            "${{ inputs.prior_deployment_run_id }}-"
            "${{ steps.prior-run.outputs.run_attempt }}"
        ),
        'case "$conclusion" in failure|cancelled)',
        (
            "--recovery-envelope docs/evidence/batch-24/production-deployment/"
            "deployment-recovery-envelope.json"
        ),
        "--same-run-rollback",
        "--prior-recovery-envelope",
        '--prior-conclusion "$PRIOR_CONCLUSION"',
        "production-deployment-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
    ),
    "scheduled-closure-revalidation.yml": (
        'artifact_expected_name="production-closure-evidence-$REQUESTED_RUN_ID-$run_attempt"',
        "name: ${{ steps.closure.outputs.artifact_name }}",
        "scheduled-closure-revalidation-${{ github.run_id }}-${{ github.run_attempt }}",
    ),
}


def _workflow_inventory(directory: Path) -> set[str]:
    """Return every workflow filename GitHub could discover in a directory."""
    if not directory.is_dir() or directory.is_symlink():
        return set()
    return {
        path.name
        for path in directory.iterdir()
        if path.suffix.lower() in {".yml", ".yaml"}
    }


def _prefix(value: str) -> str:
    """Resolve an action input path against the package checkout."""
    if (
        not value
        or value == "|"
        or value.startswith(("${{", "/", "!", PACKAGE_RELATIVE + "/"))
    ):
        return value
    if value == ".":
        return PACKAGE_RELATIVE
    return f"{PACKAGE_RELATIVE}/{value}"


def render_root_workflow(template_name: str) -> str:
    """Render the only supported root-path adaptation of a package workflow."""
    template_path = TEMPLATE_DIRECTORY / template_name
    source = template_path.read_text(encoding="utf-8")
    marker = "\njobs:\n"
    if source.count(marker) != 1:
        raise ValueError(f"{template_path}: expected exactly one jobs mapping")
    source = source.replace(
        marker,
        f"\ndefaults:\n  run:\n    working-directory: {PACKAGE_RELATIVE}\n\njobs:\n",
        1,
    )

    output: list[str] = []
    path_block_indent: int | None = None
    checkout_seen = False
    action_input = re.compile(
        r"^(?P<indent>\s+)(?P<key>"
        + "|".join(ACTION_PATH_KEYS)
        + r"):\s*(?P<value>.*)$"
    )
    for original_line in source.splitlines():
        line = original_line
        if re.fullmatch(r"  [A-Za-z0-9_-]+:", line):
            checkout_seen = False
        if line.startswith("      - uses: actions/checkout@"):
            checkout_seen = True
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if path_block_indent is not None:
            if stripped and indent <= path_block_indent:
                path_block_indent = None
            elif stripped and not stripped.startswith("#"):
                prefix = line[:indent]
                line = prefix + _prefix(stripped)

        match = action_input.fullmatch(line)
        if match and len(match.group("indent")) == 10:
            value = match.group("value")
            if match.group("key") == "path" and value == "|":
                path_block_indent = len(match.group("indent"))
            else:
                line = f"{match.group('indent')}{match.group('key')}: {_prefix(value)}"

        if stripped == "working-directory: web":
            line = line[:indent] + f"working-directory: {PACKAGE_RELATIVE}/web"
        if (
            not checkout_seen
            and line.startswith("        run:")
            and (not output or "working-directory:" not in output[-1])
        ):
            output.append("        working-directory: ${{ github.workspace }}")
        output.append(line)

    return (
        "# Generated root entrypoint; edit the package template and sync deliberately.\n"
        f"# Template: {PACKAGE_RELATIVE}/.github/workflows/{template_name}\n"
        + "\n".join(output)
        + "\n"
    )


def _validate_contract(root_name: str, content: str) -> list[str]:
    errors: list[str] = []
    package_default = f"defaults:\n  run:\n    working-directory: {PACKAGE_RELATIVE}\n"
    if package_default not in content:
        errors.append(f"{root_name}: missing package working-directory default")
    for expected_workflow_path in WORKFLOW_PATH_BINDINGS.get(root_name, ()):
        binding = f'"${{workflow_path%%@*}}" = {expected_workflow_path}'
        if binding not in content:
            errors.append(
                f"{root_name}: missing API workflow path {expected_workflow_path}"
            )
    for fragment in ARTIFACT_BINDING_FRAGMENTS.get(root_name, ()):
        if fragment not in content:
            errors.append(
                f"{root_name}: missing run/attempt artifact binding {fragment}"
            )
    for line in content.splitlines():
        match = re.fullmatch(
            r"\s{10}(?:" + "|".join(ACTION_PATH_KEYS) + r"):\s*(.+)", line
        )
        if not match:
            continue
        value = match.group(1)
        if value == "|" or value.startswith((PACKAGE_RELATIVE + "/", "${{", "/")):
            continue
        if value == PACKAGE_RELATIVE:
            continue
        errors.append(f"{root_name}: unrooted action path input {value}")
    for line in content.splitlines():
        if "working-directory:" not in line:
            continue
        value = line.split("working-directory:", 1)[1].strip()
        if value not in {
            PACKAGE_RELATIVE,
            f"{PACKAGE_RELATIVE}/web",
            "${{ github.workspace }}",
        }:
            errors.append(f"{root_name}: unrooted shell working-directory {value}")
    if root_name == "ci.yml":
        required = (
            f"working-directory: {PACKAGE_RELATIVE}/web",
            f"cache-dependency-path: {PACKAGE_RELATIVE}/backend/requirements.lock",
            f"cache-dependency-path: {PACKAGE_RELATIVE}/web/package-lock.json",
            f"context: {PACKAGE_RELATIVE}",
            f"file: {PACKAGE_RELATIVE}/deploy/compose/Dockerfile.backend",
            f"file: {PACKAGE_RELATIVE}/deploy/compose/Dockerfile.web",
            "workflow_dispatch:",
            "refresh_evidence:",
            "SHADOW_TEST_RESTORE_POSTGRESQL_URL:",
            (
                "postgresql+psycopg://shadow_test:shadow_test_password@127.0.0.1:"
                "5432/shadow_test?sslmode=disable"
            ),
            (
                "postgresql+psycopg://shadow_test:shadow_restore_password@127.0.0.1:"
                "5433/shadow_restore_drill?sslmode=disable"
            ),
            'SHADOW_ALLOW_LOCAL_RESTORE_DRILL: "true"',
            "azure/setup-kubectl@829323503d1be3d00ca8346e5391ca0b07a9ab0d",
            "version: v1.32.2",
            "python tools/build_evidence.py",
            "python tools/validate_implementation.py",
            "python tools/stage_evidence_refresh.py",
            f"path: {PACKAGE_RELATIVE}/artifacts/evidence-refresh-staging",
        )
        for fragment in required:
            if fragment not in content:
                errors.append(f"ci.yml: missing root path contract {fragment}")
        refresh_job = content.split("\n  evidence-refresh:\n", 1)
        if len(refresh_job) != 2:
            errors.append("ci.yml: missing evidence-refresh job")
        elif "if: always()" in refresh_job[1]:
            errors.append(
                "ci.yml: failed evidence-refresh jobs must not upload artifacts"
            )
    if root_name == "production-acceptance.yml":
        required = (
            (
                "SHADOW_OIDC_BROWSER_JOURNEY: web/test-results/"
                "production-oidc-journey-${{ github.run_id }}-"
                "${{ github.run_attempt }}.json"
            ),
            "SHADOW_PRODUCTION_S3_CONTROL_PLANE_CONFIRMATION:",
            "SHADOW_S3_CONTROL_PLANE_CALLER_ARN:",
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY:",
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY_OWNER_ID:",
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY_ID:",
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REF:",
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_ENVIRONMENT:",
            "SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_WORKFLOW:",
            "SHADOW_KMS_ADMIN_ROLE_ARN:",
            "SHADOW_AWS_IRSA_OIDC_PROVIDER_ARN:",
            "SHADOW_KUBERNETES_NETWORK_CONTEXT:",
            "SHADOW_KUBERNETES_STORAGE_CONTEXT:",
            "SHADOW_KUBERNETES_CHAOS_CONTEXT:",
            "SHADOW_KUBERNETES_ROLLBACK_CONTEXT:",
            "Prepare pristine run-bound OIDC browser journey target",
            "Collect exact live AWS storage policy digests read-only",
            "aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708",
            "role-to-assume: ${{ env.SHADOW_S3_CONTROL_PLANE_CALLER_ARN }}",
            "role-skip-session-tagging: true",
            "unset-current-credentials: true",
            'test "$GITHUB_REF" = refs/heads/main',
            '--backup-sentinel-key "$SHADOW_BACKUP_FORBIDDEN_SENTINEL_KEY"',
            '--snapshot-sentinel-key "$SHADOW_SNAPSHOT_FORBIDDEN_SENTINEL_KEY"',
            '--caller-trust-repository "$SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY"',
            (
                "--caller-trust-repository-owner-id "
                '"$SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY_OWNER_ID"'
            ),
            '--caller-trust-repository-id "$SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REPOSITORY_ID"',
            '--caller-trust-ref "$SHADOW_S3_CONTROL_PLANE_CALLER_TRUST_REF"',
            "docs/evidence/batch-24/production/aws-storage-policy-target.json",
            "Verify fresh live OIDC journey and persona RBAC",
        )
        for fragment in required:
            if fragment not in content:
                errors.append(
                    f"production-acceptance.yml: missing production binding {fragment}"
                )
        if "\n      SHADOW_KUBERNETES_CONTEXT:" in content:
            errors.append(
                "production-acceptance.yml: generic Kubernetes context is forbidden"
            )
        ordered = (
            "production-oidc.spec.ts",
            "production_gate.py oidc",
            "production_gate.py network_policy",
            "production_gate.py s3",
        )
        positions = [content.find(fragment) for fragment in ordered]
        if any(position < 0 for position in positions) or positions != sorted(
            positions
        ):
            errors.append(
                "production-acceptance.yml: OIDC/network/storage gate order is invalid"
            )
        aws_ordered = (
            "Resolve the partition-exact AWS STS audience",
            "aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708",
            "Collect exact live AWS storage policy digests read-only",
            "production_gate.py preflight",
        )
        aws_positions = [content.find(fragment) for fragment in aws_ordered]
        if any(position < 0 for position in aws_positions) or aws_positions != sorted(
            aws_positions
        ):
            errors.append(
                "production-acceptance.yml: GitHub OIDC caller exchange order is invalid"
            )
    return errors


def main() -> int:
    errors: list[str] = []
    inventories = (
        (TEMPLATE_DIRECTORY, set(WORKFLOWS)),
        (ROOT_WORKFLOW_DIRECTORY, set(WORKFLOWS.values())),
    )
    for directory, expected_names in inventories:
        if not directory.is_dir() or directory.is_symlink():
            errors.append(f"missing regular workflow directory: {directory}")
            continue
        observed_names = _workflow_inventory(directory)
        if observed_names != expected_names:
            missing = sorted(expected_names - observed_names)
            unexpected = sorted(observed_names - expected_names)
            errors.append(
                f"workflow inventory mismatch: {directory}; "
                f"missing={missing}; unexpected={unexpected}"
            )
    for template_name, root_name in WORKFLOWS.items():
        template_path = TEMPLATE_DIRECTORY / template_name
        if not template_path.is_file() or template_path.is_symlink():
            errors.append(f"missing regular package workflow: {template_path}")
            continue
        root_path = ROOT_WORKFLOW_DIRECTORY / root_name
        expected = render_root_workflow(template_name)
        if not root_path.is_file() or root_path.is_symlink():
            errors.append(f"missing regular root workflow: {root_path}")
            continue
        actual = root_path.read_text(encoding="utf-8")
        if actual != expected:
            diff = "\n".join(
                difflib.unified_diff(
                    actual.splitlines(),
                    expected.splitlines(),
                    fromfile=str(root_path),
                    tofile=f"rendered:{template_name}",
                    n=2,
                )
            )
            errors.append(f"root workflow drift: {root_name}\n{diff}")
        errors.extend(_validate_contract(root_name, actual))
    if errors:
        raise SystemExit("\n\n".join(errors))
    print(f"ROOT_WORKFLOW_SYNC_OK={len(WORKFLOWS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
