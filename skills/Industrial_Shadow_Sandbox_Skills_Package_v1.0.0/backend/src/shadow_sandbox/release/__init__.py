from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass

from shadow_sandbox.common.models import DomainError, canonical_digest, utc_now


@dataclass(frozen=True, slots=True)
class ServiceCatalogEntry:
    name: str
    owner: str
    dependencies: tuple[str, ...]
    sli: tuple[str, ...]
    slo: Mapping[str, float]
    alerts: tuple[str, ...]
    runbook: str
    version: str
    criticality: str


@dataclass(frozen=True, slots=True)
class ReleaseManifest:
    source_digest: str
    build_digest: str
    schema_digest: str
    migration_digest: str
    domain_pack_digest: str
    dataset_digest: str
    gate_digest: str
    configuration_digest: str
    sbom_digest: str
    supported_upgrade_from: tuple[str, ...]

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ClosureCertificate:
    certificate_id: str
    release_manifest_digest: str
    scope: tuple[str, ...]
    exclusions: tuple[str, ...]
    gate_passed: bool
    evidence_digests: tuple[str, ...]
    residual_risks: tuple[str, ...]
    rollback_target: str
    issued_at: str
    signer: str
    signature: str


class ClosureService:
    def issue(
        self,
        *,
        certificate_id: str,
        manifest: ReleaseManifest,
        gate_passed: bool,
        evidence_digests: Sequence[str],
        residual_risks: Sequence[str],
        rollback_target: str,
        signer: str,
        signing_key: bytes,
    ) -> ClosureCertificate:
        if not gate_passed:
            raise DomainError("RELEASE_GATE_FAILED", "closure cannot be issued for a failed Gate")
        if not evidence_digests or not rollback_target:
            raise DomainError(
                "CLOSURE_EVIDENCE_MISSING", "closure requires evidence and rollback target"
            )
        provisional = {
            "certificate_id": certificate_id,
            "release_manifest_digest": manifest.digest,
            "scope": ("S0 simulation", "S1 historical replay", "S2 real read-only Shadow"),
            "exclusions": ("real write", "real control", "regulatory certification"),
            "gate_passed": True,
            "evidence_digests": tuple(evidence_digests),
            "residual_risks": tuple(residual_risks),
            "rollback_target": rollback_target,
            "issued_at": utc_now(),
            "signer": signer,
            "signature": "",
        }
        import hashlib
        import hmac

        signature = hmac.new(
            signing_key, canonical_digest(provisional).encode(), hashlib.sha256
        ).hexdigest()
        return ClosureCertificate(**{**provisional, "signature": signature})

    def verify(self, certificate: ClosureCertificate, signing_key: bytes) -> bool:
        import hashlib
        import hmac

        data = asdict(certificate)
        signature = data.pop("signature")
        expected = hmac.new(
            signing_key, canonical_digest({**data, "signature": ""}).encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected)
