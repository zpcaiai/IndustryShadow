from dataclasses import dataclass, replace

from shadow_sandbox.common import canonical_digest


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    gateway_id: str
    certificate_fingerprint: str
    generation: int = 1

    @property
    def digest(self) -> str:
        return canonical_digest(
            [self.gateway_id, self.certificate_fingerprint, self.generation]
        )

    def rotate(self, fingerprint: str):
        return replace(
            self, certificate_fingerprint=fingerprint, generation=self.generation + 1
        )
