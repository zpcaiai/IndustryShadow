from shadow_sandbox.common import DomainError

from .entities import Variant


def validate_variants(variants: tuple[Variant, ...]) -> None:
    if len(variants) < 2 or len({item.name for item in variants}) != len(variants):
        raise DomainError("EXPERIMENT_INVALID", "two uniquely named variants are required")
