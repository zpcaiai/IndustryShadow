from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Variant:
    name: str
    overrides: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class Experiment:
    experiment_id: str
    dataset_digest: str
    variants: tuple[Variant, ...]
    state: str = "REQUESTED"
