from . import UNIT_CONVERSIONS


def convert(value: float, source_unit: str, target_unit: str) -> float:
    scale, offset = UNIT_CONVERSIONS[(source_unit, target_unit)]
    return value * scale + offset
