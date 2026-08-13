from dataclasses import asdict
from typing import Any

from . import AssetModel


def model_response(model: AssetModel) -> dict[str, Any]:
    return {**asdict(model), "digest": model.digest}
