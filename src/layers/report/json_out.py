from __future__ import annotations

import json
from typing import Any

from layers.schemas import Diagnosis


def render_json(diagnosis: Diagnosis, indent: int = 2) -> str:
    """Serialise diagnosis into JSON string."""
    data: dict[str, Any] = diagnosis.model_dump(mode="json")
    return json.dumps(data, indent=indent)
