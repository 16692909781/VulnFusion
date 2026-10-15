"""Evidence graph helpers.

Every automated conclusion should point back to one or more immutable evidence
records. The graph is represented as IDs in the MVP and can later move to a
graph database without changing the public model.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .models import Evidence, EvidenceCreate
from .store import store


def add_evidence(payload: EvidenceCreate) -> Evidence:
    item = Evidence(**payload.model_dump())
    item.sha256 = hashlib.sha256(item.content.encode("utf-8", errors="replace")).hexdigest()
    return store.add("evidence", item)


def evidence_map(project_id: str) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for evidence in store.list("evidence", project_id):
        result.setdefault(evidence["kind"], []).append(evidence)
    return result
