"""Small JSON-backed store for the MVP.

The interface is intentionally repository-like so PostgreSQL/object storage can
replace it later without changing Agent code.
"""

from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from filelock import FileLock
from pathlib import Path
from typing import Any, Iterable, TypeVar

from .models import AgentTask, Evidence, Finding, Project

T = TypeVar("T")


class Store:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path or os.getenv("VULNFUSION_DATA", "data/store.json"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._file_lock = FileLock(str(self.path) + ".lock", timeout=30)
        self._data: dict[str, list[dict[str, Any]]] = {
            "projects": [], "evidence": [], "findings": [], "tasks": []
        }
        with self._file_lock:
            self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                for key in self._data:
                    if isinstance(loaded.get(key), list):
                        self._data[key] = loaded[key]
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read store {self.path}; existing data was not overwritten") from exc

    def _save(self) -> None:
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)

    def add(self, collection: str, item: T) -> T:
        with self._lock, self._file_lock:
            self._load()
            self._data[collection].append(item.model_dump(mode="json"))
            self._save()
        return item

    def list(self, collection: str, project_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._file_lock:
            self._load()
            values = deepcopy(self._data[collection])
        if project_id:
            values = [x for x in values if x.get("project_id") == project_id]
        return values

    def get(self, collection: str, item_id: str) -> dict[str, Any] | None:
        with self._lock, self._file_lock:
            self._load()
            return deepcopy(next((x for x in self._data[collection] if x.get("id") == item_id), None))

    def update(self, collection: str, item_id: str, changes: dict[str, Any], *, expected_status: str | None = None) -> dict[str, Any] | None:
        with self._lock, self._file_lock:
            self._load()
            for item in self._data[collection]:
                if item.get("id") == item_id:
                    if expected_status is not None and item.get("status") != expected_status:
                        raise ValueError(f"status changed: {item.get('status')}")
                    item.update(changes)
                    self._save()
                    return deepcopy(item)
        return None

    def clear_project_findings(self, project_id: str) -> None:
        with self._lock, self._file_lock:
            self._load()
            self._data["findings"] = [x for x in self._data["findings"] if x.get("project_id") != project_id]
            self._save()


store = Store()
