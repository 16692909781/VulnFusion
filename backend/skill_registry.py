"""Discover and route VulnFusion's prompt-based security skills."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Skill:
    id: str
    name: str
    description: str
    category: str
    path: str
    instructions: str
    tools: tuple[str, ...] = ()
    phase: str = "analysis"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "path": self.path,
            "tools": list(self.tools),
            "phase": self.phase,
        }


_FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.S)


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    match = _FRONTMATTER.match(text)
    if not match:
        return {}, text
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values, match.group(2).strip()


class SkillRegistry:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or Path(__file__).parent.parent / "skills")
        self._skills: dict[str, Skill] = {}
        self.reload()

    def reload(self) -> None:
        self._skills = {}
        if not self.root.exists():
            return
        for path in sorted(self.root.glob("**/SKILL.md")):
            meta, body = _frontmatter(path.read_text(encoding="utf-8", errors="replace"))
            skill_id = meta.get("id") or meta.get("name") or path.parent.name
            tools = tuple(x.strip() for x in meta.get("tools", "").split(",") if x.strip())
            self._skills[skill_id] = Skill(
                id=skill_id,
                name=meta.get("name", skill_id),
                description=meta.get("description", ""),
                category=meta.get("category", path.parent.parent.name),
                path=str(path),
                instructions=body,
                tools=tools,
                phase=meta.get("phase", "analysis"),
            )

    def list(self) -> list[Skill]:
        return list(self._skills.values())

    def get(self, skill_id: str) -> Skill | None:
        return self._skills.get(skill_id)

    def select(self, requested: list[str] | None = None, *, phase: str = "") -> list[Skill]:
        if requested:
            return [self._skills[item] for item in requested if item in self._skills]
        if phase:
            selected = [x for x in self._skills.values() if x.phase == phase]
            if selected:
                return selected
        return self.list()

    def prompt_context(self, skill_ids: list[str]) -> str:
        selected = self.select(skill_ids)
        return "\n\n".join(f"# Skill: {skill.name}\n{skill.instructions}" for skill in selected)


skill_registry = SkillRegistry()
