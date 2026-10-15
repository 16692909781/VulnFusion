"""Stable domain models shared by the API, agents and UI."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    root_path: str = ""
    targets: list[str] = Field(default_factory=list)
    authorized: bool = False


class Project(ProjectCreate):
    id: str = Field(default_factory=lambda: new_id("proj"))
    created_at: str = Field(default_factory=now_iso)


class EvidenceCreate(BaseModel):
    project_id: str
    kind: Literal["code", "http", "browser", "tool", "human", "sandbox"]
    title: str
    content: str
    source: dict[str, Any] = Field(default_factory=dict)
    trust: Literal["observed", "derived", "human"] = "observed"


class Evidence(EvidenceCreate):
    id: str = Field(default_factory=lambda: new_id("ev"))
    created_at: str = Field(default_factory=now_iso)
    sha256: str = ""


class FindingStatus(str, Enum):
    NEW = "new"
    NEEDS_HUMAN = "needs_human"
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("finding"))
    project_id: str
    title: str
    vulnerability_type: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    status: FindingStatus = FindingStatus.NEW
    confidence: float = Field(default=0.5, ge=0, le=1)
    description: str = ""
    file_path: str = ""
    line_start: int | None = None
    code_snippet: str = ""
    source: str = ""
    sink: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    next_action: str = ""
    poc: str = ""
    analyst_note: str = ""
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)


class HumanDecision(BaseModel):
    status: FindingStatus
    note: str = ""
    next_action: str = ""


class RunRequest(BaseModel):
    mode: Literal["code_audit", "runtime_plan", "full"] = "code_audit"
    dry_run: bool = True
    execute_remote: bool = False
    target: str = ""
    skill_ids: list[str] = Field(default_factory=list)


class TaskDecision(BaseModel):
    decision: Literal["approve", "reject"]
    note: str = ""
    approved_by: str = ""


class AgentTask(BaseModel):
    id: str = Field(default_factory=lambda: new_id("task"))
    project_id: str
    kind: Literal["code_audit", "recon", "analysis", "runtime_probe", "verification", "human_review", "reporting"]
    title: str
    status: Literal["queued", "running", "waiting_approval", "waiting_kali", "completed", "failed", "rejected"] = "queued"
    skill_id: str = ""
    stage: Literal["recon", "analysis", "verification", "reporting"] = "analysis"
    available_tools: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    remote_tool: str = ""
    remote_command: str = ""
    requires_approval: bool = True
    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)
