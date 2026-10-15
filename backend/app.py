"""VulnFusion HTTP API and local review console."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .agents import Orchestrator, build_planner
from .evidence import add_evidence, evidence_map
from .models import EvidenceCreate, Finding, FindingStatus, HumanDecision, Project, ProjectCreate, RunRequest, TaskDecision, now_iso
from .reporting import render_report, save_report
from .skill_registry import skill_registry
from .store import store

app = FastAPI(title="VulnFusion", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
planner = build_planner()
orchestrator = Orchestrator(planner=planner)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "vulnfusion", "planner": planner.__class__.__name__}


@app.get("/api/providers")
def provider_status() -> dict:
    """Expose capability status without ever returning an API key."""
    deepseek = getattr(planner, "provider", None)
    return {
        "active_planner": planner.__class__.__name__,
        "providers": {
            "deepseek": {
                "configured": bool(deepseek and deepseek.configured),
                "model": getattr(deepseek, "model", None),
                "base_url": getattr(deepseek, "base_url", None),
                "last_used": bool(getattr(planner, "last_used", False)),
                "last_error": getattr(planner, "last_error", ""),
            }
        },
    }


@app.get("/api/skills")
def list_skills() -> list[dict]:
    """List the prompt-based Web security skills available to the planner."""
    return [skill.to_dict() for skill in skill_registry.list()]


@app.get("/api/skills/{skill_id}")
def get_skill(skill_id: str) -> dict:
    skill = skill_registry.get(skill_id)
    if not skill:
        raise HTTPException(status_code=404, detail="skill not found")
    return {**skill.to_dict(), "instructions": skill.instructions}


@app.get("/api/kali/status")
def kali_status() -> dict:
    """Expose connection and policy state without returning private key material."""
    return orchestrator.kali.status()


@app.post("/api/kali/check")
def check_kali() -> dict:
    """Check SSH authentication, tool availability and the remote workspace."""
    return orchestrator.kali.probe()


@app.get("/api/projects")
def list_projects() -> list[dict]:
    return store.list("projects")


@app.post("/api/projects", response_model=Project)
def create_project(payload: ProjectCreate) -> Project:
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="项目必须明确标记为 authorized=true")
    project = Project(**payload.model_dump())
    return store.add("projects", project)


def get_project(project_id: str) -> Project:
    raw = store.get("projects", project_id)
    if not raw:
        raise HTTPException(status_code=404, detail="project not found")
    return Project.model_validate(raw)


@app.post("/api/projects/{project_id}/runs")
def run_project(project_id: str, request: RunRequest) -> dict:
    project = get_project(project_id)
    try:
        return orchestrator.run(project, request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/projects/{project_id}/findings")
def list_findings(project_id: str) -> list[dict]:
    get_project(project_id)
    return store.list("findings", project_id)


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    finding = store.get("findings", finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@app.post("/api/findings/{finding_id}/decision")
def decide_finding(finding_id: str, decision: HumanDecision) -> dict:
    finding = store.get("findings", finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    updated = store.update("findings", finding_id, {
        "status": decision.status.value,
        "analyst_note": decision.note,
        "next_action": decision.next_action or finding.get("next_action", ""),
        "updated_at": now_iso(),
    })
    return updated or finding


@app.get("/api/projects/{project_id}/evidence")
def list_evidence(project_id: str) -> dict:
    get_project(project_id)
    return evidence_map(project_id)


@app.post("/api/evidence", response_model=None)
def create_evidence(payload: EvidenceCreate) -> dict:
    get_project(payload.project_id)
    return add_evidence(payload).model_dump(mode="json")


@app.get("/api/projects/{project_id}/tasks")
def list_tasks(project_id: str) -> list[dict]:
    get_project(project_id)
    return store.list("tasks", project_id)


@app.post("/api/tasks/{task_id}/decision")
def decide_task(task_id: str, decision: TaskDecision) -> dict:
    try:
        return orchestrator.decide_task(task_id, decision.decision, decision.note, decision.approved_by)
    except ValueError as exc:
        message = str(exc)
        status = 404 if message == "task not found" else 400
        raise HTTPException(status_code=status, detail=message) from exc


@app.get("/api/projects/{project_id}/report")
def project_report(project_id: str) -> dict:
    project = get_project(project_id)
    return {"project_id": project.id, "markdown": render_report(project)}


@app.post("/api/projects/{project_id}/report")
def create_project_report(project_id: str) -> dict:
    return save_report(get_project(project_id))


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent.parent / "frontend" / "static" / "index_v2.html")
