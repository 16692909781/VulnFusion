"""Agent orchestration for the first vertical slice.

The interfaces are intentionally small. A future LLM planner can implement
Planner.plan() while the evidence, approval and persistence contracts remain
stable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .analysis import analyze_tool_output, persist_findings
from .kali import KaliConfigurationError, KaliExecutor
from .evidence import add_evidence
from .llm import DeepSeekProvider, LLMProviderError
from .models import AgentTask, EvidenceCreate, Project, RunRequest, now_iso, new_id
from .reporting import save_report
from .skill_registry import Skill, skill_registry
from .store import store


@dataclass
class Plan:
    steps: list[dict[str, Any]]
    source: str = "deterministic"


class Planner:
    """Offline plan covering the complete Web audit skill taxonomy."""

    def plan(self, project: Project, request: RunRequest) -> Plan:
        steps: list[dict[str, Any]] = []
        if request.mode in {"runtime_plan", "full"}:
            steps.extend([
                {"agent": "recon", "skill_id": "recon-technology-identification", "reason": "识别 Web 技术栈和运行时"},
                {"agent": "recon", "skill_id": "recon-directory-discovery", "reason": "发现授权范围内的目录和入口"},
            ])
        if request.mode in {"code_audit", "full"}:
            steps.extend([
                {"agent": "analysis", "skill_id": "analysis-javascript", "reason": "提取前端脚本中的 API 和危险 Sink"},
                {"agent": "analysis", "skill_id": "analysis-api", "reason": "分析 API 认证、参数和授权边界"},
                {"agent": "analysis", "skill_id": "vulnerabilities-injection-triage", "reason": "排查注入类漏洞候选"},
                {"agent": "analysis", "skill_id": "vulnerabilities-web-triage", "reason": "排查常见 Web 漏洞和配置问题"},
            ])
        if request.mode == "full":
            steps.extend([
                {"agent": "verification", "skill_id": "verification-evidence", "reason": "按证据设计低风险验证"},
                {"agent": "reporting", "skill_id": "reporting-security", "reason": "汇总证据链并生成报告"},
            ])
        if not steps:
            steps = [{"agent": "analysis", "skill_id": "analysis-api", "reason": "基础 API 分析"}]
        return Plan(steps)


class DeepSeekPlanner(Planner):
    """Use DeepSeek to propose a bounded plan, then validate its shape."""

    ALLOWED_AGENTS = {"recon", "analysis", "verification", "reporting"}

    def __init__(self, provider: DeepSeekProvider | None = None) -> None:
        self.provider = provider or DeepSeekProvider()
        self.last_error = ""
        self.last_used = False

    def plan(self, project: Project, request: RunRequest) -> Plan:
        fallback = super().plan(project, request)
        self.last_error = ""
        self.last_used = False
        available = [skill.to_dict() for skill in skill_registry.list()]
        prompt = (
            "你是 VulnFusion 的安全审计编排器。只生成 JSON 计划，不执行命令。\n"
            "只能从给定 skill 列表选择 skill_id；扫描和验证必须交给 Kali 且等待人工批准。\n"
            '输出格式：{"steps":[{"agent":"recon|analysis|verification|reporting","skill_id":"...","reason":"..."}]}\n\n'
            f"项目: {project.name}\n源码路径: {project.root_path}\n模式: {request.mode}\n"
            f"目标: {request.target or '未指定'}\n可用 Skill: {json.dumps(available, ensure_ascii=False)}"
        )
        try:
            result = self.provider.chat([
                {"role": "system", "content": "你是严格的 JSON 规划器。"},
                {"role": "user", "content": prompt},
            ])
            raw = result.content.strip()
            fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
            parsed = json.loads(fenced.group(1) if fenced else raw)
            steps = parsed.get("steps", []) if isinstance(parsed, dict) else []
            validated = []
            for item in steps:
                if not isinstance(item, dict):
                    continue
                if item.get("agent") not in self.ALLOWED_AGENTS:
                    continue
                skill_id = str(item.get("skill_id", ""))
                if not skill_registry.get(skill_id):
                    continue
                validated.append({
                    "agent": item["agent"],
                    "skill_id": skill_id,
                    "reason": str(item.get("reason", ""))[:240],
                })
            if validated:
                self.last_used = True
                return Plan(validated[:12], source="deepseek")
            raise LLMProviderError("DeepSeek returned no valid agent steps")
        except Exception as exc:
            self.last_error = str(exc)
            return fallback


def build_planner() -> Planner:
    """Prefer DeepSeek when configured, otherwise keep the offline fallback."""
    provider = DeepSeekProvider()
    return DeepSeekPlanner(provider) if provider.configured else Planner()


def _kind(agent: str) -> str:
    return {
        "recon": "recon",
        "analysis": "analysis",
        "verification": "verification",
        "reporting": "reporting",
    }.get(agent, "analysis")


def _tool_for_skill(skill: Skill, request: RunRequest) -> str:
    if request.mode == "code_audit":
        for preferred in ("semgrep", "gitleaks"):
            if preferred in skill.tools:
                return preferred
    return skill.tools[0] if skill.tools else ""


def _target_in_scope(target: str, allowed_targets: list[str]) -> bool:
    """Compare URL host/port boundaries instead of accepting string prefixes."""
    if not allowed_targets:
        return True
    candidate = urlsplit(target.strip())
    if not candidate.hostname:
        return False
    for allowed in allowed_targets:
        parsed = urlsplit(allowed.strip() if "://" in allowed else f"https://{allowed.strip()}")
        if parsed.hostname != candidate.hostname:
            continue
        if parsed.port and parsed.port != candidate.port:
            continue
        return True
    return False


def _args_for_tool(tool: str, request: RunRequest, remote_path: str) -> list[str]:
    target = request.target.strip()
    if tool == "nmap":
        parsed = urlsplit(target)
        if parsed.hostname:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return ["-sV", "-p", str(port), parsed.hostname]
        return ["-sV", "--top-ports", "100", target or "TARGET_REQUIRED"]
    if tool == "httpx":
        return ["-u", target or "TARGET_REQUIRED", "-title", "-tech-detect", "-status-code"]
    if tool == "whatweb":
        return [target or "TARGET_REQUIRED"]
    if tool == "ffuf":
        return ["-u", f"{target.rstrip('/')}/FUZZ" if target else "TARGET_REQUIRED/FUZZ", "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt", "-rate", "25"]
    if tool == "subfinder":
        parsed = urlsplit(target)
        return ["-d", parsed.hostname if parsed.hostname else (target or "TARGET_REQUIRED"), "-silent"]
    if tool == "nikto":
        return ["-h", target or "TARGET_REQUIRED"]
    if tool == "nuclei":
        return ["-u", target or "TARGET_REQUIRED", "-severity", "medium,high,critical", "-rate-limit", "10"]
    if tool == "sqlmap":
        return ["-u", target or "TARGET_REQUIRED", "--batch", "--level=1", "--risk=1"]
    if tool == "semgrep":
        return ["--config", "auto", "--json", remote_path]
    if tool == "gitleaks":
        return ["dir", remote_path, "--no-banner", "--redact", "--exit-code", "0", "--report-format", "json", "--report-path", "/dev/stdout"]
    return []


class Orchestrator:
    def __init__(self, planner: Planner | None = None, kali: KaliExecutor | None = None) -> None:
        self.planner = planner or Planner()
        self.kali = kali or KaliExecutor()

    def _task_for(self, project: Project, request: RunRequest, step: dict[str, Any]) -> AgentTask:
        skill = skill_registry.get(step.get("skill_id", ""))
        if skill is None:
            raise ValueError(f"unknown skill: {step.get('skill_id')}")
        tool = step.get("tool", _tool_for_skill(skill, request))
        if tool and tool not in skill.tools:
            raise ValueError(f"tool {tool} is not provided by skill {skill.id}")
        task_id = new_id("task")
        remote_path = f"{self.kali.config.remote_root.rstrip('/')}/{project.id}/{task_id}"
        args = _args_for_tool(tool, request, remote_path)
        command = self.kali.plan(tool, args) if tool else ""
        requires_approval = bool(tool)
        if not tool:
            status = "queued"
        elif not self.kali.configured:
            status = "waiting_kali"
        else:
            status = "waiting_approval"
        task_suffix = "（Kali 远程任务）" if tool else "（Agent 任务）"
        return AgentTask(
            id=task_id,
            project_id=project.id,
            kind=_kind(step["agent"]),
            title=f"{skill.name}{task_suffix}",
            status=status,
            skill_id=skill.id,
            stage=skill.category if skill.category in {"recon", "analysis", "verification", "reporting"} else "analysis",
            available_tools=list(skill.tools),
            remote_tool=tool,
            remote_command=command,
            requires_approval=requires_approval,
            payload={
                "skill": skill.to_dict(),
                "skill_instructions": skill.instructions,
                "tool": tool,
                "args": args,
                "target": request.target,
                "remote_path": remote_path,
                "dry_run": request.dry_run,
                "execute_remote": request.execute_remote,
                "policy": "scanner commands execute on Kali only",
            },
        )

    def run(self, project: Project, request: RunRequest) -> dict[str, Any]:
        if not project.authorized:
            raise ValueError("project is not authorized for security testing")
        if request.mode != "code_audit" and request.execute_remote and not request.dry_run and not request.target.strip():
            raise ValueError("target is required before enabling remote execution")
        if request.target.strip() and not _target_in_scope(request.target, project.targets):
            raise ValueError("target is outside the project's authorized targets")
        plan = self.planner.plan(project, request)
        created: list[AgentTask] = []
        for step in plan.steps:
            if request.skill_ids and step.get("skill_id") not in request.skill_ids:
                continue
            created.append(store.add("tasks", self._task_for(project, request, step)))
        return {
            "plan": plan.steps,
            "plan_source": plan.source,
            "skills": [skill_registry.get(x.get("skill_id", "")).to_dict() for x in plan.steps if skill_registry.get(x.get("skill_id", ""))],
            "findings": [],
            "tasks": [x.model_dump(mode="json") for x in created],
            "kali": self.kali.status(),
            "message": "扫描命令只会在 Kali 执行；当前任务需要逐个批准。",
        }

    def decide_task(self, task_id: str, decision: str, note: str = "", approved_by: str = "") -> dict[str, Any]:
        raw = store.get("tasks", task_id)
        if not raw:
            raise ValueError("task not found")
        if decision == "reject":
            if raw.get("status") in {"running", "completed", "failed", "rejected"}:
                raise ValueError(f"task is already terminal: {raw.get('status')}")
            return store.update("tasks", task_id, {"status": "rejected", "result": {"note": note}, "updated_at": now_iso()}, expected_status=raw["status"]) or raw
        if decision != "approve":
            raise ValueError("decision must be approve or reject")
        tool = raw.get("remote_tool", "")
        args = raw.get("payload", {}).get("args", [])
        payload = raw.get("payload", {})
        for dependency_id in raw.get("depends_on", []):
            dependency = store.get("tasks", dependency_id)
            if not dependency or dependency.get("project_id") != raw["project_id"] or dependency.get("status") != "completed":
                raise ValueError(f"dependency is not complete: {dependency_id}")
            if not payload.get("dry_run", True) and dependency.get("result", {}).get("planned"):
                raise ValueError(f"dependency is only a preview: {dependency_id}")
        if not tool:
            if raw.get("status") != "queued":
                raise ValueError(f"task is not queued: {raw.get('status')}")
            report = save_report(Project.model_validate(store.get("projects", raw["project_id"]))) if raw.get("skill_id") == "reporting-security" else {}
            return store.update("tasks", task_id, {
                "status": "completed",
                "result": {"planned": not bool(report), **report, "human_note": note, "approved_by": approved_by},
                "updated_at": now_iso(),
            }) or raw
        if raw.get("status") != "waiting_approval":
            raise ValueError(f"task is not awaiting approval: {raw.get('status')}")
        store.update("tasks", task_id, {"status": "running", "updated_at": now_iso()}, expected_status="waiting_approval")
        if payload.get("dry_run", True) or not payload.get("execute_remote", False):
            preview = {
                "ok": True,
                "planned": True,
                "command": raw.get("remote_command", ""),
                "message": "dry_run 或 execute_remote=false，已记录批准但未向目标发包",
                "human_note": note,
                "approved_by": approved_by,
            }
            evidence = add_evidence(EvidenceCreate(
                project_id=raw["project_id"],
                kind="tool",
                title=f"Kali 任务预览: {raw.get('title', task_id)}",
                content=json.dumps(preview, ensure_ascii=False, indent=2),
                source={"task_id": task_id, "tool": tool, "planned_only": True},
                trust="observed",
            ))
            preview["evidence_id"] = evidence.id
            return store.update("tasks", task_id, {"status": "completed", "result": preview, "updated_at": now_iso()}) or raw
        try:
            if raw.get("kind") in {"analysis", "verification"} and tool in {"semgrep", "gitleaks"}:
                project = store.get("projects", raw["project_id"])
                if project:
                    self.kali.upload_project(project["root_path"], f"{raw['project_id']}/{task_id}", approved=True)
            result = self.kali.execute(tool, args, approved=True)
            result_data = result.to_dict()
            evidence = add_evidence(EvidenceCreate(
                project_id=raw["project_id"],
                kind="tool",
                title=f"Kali 输出: {raw.get('title', task_id)}",
                content=json.dumps(result_data, ensure_ascii=False, indent=2),
                source={"task_id": task_id, "tool": tool, "target": payload.get("target", "")},
                trust="observed",
            ))
            analysis = analyze_tool_output(tool, result_data.get("stdout", ""), result_data.get("stderr", ""), raw.get("payload", {}).get("skill_instructions", ""), self._analysis_provider())
            finding_ids = persist_findings(raw["project_id"], raw, evidence.id, analysis)
            result_data["analysis"] = {"candidates": len(analysis), "finding_ids": finding_ids}
            result_data["approved_by"] = approved_by
            return store.update("tasks", task_id, {
                "status": "completed" if result.ok else "failed",
                "result": {**result_data, "evidence_id": evidence.id, "human_note": note},
                "updated_at": now_iso(),
            }) or raw
        except (KaliConfigurationError, OSError) as exc:
            error = {"ok": False, "error": str(exc), "human_note": note, "approved_by": approved_by}
            evidence = add_evidence(EvidenceCreate(
                project_id=raw["project_id"],
                kind="tool",
                title=f"Kali 任务错误: {raw.get('title', task_id)}",
                content=json.dumps(error, ensure_ascii=False, indent=2),
                source={"task_id": task_id, "tool": tool},
                trust="observed",
            ))
            error["evidence_id"] = evidence.id
            return store.update("tasks", task_id, {"status": "failed", "result": error, "updated_at": now_iso()}) or raw

    def _analysis_provider(self):
        provider = getattr(self.planner, "provider", None)
        return provider if getattr(provider, "configured", False) else None
