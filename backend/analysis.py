"""Turn remote tool output into bounded, reviewable vulnerability hypotheses."""

from __future__ import annotations

import json
import re
from typing import Any

from .models import Finding, FindingStatus
from .store import store


SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _severity(value: Any, default: str = "medium") -> str:
    value = str(value or "").lower()
    return value if value in SEVERITIES else default


def _confidence(value: Any, default: float = 0.5) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def _llm_json(text: str) -> list[dict[str, Any]]:
    match = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.S)
    raw = match.group(1) if match else text.strip()
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    if isinstance(parsed, dict):
        parsed = parsed.get("findings", parsed.get("candidates", []))
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


def _semgrep(stdout: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        return []
    candidates = []
    for item in data.get("results", []) if isinstance(data, dict) else []:
        extra = item.get("extra", {}) if isinstance(item, dict) else {}
        start = item.get("start", {}) if isinstance(item, dict) else {}
        candidates.append({
            "title": str(extra.get("message") or item.get("check_id") or "Semgrep 命中"),
            "vulnerability_type": str(item.get("check_id") or "code_security_issue"),
            "severity": _severity(extra.get("severity"), "medium"),
            "confidence": 0.62,
            "description": str(extra.get("message") or "Semgrep 规则命中，需要结合 source、sink 和上下文复核。"),
            "file_path": str(item.get("path") or ""),
            "line_start": start.get("line"),
            "next_action": "读取完整上下文并由人工确认输入可控性和防护措施。",
        })
    return candidates


def _gitleaks(stdout: str) -> list[dict[str, Any]]:
    candidates = []
    try:
        parsed = json.loads(stdout)
        items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        items = []
        for line in stdout.splitlines():
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for item in items:
        if not isinstance(item, dict):
            continue
        candidates.append({
            "title": f"疑似敏感信息泄露: {item.get('RuleID') or 'secret'}",
            "vulnerability_type": "secret_exposure",
            "severity": "high",
            "confidence": 0.75,
            "description": "Gitleaks 发现疑似凭据或密钥；应立即人工确认是否为真实、有效且仍在使用的秘密。",
            "file_path": str(item.get("File") or ""),
            "line_start": item.get("StartLine"),
            "next_action": "吊销或轮换凭据，并确认历史提交和部署环境是否已暴露。",
        })
    return candidates


def _network(tool: str, text: str) -> list[dict[str, Any]]:
    candidates = []
    if tool == "nuclei":
        for line in text.splitlines():
            match = re.search(r"\[(critical|high|medium|low|info)\].*?\s(https?://\S+)", line, re.I)
            if match:
                level, url = match.groups()
                candidates.append({
                    "title": f"Nuclei 模板命中: {url}",
                    "vulnerability_type": "web_template_match",
                    "severity": _severity(level),
                    "confidence": 0.48,
                    "description": "Nuclei 结果仅作为候选证据，必须复核模板、响应和版本，排除误报。",
                    "next_action": "使用低风险请求复核响应，并在确认影响后生成最小 PoC。",
                })
    if tool == "sqlmap" and re.search(r"is vulnerable|parameter .* is vulnerable", text, re.I):
        candidates.append({
            "title": "SQLMap 报告参数可能可注入",
            "vulnerability_type": "sql_injection",
            "severity": "high",
            "confidence": 0.7,
            "description": "SQLMap 观察到注入迹象；需要检查授权范围、请求参数和业务影响。",
            "next_action": "人工复核请求和数据库影响，避免继续扩大风险测试。",
        })
    return candidates


def analyze_tool_output(tool: str, stdout: str, stderr: str, instructions: str = "", provider: Any = None) -> list[dict[str, Any]]:
    """Prefer structured parser output, then optionally ask DeepSeek to triage it."""
    text = (stdout or "")[:100_000]
    candidates = _semgrep(text) if tool == "semgrep" else _gitleaks(text) if tool == "gitleaks" else _network(tool, text)
    if provider is not None and (text or stderr):
        prompt = (
            "你是漏洞复核 Agent。只输出 JSON 数组，不执行命令。\n"
            "把工具输出整理成需要人工复核的候选；没有足够证据时返回空数组。"
            '字段：title,vulnerability_type,severity,confidence,description,next_action,file_path,line_start。\n'
            f"Skill 指令：{instructions[:5000]}\n工具：{tool}\n输出：{text[-30000:]}\n错误：{(stderr or '')[-5000:]}"
        )
        try:
            result = provider.chat([
                {"role": "system", "content": "你是严格的安全证据分析器。"},
                {"role": "user", "content": prompt},
            ])
            llm_candidates = []
            for item in _llm_json(result.content)[:20]:
                llm_candidates.append({
                    "title": str(item.get("title") or "AI 候选")[:240],
                    "vulnerability_type": str(item.get("vulnerability_type") or "web_security_issue")[:100],
                    "severity": _severity(item.get("severity")),
                    "confidence": _confidence(item.get("confidence", 0.5)),
                    "description": str(item.get("description") or "需要人工复核。")[:2000],
                    "next_action": str(item.get("next_action") or "绑定证据并人工复核。")[:500],
                    "file_path": str(item.get("file_path") or "")[:500],
                    "line_start": item.get("line_start"),
                })
            if llm_candidates:
                candidates = llm_candidates
        except Exception:
            # Tool evidence remains useful even if the optional LLM is unavailable.
            pass
    return candidates[:20]


def persist_findings(project_id: str, task: dict[str, Any], evidence_id: str, candidates: list[dict[str, Any]]) -> list[str]:
    finding_ids: list[str] = []
    existing = store.list("findings", project_id)
    for candidate in candidates:
        title = str(candidate.get("title") or "未命名候选")
        file_path = str(candidate.get("file_path") or "")
        line_start = candidate.get("line_start")
        duplicate = next((item for item in existing if item.get("title") == title and item.get("file_path", "") == file_path and item.get("line_start") == line_start), None)
        if duplicate:
            ids = duplicate.get("evidence_ids", [])
            if evidence_id not in ids:
                store.update("findings", duplicate["id"], {"evidence_ids": [*ids, evidence_id]})
            finding_ids.append(duplicate["id"])
            continue
        finding = Finding(
            project_id=project_id,
            title=title,
            vulnerability_type=str(candidate.get("vulnerability_type") or "web_security_issue"),
            severity=_severity(candidate.get("severity")),
            status=FindingStatus.NEEDS_HUMAN,
            confidence=_confidence(candidate.get("confidence", 0.5)),
            description=str(candidate.get("description") or "需要人工复核。"),
            file_path=file_path,
            line_start=line_start if isinstance(line_start, int) else None,
            evidence_ids=[evidence_id],
            next_action=str(candidate.get("next_action") or "绑定证据并人工复核。"),
            source=f"task:{task.get('id', '')}",
        )
        store.add("findings", finding)
        existing.append(finding.model_dump(mode="json"))
        finding_ids.append(finding.id)
    return finding_ids
