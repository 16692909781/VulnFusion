"""Evidence-backed Markdown report generation for the reporting Skill."""

from __future__ import annotations

from collections import Counter

from .evidence import add_evidence
from .models import EvidenceCreate, Project
from .store import store


def render_report(project: Project) -> str:
    findings = store.list("findings", project.id)
    tasks = store.list("tasks", project.id)
    evidence = store.list("evidence", project.id)
    status_counts = Counter(item.get("status", "unknown") for item in findings)
    lines = [
        f"# VulnFusion 安全评估报告：{project.name}",
        "",
        f"- 项目 ID：`{project.id}`",
        f"- 授权标记：`{str(project.authorized).lower()}`",
        f"- 目标范围：{', '.join(project.targets) if project.targets else '由运行请求提供，需人工确认'}",
        f"- Findings：{len(findings)}；Evidence：{len(evidence)}；Tasks：{len(tasks)}",
        f"- 状态统计：{dict(status_counts) or {'none': 0}}",
        "",
        "> 结论只来自任务输出、源码证据和人工决策。`needs_human` 仍是候选，不等于已确认漏洞。",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("当前没有可报告的漏洞候选。")
    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### {index}. {finding.get('title', '未命名候选')}",
            "",
            f"- 状态：`{finding.get('status', '')}`；严重性：`{finding.get('severity', '')}`；置信度：`{finding.get('confidence', '')}`",
            f"- 类型：`{finding.get('vulnerability_type', '')}`",
            f"- 位置：`{finding.get('file_path', '')}:{finding.get('line_start') or ''}`",
            f"- Evidence：{', '.join(f'`{item}`' for item in finding.get('evidence_ids', [])) or '无'}",
            f"- 描述：{finding.get('description', '')}",
            f"- 下一步：{finding.get('next_action', '')}",
            f"- 人工复核：{finding.get('analyst_note', '')}",
            "",
        ])
    analyses = [item for item in evidence if item.get("source", {}).get("producer") == "host-agent"]
    if analyses:
        lines.extend(["## Agent 分析", ""])
        for item in analyses:
            lines.extend([f"### 分析 `{item['id']}`", "", item["content"], "", f"引用证据：{', '.join(item['source'].get('evidence_ids', []))}", ""])
    lines.extend([
        "## Task 执行记录",
        "",
    ])
    for task in tasks:
        result = task.get("result") or {}
        lines.append(f"- `{task.get('status')}` {task.get('title')}；工具：`{task.get('remote_tool') or 'Agent'}`；Evidence：`{result.get('evidence_id', '')}`")
    return "\n".join(lines) + "\n"


def save_report(project: Project) -> dict:
    markdown = render_report(project)
    evidence = add_evidence(EvidenceCreate(
        project_id=project.id,
        kind="human",
        title=f"安全报告：{project.name}",
        content=markdown,
        source={"skill_id": "reporting-security", "format": "markdown"},
        trust="derived",
    ))
    return {"project_id": project.id, "markdown": markdown, "evidence_id": evidence.id}
