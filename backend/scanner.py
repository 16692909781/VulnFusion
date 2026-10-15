"""Conservative source candidate scanner used by the MVP.

It deliberately reports hypotheses with evidence instead of claiming verified
vulnerabilities. Semgrep/Tree-sitter/CodeQL adapters can replace this module.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .evidence import add_evidence
from .models import EvidenceCreate, Finding, FindingStatus, new_id
from .store import store


RULES = [
    ("sql_injection", "high", re.compile(r"(?:execute\s*\([^\n]*|query\s*=\s*)[^\n]*(?:f['\"]|%s|\+|\$\{)", re.I), "SQL query construction"),
    ("command_injection", "critical", re.compile(r"(?:os\.system|shell_exec|Runtime\.getRuntime\(\)\.exec|subprocess\.(?:run|Popen|call))\s*\(", re.I), "command execution sink"),
    ("ssrf", "high", re.compile(r"(?:requests\.(?:get|post)|urllib\.request\.urlopen|fetch)\s*\(", re.I), "server-side request sink"),
    ("dangerous_eval", "high", re.compile(r"\b(?:eval|exec)\s*\(", re.I), "dynamic code evaluation"),
    ("hardcoded_secret", "medium", re.compile(r"\b(?:password|secret|api[_-]?key|token)\s*=\s*['\"][^'\"]{8,}['\"]", re.I), "possible hardcoded secret"),
]

EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".php", ".java", ".go", ".rb", ".rs"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}


def iter_source_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in EXTENSIONS:
            yield path


def scan_project(project_id: str, root_path: str) -> list[Finding]:
    root = Path(root_path).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"project root does not exist or is not a directory: {root_path}")

    findings: list[Finding] = []
    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        relative = str(path.relative_to(root))
        for number, line in enumerate(lines, start=1):
            for vuln_type, severity, pattern, rule_name in RULES:
                if not pattern.search(line):
                    continue
                start = max(0, number - 2)
                snippet = "\n".join(lines[start:min(len(lines), number + 1)])[:1200]
                evidence = add_evidence(EvidenceCreate(
                    project_id=project_id,
                    kind="code",
                    title=f"{rule_name}: {relative}:{number}",
                    content=snippet,
                    source={"file_path": relative, "line_start": number, "rule": rule_name},
                    trust="observed",
                ))
                finding = Finding(
                    id=new_id("finding"),
                    project_id=project_id,
                    title=f"疑似 {vuln_type}: {relative}:{number}",
                    vulnerability_type=vuln_type,
                    severity=severity,
                    status=FindingStatus.NEEDS_HUMAN,
                    confidence=0.55,
                    description=f"规则 {rule_name} 发现潜在危险模式，需要结合输入来源和运行时行为确认。",
                    file_path=relative,
                    line_start=number,
                    code_snippet=snippet,
                    sink=rule_name,
                    evidence_ids=[evidence.id],
                    next_action="读取上下文并确认 source；必要时生成沙箱 Harness。",
                )
                store.add("findings", finding)
                findings.append(finding)
    return findings
