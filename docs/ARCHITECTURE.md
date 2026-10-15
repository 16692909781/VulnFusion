# VulnFusion architecture

## Primary entry: host Agent via MCP

`agent/mcp_server.py` loads the checkout's `.env` and starts the official Python
MCP SDK over stdio. It does not start HTTP or call a model provider. The host
Agent reads Skill methodology, plans each task with `vulnfusion_plan_task`,
records user approval and interprets the resulting evidence using its own model.
`vulnfusion_submit_analysis` binds that analysis and candidates to same-project
evidence, and reporting includes the analysis and human decisions.

MCP uses a deterministic Orchestrator only for command templates and execution;
it never invokes the standalone DeepSeek planner even if a key is configured.
Tool names are checked against the selected Skill. HTTP(S) targets are checked
against explicit host/URL scopes at planning and approval. No arbitrary shell
tool is exposed. Dependencies must complete before a task runs; a preview is
not a valid dependency for a real execution. Source uploads have a unique
project/task destination so repeated uploads do not retain stale scan input.

Agent mode defaults to `data/agent-store.json`. File locks and reload-before-write
support multiple MCP processes; compare-and-set task claiming prevents duplicate
remote execution. The host/client enforces actual human consent; the server's
approved_by and note fields are audit metadata, not authentication.

See `agent/README.md` for generated client configuration and the protocol smoke
test. The web API below remains optional and has its own planner/data file.

## Optional web application

`POST /api/projects/{id}/runs` checks the authorization marker, then invokes
DeepSeek or the deterministic fallback planner. The planner chooses entries
from `skills/**/SKILL.md` and creates one structured task per Skill. Tasks carry
the Skill instructions, target, allowlisted Kali tool, generated command
preview and dry-run policy. Network and scanner work is never run locally.

When Kali is not configured a task is `waiting_kali`. When it is configured a
tool task is `waiting_approval`. Approval with the default `dry_run=true` only
records a preview; a real SSH execution requires both `execute_remote=true`
and `dry_run=false`. stdout, stderr, exit code and preview metadata are stored
as Evidence. A bounded analyzer parses Semgrep/Gitleaks/Nuclei/SQLMap output
and optionally asks configured DeepSeek to triage it; each candidate is saved
as `needs_human` with the task Evidence ID.

The UI reads Findings and Tasks, then sends a human decision to
`POST /api/findings/{id}/decision`.

## Planned adapters

- `Planner`: OpenAI-compatible tool-calling model with bounded budgets.
- `CodeAuditAgent`: Semgrep/tree-sitter/dataflow/RAG.
- `RuntimeAgent`: HTTP, browser and Burp MCP behind scope and approval gates.
- `VerificationAgent`: Docker/gVisor harness execution and request replay.
- `KnowledgeStore`: pgvector/Chroma with organization-specific human labels.

## Safety invariants

1. Project creation requires `authorized=true`.
2. Runtime tasks are approval-gated and dry-run by default.
3. A finding is a hypothesis until verification or human confirmation.
4. Evidence records are content-hashed and findings reference their IDs.
5. Tool adapters must enforce target scope, rate limits and an audit log.
6. Reporting never upgrades a hypothesis; only evidence and human decisions do.

## Skill and execution boundary

Skills are prompt-based methodology, not permissions. DeepSeek may suggest a
Skill but the server validates its `skill_id` against the registry and maps it
to a fixed Agent type. `KaliExecutor` accepts only the tools in its allowlist
and constructs commands from structured arguments; raw model shell is never
accepted. The Windows controller only orchestrates, persists Evidence and
serves the UI. Kali is the sole scanner execution environment.

## API surface

- `GET /api/skills`、`GET /api/skills/{skill_id}`：Skill Registry 和完整指令；
- `GET /api/kali/status`：连接配置状态，不返回私钥；
- `POST /api/projects/{id}/runs`：生成结构化 AgentTask；
- `POST /api/tasks/{id}/decision`：批准或拒绝任务，批准后的输出进入 Evidence 和 Finding 候选；
- `GET/POST /api/projects/{id}/report`：预览或保存报告 Evidence。
