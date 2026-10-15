# VulnFusion

VulnFusion 是一个“AI 编排 + Skill 方法论 + 人工审批 + Kali 执行”的 Web 漏洞挖掘工作台，吸收了 VulnClaw 的运行时探测能力和 DeepAudit 的源码审计、沙箱验证思路。

主要入口现在是 **现有 Agent + MCP**：使用你正在使用的 Agent 读取 Skills、规划步骤和分析证据，
VulnFusion 提供 Kali 执行、任务和报告工具。此模式不需要配置 DeepSeek，也不需要启动网页。
支持本地 MCP stdio 的客户端；详细配置见 [Agent 接入说明](agent/README.md)。

```powershell
powershell -ExecutionPolicy Bypass -File .\agent\setup.ps1
```

将生成的 `agent/configs/mcp.json` 或 `agent/configs/codex.toml` 中的 VulnFusion 条目
合并到 Agent 的 MCP 设置，再重新连接。执行 `vulnfusion_get_guide` 即可读取完整使用流程。
下面的网页和 DeepSeek 说明仅适用于可选的独立网页模式。

当前版本是一个可运行的 MVP：

- 统一项目、证据、漏洞候选和人工决策数据模型；
- 对 Python/JavaScript/TypeScript/ PHP 等源码执行轻量候选扫描；
- 将技术识别、目录探测、JS/API 分析、漏洞排查、验证和报告拆成可发现的 Skill；
- 将运行时探测和代码扫描拆成需要人工批准的 Kali 远程任务，默认 dry-run；
- 工具 stdout/stderr 经过受控分析后生成 Evidence 和 `needs_human` 漏洞候选；
- 支持 Evidence-backed Markdown 报告预览和导出；
- 每个发现都绑定源码证据、规则、置信度和下一步建议；
- 提供 FastAPI JSON API 和本地浏览器控制台。

## 启动

```powershell
cd C:\Users\Administrator\Desktop\VulnFusion
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }  # 然后填写 Kali 连接配置
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

打开 <http://127.0.0.1:8090>。`start.ps1` 会读取项目根目录的 `.env`；已配置的 `.env` 不要覆盖。

## 接入 DeepSeek Agent

DeepSeek 使用 OpenAI-compatible Chat Completions 接口，只负责从 Skill Registry 选择合法步骤和给出理由，不会直接获得任意工具执行权限。将密钥放入当前进程环境变量：

```powershell
$env:DEEPSEEK_API_KEY = "你的密钥"
$env:DEEPSEEK_MODEL = "deepseek-chat"
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

未配置密钥时，系统使用离线 deterministic planner；配置后，`/api/projects/{project_id}/runs` 会优先让 DeepSeek 生成步骤，非法或失败响应自动回退。可通过 `GET /api/providers` 查看状态，接口不会返回密钥。

## Kali 远程执行

如果 Kali 使用 VMware NAT，可先运行 deploy/kali/discover_vmware.ps1，根据 VMX 和 DHCP 租约发现当前 IP，再把输出写入 VulnFusion 进程环境。NAT 地址会随虚拟机启动变化，启动 Kali 后重新发现即可。

控制端不会运行 nmap、ffuf、nuclei、sqlmap 等扫描器，所有扫描命令只在 Kali 执行。先在 Kali 上运行 [deploy/kali/bootstrap.sh](deploy/kali/bootstrap.sh)，再配置 `.env.example` 中的 `VULNFUSION_KALI_*` 环境变量。没有 Kali 时任务会进入 `waiting_kali`，仍可查看 Skill 和命令预览。

只有目标已授权、人工批准，并且运行请求同时设置 `execute_remote=true`、`dry_run=false` 时才会通过 SSH 发包。stdout/stderr、退出码和预览结果都会写入 Evidence。详见 [deploy/kali/README.md](deploy/kali/README.md)。

可通过 `GET /api/skills`、`GET /api/kali/status` 查看 Skill 和执行环境，通过 `POST /api/tasks/{task_id}/decision` 批准或拒绝任务。工具完成后，结果会自动进入候选分析；报告可从 `GET /api/projects/{project_id}/report` 预览，或用 `POST` 写入报告 Evidence。

`GET /api/kali/status` 只表示配置状态。控制台的“检查连接和工具”按钮调用 `POST /api/kali/check`，实际验证 SSH、工作目录、工具和 SecLists 字典，不扫描目标。`connected=true` 表示 SSH 诊断成功；`ready=true` 还要求完整工具集、正确的 ProjectDiscovery HTTPX 和字典可用，不能代替实际扫描验证。Kali 软件包的 HTTPX 命令是 `httpx-toolkit`，默认使用它以避免误调用 Python HTTPX。

## 运行一次源码审计

```powershell
curl -X POST http://127.0.0.1:8090/api/projects `
  -H "Content-Type: application/json" `
  -d '{"name":"demo","root_path":"C:\\Users\\Administrator\\Desktop\\VulnFusion\\examples"}'

curl -X POST http://127.0.0.1:8090/api/projects/{project_id}/runs `
  -H "Content-Type: application/json" `
  -d '{"mode":"code_audit","dry_run":true}'
```

## 设计原则

1. **证据优先**：模型结论必须引用 Evidence，而不是只保留自然语言。
2. **人工闭环**：高风险探测先进入 approval task，由人批准、修改或拒绝。
3. **源码与运行时关联**：代码候选和 HTTP/浏览器证据共享同一个 finding。
4. **可替换 Agent**：MVP 中的启发式 planner/scanner 可以替换为 OpenAI-compatible LLM、Semgrep、Tree-sitter、浏览器 MCP 和 Docker verifier。
5. **默认保守**：运行时主动探测默认只生成计划，不自动发包。

详细架构见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
