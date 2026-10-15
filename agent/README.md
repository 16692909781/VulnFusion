# 在现有 Agent 中使用 VulnFusion

当前 Agent 负责理解目标、读取 Skill、选择步骤和分析输出。VulnFusion 是
MCP 工具服务，负责保存项目、检查范围、排队、记录授权、执行 Kali 工具和保存证据。
这个模式不调用 DeepSeek 或任何其他模型 API，不需要单独的模型密钥或网页进程。

支持能启动本地 **MCP stdio** 服务的客户端。Claude Code、Cursor、Cline 等
客户端可使用 `mcpServers` 配置；Codex 使用 TOML。普通纯聊天窗口、仅支持远程
HTTP MCP 的云端 Agent，不能直接读取本机配置或连接 VMware NAT 中的 Kali。
本项目目前不提供远程 HTTP MCP 服务。

## 安装与接入

需要 Python 3.10+、OpenSSH 客户端，以及已经配置公钥登录的 Kali。
Kali 工具环境见 `deploy/kali/README.md`。在 Windows 项目根目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\agent\setup.ps1
```

macOS/Linux 控制端可使用：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r agent/requirements.txt
.venv/bin/python agent/configure.py --write
```

这会创建独立环境并生成两个含当前电脑绝对路径的配置片段：

- `agent/configs/mcp.json`：把 `vulnfusion` 条目合并到客户端的 `mcpServers`。
- `agent/configs/codex.toml`：把两个 `mcp_servers.vulnfusion` 段合并到 Codex 的配置。

不要覆盖客户端已有的其他服务配置，也不要直接复制其他电脑的绝对路径。
项目根目录 `.mcp.json` 是当前 Windows 机器的 Claude Code 项目配置示例；
移动项目或换电脑后，以重新生成的片段为准。

Codex 的配置位置是 `~/.codex/config.toml`，或受信任项目的 `.codex/config.toml`。
依据：[Codex 官方 MCP 文档](https://developers.openai.com/codex/mcp/)。
配置生成器不修改全局设置。接入后重新连接 MCP 或新建会话，使客户端重新发现工具。
较慢的源码扫描建议客户端工具超时设为 1200 秒；生成的 Codex 片段已包含该设置。

MCP 服务从项目根目录 `.env` 读取 `VULNFUSION_KALI_*`。客户端 env 优先于 `.env`。
SSH 私钥留在运行 MCP 服务的电脑上。Agent 模式默认把数据写入
`data/agent-store.json`，与可选网页模式的数据分开；也可以用 `VULNFUSION_DATA`
指定共享文件，多个新版 MCP 进程通过文件锁串行写入。

## 一句话开始

接入后在 Agent 中说：

> 使用 VulnFusion 检查 Kali，列出可用 Skills，再为我的授权靶场设计测试计划。先展示命令，等我批准后执行。

Skill 指令可直接通过 `vulnfusion_get_guide` 或 MCP prompt
`authorized_assessment` 读取。支持本地 Skills 的客户端还可把
`agent/vulnfusion-agent` 文件夹复制到自己的 Skill 目录；这一步可选，MCP 工具
本身已经提供完整指令入口。

## 实际调用流程

1. `vulnfusion_check_kali` 检查连接；`vulnfusion_list_skills` 和 `vulnfusion_get_skill` 获取方法论。
2. `vulnfusion_start_assessment` 创建授权范围；Web 项目不需要源码目录。
3. Agent 调用 `vulnfusion_plan_task` 自己指定 Skill、工具、目标和理由，不经过第二个模型。
4. 默认 `dry_run=true`，批准也只记录预览。真实执行需要新建 `dry_run=false` 的任务，
   复核命令后用 `vulnfusion_approve_task` 记录用户决定。已有明确授权可复用，不能虚构授权。
5. `vulnfusion_get_evidence` 读取结果；Agent 使用自身模型分析，通过 `vulnfusion_submit_analysis` 保存候选。
6. 用户复核后用 `vulnfusion_decide_finding` 保存结论，`vulnfusion_generate_report` 返回 Markdown。
   没有发现候选时仍可保存分析，不应将失败或未完成的扫描写成“没有漏洞”。

任务可通过 depends_on 指定同项目的前置任务。真实任务不会接受“只完成预览”的前置步骤。
源码扫描的目录会在批准后上传到 Kali 的独立任务目录，避免反复扫描旧文件。
审核记录中的 approved_by/note 由客户端提交；服务不能独立证明提交者是人类。
请使用客户端正常的工具审批能力，保留用户对测试范围和执行的控制。

目前执行参数由受控模板生成，不提供任意 shell。已提供的 8 个 Skill 是基础方法论，
覆盖深度取决于 Agent 的分析和工具适配；不代表已经实现所有 Web 漏洞的自动验证。

## 验证

```powershell
.\.venv\Scripts\python.exe .\agent\smoke_test.py --check-kali
```

测试使用官方 MCP 客户端启动真实子进程，从不同工作目录验证握手、工具列表、
中文 Skill、授权项目、命令预览和报告；数据在临时目录，不调用模型 API、不扫描目标。
`--check-kali` 额外通过 SSH 检查 Kali 环境。
