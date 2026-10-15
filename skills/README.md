# VulnFusion Web Skill Pack

这些 Skill 是 Agent 的方法论和提示词上下文，不是扫描器本身。Agent 先从 Registry 选择 Skill，再把指令、阶段和工具映射写入 `AgentTask`。实际命令必须通过 `KaliExecutor` 白名单和人工审批后执行。

## 分类

- `recon/`：技术识别、目录与资产发现；
- `analysis/`：JavaScript、API、认证和业务逻辑分析；
- `vulnerabilities/`：注入、XSS、SSRF、文件、反序列化等漏洞排查；
- `verification/`：证据复核、差异验证和 PoC 设计；
- `reporting/`：证据链和报告生成。

Skill frontmatter 中的 `id`、`category`、`phase` 和 `tools` 用于路由；正文只描述分析方法、证据要求和风险边界。新增 Skill 后重启 API 即可被 Registry 发现，DeepSeek 返回的未知 `skill_id` 会被过滤。
