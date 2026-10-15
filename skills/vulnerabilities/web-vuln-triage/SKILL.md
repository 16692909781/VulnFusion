---
id: vulnerabilities-web-triage
name: Web 漏洞综合排查
description: 按攻击面排查 XSS、SSRF、文件、反序列化、配置和认证漏洞。
category: vulnerabilities
phase: analysis
tools: semgrep,nuclei,httpx
---

将每个候选表示为可验证假设：入口、用户控制数据、危险操作、影响和验证条件。nuclei 结果只能作为候选证据；必须检查版本、路径、响应或源码上下文，排除模板误报。
