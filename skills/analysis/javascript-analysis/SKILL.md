---
id: analysis-javascript
name: JavaScript 分析
description: 分析前端 JavaScript、Source Map、动态路由和隐藏 API。
category: analysis
phase: analysis
tools: semgrep,gitleaks,httpx,ffuf
---

从 HTML 和静态脚本提取接口、参数、GraphQL、WebSocket、Source Map、敏感配置和危险 DOM Sink。区分前端演示代码与服务端真实校验；不要因出现 `innerHTML`、`eval` 或 token 字样就直接报告漏洞。
