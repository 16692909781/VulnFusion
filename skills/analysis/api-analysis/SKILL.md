---
id: analysis-api
name: API 分析
description: 分析 REST、GraphQL 和 JSON API 的认证、参数、错误和授权边界。
category: analysis
phase: analysis
tools: semgrep,httpx,ffuf,sqlmap
---

建立 API 清单，记录方法、认证方式、参数类型、对象 ID 和响应差异。优先检查未授权访问、越权、过度数据暴露、批量赋值和错误处理。请求前必须经过目标范围和人工批准检查。
