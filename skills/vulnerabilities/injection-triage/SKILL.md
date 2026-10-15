---
id: vulnerabilities-injection-triage
name: 注入漏洞排查
description: 排查 SQL、命令、模板、表达式和 NoSQL 注入候选。
category: vulnerabilities
phase: analysis
tools: sqlmap,httpx,semgrep
---

沿 source→transform→sink 追踪数据流。只有当输入可控、危险 Sink 可达、编码或参数化保护缺失，并且验证结果支持时，才提升置信度。SQLMap 等主动工具只允许对明确授权目标运行，默认使用低风险和人工审批模式。
