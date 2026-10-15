---
id: verification-evidence
name: 证据复核与验证
description: 复核源码、HTTP 响应和扫描器结果，设计低风险验证步骤。
category: verification
phase: verification
tools: semgrep,httpx,sqlmap,nuclei
---

验证必须绑定已有 Evidence。优先使用无副作用、可重复的请求和差异比较；高风险操作先进入人工审批。不能因为一次无回显就判定无漏洞，也不能把模型推测写成确认结论。
