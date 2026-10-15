---
id: recon-technology-identification
name: 技术栈识别
description: 识别 Web 服务、框架、组件和运行时版本，为后续 Skill 选择提供依据。
category: recon
phase: recon
tools: httpx,whatweb,nmap
---

先确认目标在授权范围内，再做低侵入的被动或轻量探测。记录响应头、状态码、证书、页面特征、框架标记和开放服务。不要把版本识别直接当成漏洞；将原始输出保存为 Evidence，并提出下一步需要验证的假设。
