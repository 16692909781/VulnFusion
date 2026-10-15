---
id: recon-directory-discovery
name: 目录与资产发现
description: 发现授权 Web 目标的目录、文件、虚拟主机和公开入口。
category: recon
phase: recon
tools: ffuf,nmap,httpx
---

只对明确授权的域名或地址执行。优先使用小字典、低并发和明确的速率限制；发现登录、管理、上传、调试和 API 入口后停止无意义扩展。每个入口记录 URL、参数、状态码、长度、标题和 Evidence ID。
