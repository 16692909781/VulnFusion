"""Exercise real MCP stdio with the official client; never scan a target."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check(check_kali: bool) -> dict:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="vulnfusion-mcp-") as directory:
        env = {**os.environ, "VULNFUSION_DATA": str(Path(directory) / "store.json"), "PYTHONUTF8": "1",
               "DEEPSEEK_API_KEY": "unused-test-value", "DEEPSEEK_BASE_URL": "http://127.0.0.1:1"}
        server = StdioServerParameters(command=sys.executable, args=["-u", str(root / "agent" / "mcp_server.py")], env=env, cwd=directory)
        async with stdio_client(server) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=60)) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()

                async def call(name: str, arguments: dict | None = None) -> dict:
                    result = await session.call_tool(name, arguments or {})
                    if result.isError:
                        raise AssertionError(f"{name}: {result.content}")
                    assert isinstance(result.structuredContent, dict), result
                    return result.structuredContent

                guide = await call("vulnfusion_get_guide")
                assert guide["planner"] == "host-agent"
                skills = (await call("vulnfusion_list_skills"))["skills"]
                skill = await call("vulnfusion_get_skill", {"skill_id": "recon-technology-identification"})
                assert "授权" in skill["instructions"]
                await session.read_resource("vulnfusion://skills/recon-technology-identification")
                await session.get_prompt("authorized_assessment")
                invalid = await session.call_tool("vulnfusion_start_assessment", {"name": "no permission", "authorized": False})
                assert invalid.isError
                project = (await call("vulnfusion_start_assessment", {"name": "中文 MCP 测试", "authorized": True, "targets": ["https://example.invalid"]}))["project"]
                task = (await call("vulnfusion_plan_task", {"project_id": project["id"], "skill_id": skill["id"], "tool": "httpx", "target": "https://example.invalid", "reason": "preview only"}))["task"]
                assert task["payload"]["planner"] == "host-agent"
                assert "httpx-toolkit" in task["remote_command"]
                # Preview completion must never invoke a scanner or produce scan findings.
                preview = await call("vulnfusion_approve_task", {"task_id": task["id"], "decision": "approve", "approved_by": "test-harness", "note": "preview only; no scanning"})
                assert preview["result"]["planned"]
                refused = await session.call_tool("vulnfusion_submit_analysis", {"project_id": project["id"], "summary": "cannot infer a scan result", "evidence_ids": [preview["result"]["evidence_id"]]})
                assert refused.isError
                report = await call("vulnfusion_generate_report", {"project_id": project["id"], "save": True})
                assert "中文 MCP 测试" in report["markdown"]
                result = {"server": initialized.serverInfo.name, "tools": len(tools.tools), "skills": len(skills), "workflow": "preview/report passed", "separate_llm": False}
                if check_kali:
                    kali = await call("vulnfusion_check_kali")
                    assert kali["connected"] and kali["ready"], kali
                    result["kali"] = {"connected": kali["connected"], "ready": kali["ready"]}
                return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-kali", action="store_true")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(check(args.check_kali)), ensure_ascii=True, indent=2))
