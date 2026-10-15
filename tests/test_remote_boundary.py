import unittest
from unittest.mock import patch

from backend.agents import Orchestrator, Planner
from backend.kali import KaliConfig, KaliExecutor, RemoteResult
from backend.models import Project, RunRequest
from backend.skill_registry import skill_registry


class RemoteBoundaryTest(unittest.TestCase):
    def test_registry_discovers_all_skill_categories(self):
        ids = {skill.id for skill in skill_registry.list()}
        self.assertTrue({"recon-technology-identification", "analysis-api", "verification-evidence", "reporting-security"} <= ids)

    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(ValueError):
            KaliExecutor(KaliConfig(host="kali.example")).plan("arbitrary-shell", ["id"])

    def test_unconfigured_kali_waits_for_kali(self):
        executor = KaliExecutor(KaliConfig(host=""))
        result = Orchestrator(planner=Planner(), kali=executor).run(
            Project(name="authorized", root_path=".", authorized=True),
            RunRequest(mode="runtime_plan", target="https://authorized.example"),
        )
        self.assertTrue(result["tasks"])
        self.assertTrue(all(task["status"] == "waiting_kali" for task in result["tasks"]))

    def test_approval_gate_does_not_execute_dry_run(self):
        executor = KaliExecutor(KaliConfig(host="kali.example"))
        orchestrator = Orchestrator(planner=Planner(), kali=executor)
        result = orchestrator.run(
            Project(name="authorized", root_path=".", authorized=True),
            RunRequest(mode="runtime_plan", target="https://authorized.example", dry_run=True, execute_remote=True),
        )
        task_id = result["tasks"][0]["id"]
        task = orchestrator.decide_task(task_id, "approve", "测试预览")
        self.assertEqual(task["status"], "completed")
        self.assertTrue(task["result"]["planned"])
        self.assertIn("evidence_id", task["result"])

    def test_remote_execution_requires_target(self):
        orchestrator = Orchestrator(planner=Planner(), kali=KaliExecutor(KaliConfig(host="kali.example")))
        with self.assertRaises(ValueError):
            orchestrator.run(
                Project(name="authorized", root_path=".", authorized=True),
                RunRequest(mode="runtime_plan", dry_run=False, execute_remote=True),
            )

    def test_code_audit_uses_structured_remote_code_tools(self):
        orchestrator = Orchestrator(planner=Planner(), kali=KaliExecutor(KaliConfig(host="kali.example")))
        result = orchestrator.run(
            Project(name="authorized", root_path=".", authorized=True),
            RunRequest(mode="code_audit", dry_run=True),
        )
        self.assertTrue(result["tasks"])
        self.assertTrue(all(task["remote_tool"] == "semgrep" for task in result["tasks"] if task["remote_tool"]))
        self.assertTrue(all("--json" in task["payload"]["args"] for task in result["tasks"] if task["remote_tool"] == "semgrep"))

    def test_target_must_match_project_scope(self):
        orchestrator = Orchestrator(planner=Planner(), kali=KaliExecutor(KaliConfig(host="kali.example")))
        with self.assertRaises(ValueError):
            orchestrator.run(
                Project(name="scoped", root_path=".", targets=["https://authorized.example"], authorized=True),
                RunRequest(mode="runtime_plan", target="https://outside.example", dry_run=True),
            )

    def test_remote_result_becomes_evidence_backed_finding(self):
        executor = KaliExecutor(KaliConfig(host="kali.example"))
        orchestrator = Orchestrator(planner=Planner(), kali=executor)
        project = Project(name="authorized", root_path=".", authorized=True)
        result = orchestrator.run(
            project,
            RunRequest(mode="full", target="https://authorized.example/item?id=1", dry_run=False, execute_remote=True),
        )
        task_id = next(task["id"] for task in result["tasks"] if task["remote_tool"] == "sqlmap")
        with patch.object(executor, "execute", return_value=RemoteResult(True, "sqlmap ...", "parameter id is vulnerable", "", 0)):
            task = orchestrator.decide_task(task_id, "approve", "已批准低风险验证", "tester")
        self.assertEqual(task["status"], "completed")
        self.assertEqual(task["result"]["analysis"]["candidates"], 1)
        self.assertTrue(task["result"]["analysis"]["finding_ids"])


if __name__ == "__main__":
    unittest.main()
