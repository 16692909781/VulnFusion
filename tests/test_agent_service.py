import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from agent import service
from backend.agents import Orchestrator, Planner
from backend.analysis import analyze_tool_output
from backend.evidence import add_evidence
from backend.kali import KaliConfig, KaliExecutor, RemoteResult
from backend.models import EvidenceCreate, Project
from backend.store import Store


class AgentServiceTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.store = Store(str(Path(self.directory) / "store.json"))
        for module in ("agent.service", "backend.agents", "backend.evidence", "backend.analysis", "backend.reporting"):
            self.stack.enter_context(patch(module + ".store", self.store))
        self.executor = KaliExecutor(KaliConfig(host="kali.example"))
        self.stack.enter_context(patch.object(service, "orchestrator", Orchestrator(Planner(), self.executor)))
        self.project = service.vulnfusion_start_assessment("test", True, ["https://lab.test/app"], self.directory)["project"]

    def plan(self, **kwargs):
        args = {"project_id": self.project["id"], "skill_id": "recon-technology-identification", "target": "https://lab.test/app", "tool": "httpx"}
        return service.vulnfusion_plan_task(**{**args, **kwargs})["task"]

    def test_host_agent_selects_skill_without_model_api(self):
        with patch("backend.llm.OpenAICompatibleProvider.chat", side_effect=AssertionError("unexpected model call")):
            task = self.plan(tool="whatweb", reason="inspect framework")
        self.assertEqual(task["remote_tool"], "whatweb")
        self.assertEqual(task["payload"]["planner"], "host-agent")
        self.assertIn("--follow-redirect=never", task["payload"]["args"])
        self.assertTrue(service.vulnfusion_get_skill(task["skill_id"])["instructions"])

    def test_scope_rejects_wrong_host_protocol_port_and_path(self):
        for target in ("https://lab.test.evil/app", "http://lab.test/app", "https://lab.test:8443/app", "https://lab.test/apple", "https://lab.test/app/../admin", "https://lab.test/app/%2e%2e/admin", "https://user:pass@lab.test/app"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.plan(target=target)
        self.assertTrue(self.plan(target="https://lab.test/app/api?x=1"))
        with self.assertRaises(ValueError):
            self.plan(tool="nmap")

    def test_missing_scope_and_arbitrary_tool_rejected_before_persistence(self):
        project = service.vulnfusion_start_assessment("code", True, root_path=self.directory)["project"]
        with self.assertRaises(ValueError):
            service.vulnfusion_plan_task(project["id"], "recon-technology-identification", "httpx", "https://lab.test")
        with self.assertRaises(ValueError):
            self.plan(tool="bash")
        self.assertEqual(self.store.list("tasks"), [])

    def test_preview_never_executes_and_cannot_support_conclusions(self):
        task = self.plan()
        with patch.object(self.executor, "execute") as execute:
            with self.assertRaises(ValueError):
                service.vulnfusion_approve_task(task["id"], "approve")
            result = service.vulnfusion_approve_task(task["id"], "approve", "preview only", "tester")
            execute.assert_not_called()
        self.assertTrue(result["result"]["planned"])
        with self.assertRaises(ValueError):
            service.vulnfusion_submit_analysis(self.project["id"], "not observed", [result["result"]["evidence_id"]])

    def test_dependencies_block_execution_until_real_completion(self):
        first = self.plan()
        second = self.plan(dry_run=False, depends_on=[first["id"]])
        with self.assertRaises(ValueError):
            service.vulnfusion_approve_task(second["id"], "approve", "test", "tester")
        service.vulnfusion_approve_task(first["id"], "approve", "preview", "tester")
        with self.assertRaises(ValueError):
            service.vulnfusion_approve_task(second["id"], "approve", "test", "tester")

    def test_remote_result_host_analysis_review_and_report(self):
        task = self.plan(dry_run=False)
        with patch.object(self.executor, "execute", return_value=RemoteResult(True, "httpx-toolkit", "200 framework=test", exit_code=0)) as execute:
            result = service.vulnfusion_approve_task(task["id"], "approve", "approved fixture", "tester")
            with self.assertRaises(ValueError):
                service.vulnfusion_approve_task(task["id"], "approve", "duplicate", "tester")
            self.assertEqual(execute.call_count, 1)
        analysis = service.vulnfusion_submit_analysis(self.project["id"], "Needs application review", [result["result"]["evidence_id"]], [service.Candidate(title="Fixture", vulnerability_type="configuration", description="Fixture needs review")])
        finding_id = analysis["finding_ids"][0]
        self.assertEqual(self.store.get("findings", finding_id)["status"], "needs_human")
        service.vulnfusion_decide_finding(finding_id, "false_positive", "Fixture is expected")
        report = service.vulnfusion_generate_report(self.project["id"], True)
        self.assertIn("Needs application review", report["markdown"])
        self.assertIn("Fixture is expected", report["markdown"])
        self.assertIn(analysis["analysis_evidence_id"], report["markdown"])

    def test_evidence_cannot_cross_project_boundary(self):
        other = service.vulnfusion_start_assessment("other", True, ["https://elsewhere.test"])["project"]
        evidence = add_evidence(EvidenceCreate(project_id=other["id"], kind="tool", title="fixture", content="fixture"))
        with self.assertRaises(ValueError):
            service.vulnfusion_submit_analysis(self.project["id"], "wrong", [evidence.id])

    def test_code_upload_gets_unique_task_path_without_web_target(self):
        tasks = [self.plan(skill_id="analysis-javascript", tool="semgrep", target="", dry_run=False) for _ in range(2)]
        self.assertNotEqual(tasks[0]["payload"]["remote_path"], tasks[1]["payload"]["remote_path"])
        with patch.object(self.executor, "upload_project") as upload, patch.object(self.executor, "execute", return_value=RemoteResult(True, "semgrep", '{"results":[]}', exit_code=0)):
            service.vulnfusion_approve_task(tasks[0]["id"], "approve", "source upload allowed", "tester")
        self.assertEqual(upload.call_args.args[1], f"{self.project['id']}/{tasks[0]['id']}")

    def test_gitleaks_json_array_is_parsed(self):
        output = json.dumps([{"RuleID": "test-key", "File": "a.py", "StartLine": 3}])
        self.assertEqual(analyze_tool_output("gitleaks", output, "")[0]["line_start"], 3)

    def test_multiple_store_instances_do_not_overwrite_records(self):
        second = Store(str(self.store.path))
        self.store.add("projects", Project(name="one"))
        second.add("projects", Project(name="two"))
        self.assertEqual({item["name"] for item in self.store.list("projects")}, {"test", "one", "two"})
        task = self.plan()
        self.store.update("tasks", task["id"], {"status": "running"}, expected_status="waiting_approval")
        with self.assertRaises(ValueError):
            second.update("tasks", task["id"], {"status": "running"}, expected_status="waiting_approval")


if __name__ == "__main__":
    unittest.main()
