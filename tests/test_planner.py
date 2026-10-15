import unittest

from backend.agents import DeepSeekPlanner
from backend.llm import ProviderResult
from backend.models import Project, RunRequest


class FakeProvider:
    configured = True
    model = "deepseek-chat"
    base_url = "https://example.invalid"

    def chat(self, messages):
        return ProviderResult(
            '{"steps":[{"agent":"analysis","skill_id":"analysis-api","reason":"先分析 API"},{"agent":"recon","skill_id":"recon-technology-identification","reason":"识别技术栈"},{"agent":"arbitrary_shell","skill_id":"analysis-api","reason":"bad"},{"agent":"analysis","skill_id":"unknown","reason":"bad"}]}',
            self.model,
            "deepseek",
            {},
        )


class PlannerTest(unittest.TestCase):
    def test_filters_unknown_agents_and_skills(self):
        planner = DeepSeekPlanner(FakeProvider())
        plan = planner.plan(Project(name="x", root_path=".", authorized=True), RunRequest(mode="full"))
        self.assertEqual([x["skill_id"] for x in plan.steps], ["analysis-api", "recon-technology-identification"])
        self.assertEqual(plan.source, "deepseek")
        self.assertTrue(planner.last_used)


if __name__ == "__main__":
    unittest.main()
