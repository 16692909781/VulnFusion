import json
import shlex
import subprocess
import unittest
from unittest.mock import patch

from backend.kali import KaliConfig, KaliConfigurationError, KaliExecutor


class KaliConnectionTest(unittest.TestCase):
    def setUp(self):
        self.executor = KaliExecutor(KaliConfig(host="kali.example", key_path="test-key"))

    def inventory(self, **changes):
        data = {
            "system": "Linux", "hostname": "kali",
            "tools": {name: f"/usr/bin/{name}" for name in self.executor.ALLOWED_TOOLS},
            "workspace_writable": True, "wordlist_available": True, "httpx_valid": True,
        }
        data.update(changes)
        return data

    def probe_with(self, data):
        completed = subprocess.CompletedProcess([], 0, json.dumps(data), "")
        with patch("backend.kali.shutil.which", return_value="ssh"), patch("backend.kali.subprocess.run", return_value=completed) as run:
            result = self.executor.probe()
        command = run.call_args.args[0]
        self.assertEqual(command[0], "ssh")
        self.assertIn("-n", command)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("IdentitiesOnly=yes", command)
        return result

    def test_configured_does_not_mean_connected(self):
        with patch("backend.kali.subprocess.run") as run:
            status = self.executor.status()
        self.assertTrue(status["configured"])
        self.assertFalse(status["connection_checked"])
        self.assertNotIn("connected", status)
        run.assert_not_called()

    def test_ssh_success_with_missing_tools_is_not_ready(self):
        data = self.inventory(wordlist_available=False)
        data["tools"]["semgrep"] = None
        result = self.probe_with(data)
        self.assertTrue(result["connected"])
        self.assertFalse(result["ready"])
        self.assertEqual(result["missing_tools"], ["semgrep"])

    def test_ready_requires_workspace_wordlist_and_correct_httpx(self):
        self.assertTrue(self.probe_with(self.inventory())["ready"])
        for field in ("workspace_writable", "wordlist_available", "httpx_valid"):
            with self.subTest(field=field):
                result = self.probe_with(self.inventory(**{field: False}))
                self.assertTrue(result["connected"])
                self.assertFalse(result["ready"])

    def test_authentication_failure_and_timeout_are_not_connected(self):
        for response in (
            subprocess.CompletedProcess([], 255, "", "Permission denied (publickey)"),
            subprocess.TimeoutExpired("ssh", 30),
        ):
            with self.subTest(response=response):
                kwargs = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
                with patch("backend.kali.shutil.which", return_value="ssh"), patch("backend.kali.subprocess.run", **kwargs):
                    result = self.executor.probe()
                self.assertFalse(result["connected"])
                self.assertFalse(result["ready"])
                self.assertTrue(result["error"])

    def test_httpx_mapping_preserves_literal_target_arguments(self):
        target = "https://authorized.example/?q=$(id);echo unwanted"
        command = self.executor.plan("httpx", ["-u", target])
        self.assertEqual(shlex.split(command)[1:], ["httpx-toolkit", "-u", target])
        with self.assertRaises(KaliConfigurationError):
            KaliExecutor(KaliConfig(httpx_binary="httpx; id"))


if __name__ == "__main__":
    unittest.main()
