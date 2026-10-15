import tempfile
import unittest
from pathlib import Path

from backend.scanner import scan_project


class ScannerSmokeTest(unittest.TestCase):
    def test_finds_intentional_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.py"
            source.write_text(
                "import os\nos.system(user_input)\nquery = f'SELECT {user_input}'\n",
                encoding="utf-8",
            )
            findings = scan_project("test-project", directory)
        self.assertGreaterEqual(
            {f.vulnerability_type for f in findings},
            {"command_injection", "sql_injection"},
        )


if __name__ == "__main__":
    unittest.main()
