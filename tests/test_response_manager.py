import json
from pathlib import Path
import tempfile
import unittest

from src.response.response_manager import ResponseManager


class TestResponseManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_path = Path(self.temp_dir.name) / "test_response_audit.jsonl"
        self.current_time = 1000.0

    def tearDown(self):
        self.temp_dir.cleanup()

    def _mock_time(self) -> float:
        return self.current_time

    def test_should_prompt_initial_and_after_cooldown(self):
        manager = ResponseManager(
            cooldown_seconds=60.0,
            audit_file=self.audit_path,
            time_func=self._mock_time,
        )

        pid = 1234
        # Initially, process has not been prompted yet
        self.assertTrue(manager.should_prompt(pid))

        # Mark as prompted at t=1000
        manager.mark_prompted(pid)

        # Immediately afterwards (t=1000), should_prompt should be False
        self.assertFalse(manager.should_prompt(pid))

        # At t=1030 (30s elapsed < 60s cooldown), should still be False
        self.current_time = 1030.0
        self.assertFalse(manager.should_prompt(pid))

        # At t=1060 (60s elapsed == 60s cooldown), should be True again
        self.current_time = 1060.0
        self.assertTrue(manager.should_prompt(pid))

        # Different PID should not be affected by other PIDs' cooldowns
        self.assertTrue(manager.should_prompt(5678))

    def test_record_action_appends_valid_jsonl(self):
        manager = ResponseManager(
            cooldown_seconds=120.0,
            audit_file=self.audit_path,
            time_func=self._mock_time,
        )

        record1 = manager.record_action(
            pid=999,
            name="xmrig.exe",
            action="Terminated",
            details={"score": 85.0, "reasons": ["high CPU usage", "known miner executable name"]},
        )
        self.assertEqual(record1["pid"], 999)
        self.assertEqual(record1["name"], "xmrig.exe")
        self.assertEqual(record1["action"], "Terminated")
        self.assertIn("timestamp", record1)

        record2 = manager.record_action(
            pid=4,
            name="system.exe",
            action="Protected - skipped",
            details={"score": 90.0},
        )

        self.assertTrue(self.audit_path.exists())

        # Read back written lines
        lines = self.audit_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)

        data1 = json.loads(lines[0])
        self.assertEqual(data1["pid"], 999)
        self.assertEqual(data1["action"], "Terminated")
        self.assertEqual(data1["details"]["score"], 85.0)

        data2 = json.loads(lines[1])
        self.assertEqual(data2["pid"], 4)
        self.assertEqual(data2["action"], "Protected - skipped")

    def test_record_action_default_empty_details(self):
        manager = ResponseManager(
            cooldown_seconds=10.0,
            audit_file=self.audit_path,
            time_func=self._mock_time,
        )
        record = manager.record_action(pid=100, name="app.exe", action="User declined")
        self.assertEqual(record["details"], {})

        lines = self.audit_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        data = json.loads(lines[0])
        self.assertEqual(data["details"], {})


if __name__ == "__main__":
    unittest.main()
