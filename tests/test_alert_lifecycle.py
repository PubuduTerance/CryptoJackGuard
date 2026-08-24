"""Unit tests for shared sustained alert confirmation."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from src.detection.alert_lifecycle import AlertLifecycle, build_alert_record
from src.detection.scoring import ProcessScore
from src.storage import alert_logger


def make_score(
    pid: int = 100,
    risk_score: float = 80.0,
    path: str = r'C:\Tools\process.exe',
    cmdline: str = 'process.exe --pool stratum+tcp://example.test:3333',
) -> ProcessScore:
    return ProcessScore(
        pid=pid,
        name=f'process-{pid}.exe',
        path=path,
        cmdline=cmdline,
        cpu_percent=80.0,
        memory_percent=10.0,
        local_ports=[],
        risk_score=risk_score,
        reasons=['test alert'],
    )


class AlertLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lifecycle = AlertLifecycle(alert_threshold=60.0, sustained_cycles=2)

    def test_confirms_after_sustained_cycles(self) -> None:
        score = make_score()

        self.assertEqual(self.lifecycle.update([score]), [])
        self.assertEqual(self.lifecycle.update([score]), [score])

    def test_suppresses_duplicates_during_same_episode(self) -> None:
        score = make_score()

        self.lifecycle.update([score])
        self.lifecycle.update([score])
        self.assertEqual(self.lifecycle.update([score]), [])

    def test_below_threshold_resets_confirmed_episode(self) -> None:
        suspicious = make_score()
        benign = make_score(risk_score=20.0)

        self.lifecycle.update([suspicious])
        self.lifecycle.update([suspicious])
        self.assertEqual(self.lifecycle.update([benign]), [])
        self.assertEqual(self.lifecycle.update([suspicious]), [])
        self.assertEqual(self.lifecycle.update([suspicious]), [suspicious])

    def test_disappearing_process_resets_history(self) -> None:
        score = make_score()

        self.lifecycle.update([score])
        self.lifecycle.update([])
        self.assertEqual(self.lifecycle.update([score]), [])

    def test_tracks_multiple_processes_independently(self) -> None:
        first = make_score(pid=100)
        second = make_score(pid=200)

        self.assertEqual(self.lifecycle.update([first, second]), [])
        self.assertEqual(self.lifecycle.update([first, second]), [first, second])

    def test_score_at_threshold_qualifies(self) -> None:
        lifecycle = AlertLifecycle(alert_threshold=60.0, sustained_cycles=1)
        score = make_score(risk_score=60.0)

        self.assertEqual(lifecycle.update([score]), [score])


class AlertRecordIntegrationTests(unittest.TestCase):
    def test_confirmed_record_is_compatible_with_alert_logger(self) -> None:
        score = make_score()
        record = build_alert_record(score, sustained_cycles=2)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_log = Path(temporary_directory) / 'alerts.jsonl'
            original_path = alert_logger.ALERTS_LOG_PATH
            alert_logger.ALERTS_LOG_PATH = temporary_log
            try:
                alert_logger.log_alert(record)
            finally:
                alert_logger.ALERTS_LOG_PATH = original_path

            stored_record = json.loads(temporary_log.read_text(encoding='utf-8').strip())

        self.assertIn('timestamp', stored_record)
        for field in ('pid', 'name', 'path', 'cmdline', 'score', 'reasons', 'sustained_cycles'):
            self.assertEqual(stored_record[field], record[field])


if __name__ == '__main__':
    unittest.main()
