"""Tests for privacy-preserving command-line output handling."""

from __future__ import annotations

import json
from contextlib import redirect_stderr
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.collectors.process_collector import ProcessInfo
from src.detection.alert_lifecycle import build_alert_record
from src.detection.scoring import ProcessScore, score_process
from src.privacy.redaction import redact_command_line
from src.storage import alert_logger


class CommandLineRedactionTests(unittest.TestCase):
    def test_redacts_password_but_preserves_mining_arguments(self) -> None:
        command_line = 'python miner.py --password secret123 --algo randomx'

        redacted = redact_command_line(command_line)

        self.assertIn('--password <redacted>', redacted)
        self.assertNotIn('secret123', redacted)
        self.assertIn('--algo randomx', redacted)

    def test_redacts_equals_forms_for_tokens_and_api_keys(self) -> None:
        command_line = 'tool.exe --token=abcdef --api-key xyz123'

        redacted = redact_command_line(command_line)

        self.assertIn('--token=<redacted>', redacted)
        self.assertIn('--api-key <redacted>', redacted)
        self.assertNotIn('abcdef', redacted)
        self.assertNotIn('xyz123', redacted)

    def test_redacts_pass_but_preserves_pool_and_user(self) -> None:
        command_line = 'python miner.py --pool stratum+tcp://example.test:3333 --user wallet --pass secret'

        redacted = redact_command_line(command_line)

        self.assertIn('--pool stratum+tcp://example.test:3333', redacted)
        self.assertIn('--user wallet', redacted)
        self.assertIn('--pass <redacted>', redacted)
        self.assertNotIn('secret', redacted)

    def test_benign_command_line_is_unchanged(self) -> None:
        command_line = 'python app.py --port 8080 --debug'

        self.assertEqual(redact_command_line(command_line), command_line)

    def test_scoring_uses_raw_mining_arguments(self) -> None:
        command_line = 'python miner.py --algo randomx --pool stratum+tcp://example.test:3333 --pass secret'
        process = ProcessInfo(
            pid=1234,
            name='python.exe',
            path=r'C:\\Tools\\python.exe',
            cmdline=command_line,
            cpu_percent=95.0,
            memory_percent=5.0,
        )
        config = {
            'high_cpu_threshold': 30.0,
            'high_memory_threshold': 20.0,
            'suspicious_ports': [3333],
            'suspicious_path_keywords': [],
            'suspicious_cmd_indicators': ['stratum', 'stratum+tcp', 'randomx', '--algo', '--pool', '--pass'],
        }

        score = score_process(process, None, set(), config)

        self.assertGreaterEqual(score.risk_score, 60.0)
        self.assertTrue(any('--algo' in reason for reason in score.reasons))

    def test_alert_record_redacts_command_line(self) -> None:
        score = ProcessScore(
            pid=1234,
            name='python.exe',
            path=r'C:\\Tools\\python.exe',
            cmdline='python miner.py --pass raw-secret --pool stratum+tcp://example.test:3333',
            cpu_percent=90.0,
            memory_percent=5.0,
            local_ports=[],
            risk_score=80.0,
            reasons=['test alert'],
        )

        record = build_alert_record(score, sustained_cycles=2)

        self.assertIn('--pass <redacted>', str(record['cmdline']))
        self.assertNotIn('raw-secret', str(record['cmdline']))


class AlertLoggerPrivacyTests(unittest.TestCase):
    def test_logger_redacts_direct_command_line_records_and_writes_utc_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_log = Path(temporary_directory) / 'alerts.jsonl'
            original_path = alert_logger.ALERTS_LOG_PATH
            alert_logger.ALERTS_LOG_PATH = temporary_log
            try:
                self.assertTrue(alert_logger.log_alert({'cmdline': 'tool.exe --token raw-token'}))
            finally:
                alert_logger.ALERTS_LOG_PATH = original_path

            record = json.loads(temporary_log.read_text(encoding='utf-8').strip())

        self.assertIn('--token <redacted>', record['cmdline'])
        self.assertNotIn('raw-token', record['cmdline'])
        self.assertTrue(record['timestamp'].endswith('Z'))
        timestamp = datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
        self.assertEqual(timestamp.tzinfo, timezone.utc)

    def test_logger_write_failure_returns_false_and_warns(self) -> None:
        output = StringIO()
        with tempfile.TemporaryDirectory() as temporary_directory:
            original_path = alert_logger.ALERTS_LOG_PATH
            alert_logger.ALERTS_LOG_PATH = Path(temporary_directory) / 'alerts.jsonl'
            try:
                with patch('src.storage.alert_logger.Path.open', side_effect=OSError('test failure')):
                    with redirect_stderr(output):
                        success = alert_logger.log_alert({'cmdline': 'tool.exe --token raw-token'})
            finally:
                alert_logger.ALERTS_LOG_PATH = original_path

        self.assertFalse(success)
        self.assertIn('failed to write alert log', output.getvalue())
