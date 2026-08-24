"""Tests for safe, user-confirmed response helpers."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from src.response.actions import terminate_process


class SafeTerminationTests(unittest.TestCase):
    @patch('src.response.actions.psutil.Process')
    def test_protected_process_is_refused(self, mock_process: Mock) -> None:
        result = terminate_process(101, 'svchost.exe')

        self.assertFalse(result.success)
        self.assertEqual(result.status, 'protected process - no termination')
        mock_process.assert_not_called()

    @patch('src.response.actions.psutil.Process')
    def test_critical_pids_are_refused(self, mock_process: Mock) -> None:
        for pid in (0, 4):
            result = terminate_process(pid, 'unknown.exe')
            self.assertFalse(result.success)
            self.assertEqual(result.status, 'protected process - no termination')
        mock_process.assert_not_called()

    @patch('src.response.actions.psutil.Process')
    def test_unprotected_process_uses_mocked_termination_path(self, mock_process: Mock) -> None:
        process = Mock()
        mock_process.return_value = process

        result = terminate_process(1234, 'simulated_miner.exe')

        self.assertTrue(result.success)
        self.assertEqual(result.status, 'terminated')
        mock_process.assert_called_once_with(1234)
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)
