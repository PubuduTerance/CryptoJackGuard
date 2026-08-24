"""Focused tests for efficient, safe process telemetry collection."""

from __future__ import annotations

from contextlib import contextmanager
import unittest
from unittest.mock import patch

import psutil

from src.collectors.process_collector import collect_processes


class FakeProcess:
    def __init__(
        self,
        pid: int,
        name: str,
        path: str,
        cmdline: list[str],
        ppid: int | None,
        cpu_values: list[float] | None = None,
        memory_percent: float = 1.0,
        error: Exception | None = None,
    ) -> None:
        self.pid = pid
        self._info = {
            'pid': pid,
            'name': name,
            'exe': path,
            'cmdline': cmdline,
            'ppid': ppid,
        }
        self._cpu_values = list(cpu_values or [0.0])
        self._memory_percent = memory_percent
        self._error = error

    @contextmanager
    def oneshot(self):
        yield

    def as_dict(self, attrs: list[str], ad_value: object = None) -> dict[str, object]:
        if self._error is not None:
            raise self._error
        return {attribute: self._info.get(attribute, ad_value) for attribute in attrs}

    def cpu_percent(self, interval: float | None = None) -> float:
        if self._error is not None:
            raise self._error
        if len(self._cpu_values) > 1:
            return self._cpu_values.pop(0)
        return self._cpu_values[0]

    def memory_percent(self) -> float:
        if self._error is not None:
            raise self._error
        return self._memory_percent


class ProcessCollectorTests(unittest.TestCase):
    def test_access_denied_and_disappearing_processes_are_skipped(self) -> None:
        valid = FakeProcess(10, 'worker.exe', r'C:\Tools\worker.exe', ['worker.exe'], 1)
        denied = FakeProcess(11, 'denied.exe', '', [], 1, error=psutil.AccessDenied(pid=11))
        disappeared = FakeProcess(12, 'gone.exe', '', [], 1, error=psutil.NoSuchProcess(pid=12))

        with patch('src.collectors.process_collector.psutil.process_iter', return_value=[valid, denied, disappeared]):
            collected = collect_processes()

        self.assertEqual([process.pid for process in collected], [10])

    def test_parent_metadata_is_resolved_from_current_snapshot(self) -> None:
        parent = FakeProcess(20, 'parent.exe', r'C:\Tools\parent.exe', ['parent.exe'], 1)
        child = FakeProcess(21, 'child.exe', r'C:\Tools\child.exe', ['child.exe', '--run'], 20)

        with patch('src.collectors.process_collector.psutil.process_iter', return_value=[parent, child]):
            collected = collect_processes()

        child_info = next(process for process in collected if process.pid == 21)
        self.assertEqual(child_info.parent_name, 'parent.exe')
        self.assertEqual(child_info.parent_path, r'C:\Tools\parent.exe')
        self.assertEqual(child_info.cmdline, 'child.exe --run')

    def test_first_cpu_sample_can_be_zero_and_later_sample_is_usable(self) -> None:
        process = FakeProcess(
            30,
            'worker.exe',
            r'C:\Tools\worker.exe',
            ['worker.exe'],
            1,
            cpu_values=[0.0, 27.5],
        )

        with patch('src.collectors.process_collector.psutil.process_iter', return_value=[process]):
            first_scan = collect_processes()
            later_scan = collect_processes()

        self.assertEqual(first_scan[0].cpu_percent, 0.0)
        self.assertEqual(later_scan[0].cpu_percent, 27.5)


if __name__ == '__main__':
    unittest.main()
