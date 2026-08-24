"""Tests for lightweight stealth and Windows persistence detection."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from src.collectors.persistence_collector import (
    PersistenceFinding,
    PersistenceInspectionCache,
    PersistenceScanResult,
    apply_persistence_findings,
    collect_persistence_findings,
)
from src.collectors.process_collector import ProcessInfo
from src.detection.scoring import ProcessScore, score_process


def scoring_config() -> dict:
    return {
        'high_cpu_threshold': 30.0,
        'high_memory_threshold': 20.0,
        'suspicious_ports': [3333, 4444, 7777],
        'suspicious_path_keywords': ['miner', 'crypt', 'coins', 'xmr', 'xmrig'],
        'suspicious_cmd_indicators': [
            'stratum', 'stratum+tcp', 'stratum+ssl', 'xmrig', 'randomx',
            '--algo', '--coin', '--pool', '--pass',
        ],
        'safe_process_names': ['svchost.exe'],
    }


def make_process(
    name: str,
    path: str,
    cmdline: str = '',
    cpu_percent: float = 0.0,
    parent_name: str = '',
) -> ProcessInfo:
    return ProcessInfo(
        pid=1234,
        name=name,
        path=path,
        cmdline=cmdline,
        cpu_percent=cpu_percent,
        memory_percent=5.0,
        ppid=1000 if parent_name else None,
        parent_name=parent_name,
        parent_path=r'C:\Windows\System32\parent.exe' if parent_name else '',
    )


class StealthScoringTests(unittest.TestCase):
    def test_system32_svchost_has_no_masquerading_signal(self) -> None:
        score = score_process(
            make_process('svchost.exe', r'C:\Windows\System32\svchost.exe'),
            None,
            set(),
            scoring_config(),
        )

        self.assertFalse(any('System32 path' in reason for reason in score.reasons))

    def test_syswow64_svchost_has_no_masquerading_signal(self) -> None:
        score = score_process(
            make_process('svchost.exe', r'C:\Windows\SysWOW64\svchost.exe'),
            None,
            set(),
            scoring_config(),
        )

        self.assertFalse(any('outside expected System32 path' in reason for reason in score.reasons))

    def test_alternate_windows_root_system32_path_is_trusted(self) -> None:
        with patch.dict('os.environ', {'SystemRoot': r'D:\WindowsAlt', 'WINDIR': r'D:\WindowsAlt'}):
            score = score_process(
                make_process('svchost.exe', r'D:\WindowsAlt\System32\svchost.exe'),
                None,
                set(),
                scoring_config(),
            )

        self.assertFalse(any('outside expected System32 path' in reason for reason in score.reasons))

    def test_temp_svchost_has_masquerading_and_location_signals(self) -> None:
        score = score_process(
            make_process('svchost.exe', r'C:\Users\Test\AppData\Local\Temp\svchost.exe'),
            None,
            set(),
            scoring_config(),
        )

        self.assertTrue(any('user-writable execution location' in reason for reason in score.reasons))
        self.assertTrue(any('outside expected System32 path' in reason for reason in score.reasons))
        self.assertGreater(score.risk_score, 0.0)

    def test_benign_user_writable_process_stays_below_alert_threshold(self) -> None:
        score = score_process(
            make_process('python.exe', r'C:\Users\Test\AppData\Local\Temp\tool.exe', cpu_percent=25.0),
            None,
            set(),
            scoring_config(),
        )

        self.assertLess(score.risk_score, 60.0)

    def test_suspicious_location_with_strong_mining_cli_reaches_alert_threshold(self) -> None:
        score = score_process(
            make_process(
                'python.exe',
                r'C:\Users\Test\AppData\Local\Temp\miner.exe',
                '--algo randomx --pool stratum+tcp://example.test:3333',
                cpu_percent=95.0,
            ),
            None,
            set(),
            scoring_config(),
        )

        self.assertGreaterEqual(score.risk_score, 60.0)

    def test_scripting_parent_alone_is_not_high_risk(self) -> None:
        score = score_process(
            make_process('python.exe', r'C:\Tools\tool.exe', parent_name='powershell.exe'),
            None,
            set(),
            scoring_config(),
        )

        self.assertLess(score.risk_score, 60.0)
        self.assertFalse(any('suspicious parent process' in reason for reason in score.reasons))

    def test_scripting_parent_with_miner_indicators_adds_reason(self) -> None:
        score = score_process(
            make_process(
                'python.exe',
                r'C:\Tools\miner.exe',
                '--algo randomx --pool stratum+tcp://example.test:3333',
                cpu_percent=95.0,
                parent_name='powershell.exe',
            ),
            None,
            set(),
            scoring_config(),
        )

        self.assertIn('suspicious parent process combined with miner indicators', score.reasons)


class FakeRegistryKey:
    def __init__(self, values: list[tuple[str, str, int]]) -> None:
        self.values = values

    def Close(self) -> None:
        return None


class FakeRegistry:
    HKEY_CURRENT_USER = 'HKCU'
    HKEY_LOCAL_MACHINE = 'HKLM'
    KEY_READ = 1

    def __init__(self, values_by_hive: dict[str, list[tuple[str, str, int]]]) -> None:
        self.values_by_hive = values_by_hive

    def OpenKey(self, hive: str, *_args: object) -> FakeRegistryKey:
        if hive not in self.values_by_hive:
            raise FileNotFoundError()
        return FakeRegistryKey(self.values_by_hive[hive])

    @staticmethod
    def EnumValue(key: FakeRegistryKey, index: int) -> tuple[str, str, int]:
        if index >= len(key.values):
            raise OSError()
        return key.values[index]


class PersistenceCollectorTests(unittest.TestCase):
    @patch('src.collectors.persistence_collector._read_scheduled_task_entries', return_value=[])
    @patch('src.collectors.persistence_collector.is_windows', return_value=True)
    def test_miner_run_entry_creates_finding(self, _is_windows: object, _tasks: object) -> None:
        fake_registry = FakeRegistry({
            'HKCU': [('Miner', r'C:\Users\Test\AppData\Roaming\xmrig.exe --pool stratum+tcp://example.test:3333', 1)],
        })
        with patch('src.collectors.persistence_collector.winreg', fake_registry):
            result = collect_persistence_findings({'xmrig'})

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source, 'HKCU Run')

    @patch('src.collectors.persistence_collector._read_scheduled_task_entries', return_value=[])
    @patch('src.collectors.persistence_collector.is_windows', return_value=True)
    def test_benign_run_entry_creates_no_finding(self, _is_windows: object, _tasks: object) -> None:
        fake_registry = FakeRegistry({
            'HKCU': [('OneDrive', r'C:\Program Files\Microsoft OneDrive\OneDrive.exe /background', 1)],
        })
        with patch('src.collectors.persistence_collector.winreg', fake_registry):
            result = collect_persistence_findings({'xmrig'})

        self.assertEqual(result.findings, [])

    @patch('src.collectors.persistence_collector._read_run_registry_entries', return_value=[])
    @patch('src.collectors.persistence_collector._read_scheduled_task_entries')
    @patch('src.collectors.persistence_collector.is_windows', return_value=True)
    def test_miner_scheduled_task_creates_finding(
        self,
        _is_windows: object,
        mocked_tasks: object,
        _run_entries: object,
    ) -> None:
        mocked_tasks.return_value = [
            ('Scheduled Task', r'\MinerTask', r'C:\Users\Test\AppData\Local\Temp\xmrig.exe --algo randomx'),
        ]

        result = collect_persistence_findings({'xmrig'})

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source, 'Scheduled Task')

    @patch('src.collectors.persistence_collector._read_run_registry_entries', return_value=[])
    @patch('src.collectors.persistence_collector._read_scheduled_task_entries')
    @patch('src.collectors.persistence_collector.is_windows', return_value=True)
    def test_benign_scheduled_task_creates_no_finding(
        self,
        _is_windows: object,
        mocked_tasks: object,
        _run_entries: object,
    ) -> None:
        mocked_tasks.return_value = [('Scheduled Task', r'\BackupTask', r'C:\Windows\System32\backup.exe')]

        result = collect_persistence_findings({'xmrig'})

        self.assertEqual(result.findings, [])

    @patch('src.collectors.persistence_collector._read_scheduled_task_entries', return_value=[])
    @patch('src.collectors.persistence_collector.is_windows', return_value=True)
    def test_registry_access_failure_is_graceful(self, _is_windows: object, _tasks: object) -> None:
        fake_registry = FakeRegistry({})
        with patch('src.collectors.persistence_collector.winreg', fake_registry):
            result = collect_persistence_findings({'xmrig'})

        self.assertEqual(result.findings, [])
        self.assertTrue(result.performed)

    @patch('src.collectors.persistence_collector.is_windows', return_value=False)
    def test_non_windows_returns_unsupported_empty_result(self, _is_windows: object) -> None:
        result = collect_persistence_findings({'xmrig'})

        self.assertFalse(result.supported)
        self.assertFalse(result.performed)
        self.assertEqual(result.findings, [])

    @patch('src.collectors.persistence_collector.collect_persistence_findings')
    @patch('src.collectors.persistence_collector.is_windows', return_value=True)
    def test_deep_inspection_is_triggered_and_cached(
        self,
        _is_windows: object,
        mocked_collect: object,
    ) -> None:
        mocked_collect.return_value = PersistenceScanResult(
            findings=[], duration_ms=1.0, supported=True, performed=True,
        )
        cache = PersistenceInspectionCache(cache_seconds=300.0)
        low_score = ProcessScore(1, 'tool.exe', '', '', 0.0, 0.0, [], 20.0, [])
        high_score = ProcessScore(2, 'tool.exe', '', '', 0.0, 0.0, [], 80.0, [])

        cache.inspect_if_triggered([low_score], 40.0, {'xmrig'})
        first_result = cache.inspect_if_triggered([high_score], 40.0, {'xmrig'})
        second_result = cache.inspect_if_triggered([high_score], 40.0, {'xmrig'})

        self.assertIs(first_result, second_result)
        self.assertEqual(mocked_collect.call_count, 1)

    def test_matching_persistence_finding_adds_modest_process_signal(self) -> None:
        score = ProcessScore(
            pid=1234,
            name='xmrig.exe',
            path=r'C:\Users\Test\AppData\Local\Temp\xmrig.exe',
            cmdline='xmrig.exe --pool stratum+tcp://example.test:3333',
            cpu_percent=90.0,
            memory_percent=5.0,
            local_ports=[],
            risk_score=70.0,
            reasons=[],
        )
        finding = PersistenceFinding(
            source='HKCU Run',
            name='Miner',
            command=r'C:\Users\Test\AppData\Local\Temp\xmrig.exe --pool stratum+tcp://example.test:3333',
            reason='mining indicator in persistence command',
        )

        apply_persistence_findings([score], [finding])

        self.assertEqual(score.risk_score, 80.0)
        self.assertTrue(any('suspicious persistence entry matches process' in reason for reason in score.reasons))


if __name__ == '__main__':
    unittest.main()
