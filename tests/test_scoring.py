"""Regression tests for CryptoJackGuard heuristic process scoring."""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from src.collectors.network_collector import ProcessNetworkInfo
from src.collectors.process_collector import ProcessInfo
from src.detection.scoring import score_process
from src.intelligence.osint_loader import load_mining_indicators


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALERT_THRESHOLD = 60.0


def load_test_config() -> dict:
    with (PROJECT_ROOT / 'config.json').open('r', encoding='utf-8') as handle:
        return json.load(handle)


def make_process(
    name: str,
    cpu_percent: float,
    memory_percent: float = 5.0,
    path: str = r'C:\Tools\application.exe',
    cmdline: str = '',
    pid: int = 1234,
) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        name=name,
        path=path,
        cmdline=cmdline,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
    )


def make_network(
    local_ports: list[int] | None = None,
    remote_ports: list[int] | None = None,
) -> ProcessNetworkInfo:
    return ProcessNetworkInfo(
        pid=1234,
        local_ports=local_ports or [],
        remote_ports=remote_ports or [],
        remote_addresses=[],
        statuses=[],
    )


class ScoreProcessRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_test_config()
        self.indicators = load_mining_indicators(PROJECT_ROOT / 'data' / 'mining_iocs.txt')

    def test_benign_high_cpu_only_stays_below_alert_threshold(self) -> None:
        score = score_process(
            make_process('python.exe', cpu_percent=95.0, cmdline='python workload.py'),
            None,
            self.indicators,
            self.config,
        )

        self.assertLess(score.risk_score, ALERT_THRESHOLD)
        self.assertNotIn('mining indicator found in process path or command line', score.reasons)

    def test_safe_named_process_with_miner_evidence_is_alerted(self) -> None:
        score = score_process(
            make_process(
                'svchost.exe',
                cpu_percent=95.0,
                cmdline='svchost.exe --algo randomx --pool stratum+tcp://example.test:3333',
            ),
            make_network(remote_ports=[3333]),
            self.indicators,
            self.config,
        )

        self.assertNotEqual(score.risk_score, 0.0)
        self.assertGreaterEqual(score.risk_score, ALERT_THRESHOLD)
        self.assertIn('safe process name; no reduction due to strong mining evidence', score.allowlist_notes)

    def test_java_jar_command_does_not_create_mining_ioc_risk(self) -> None:
        score = score_process(
            make_process(
                'java.exe',
                cpu_percent=45.0,
                memory_percent=25.0,
                cmdline='java -jar myapp.jar',
            ),
            None,
            self.indicators,
            self.config,
        )

        self.assertLess(score.risk_score, ALERT_THRESHOLD)
        self.assertNotIn('mining indicator found in process path or command line', score.reasons)

    def test_local_port_8080_does_not_create_mining_port_risk(self) -> None:
        score = score_process(
            make_process('python.exe', cpu_percent=45.0, cmdline='python app.py'),
            make_network(local_ports=[8080]),
            self.indicators,
            self.config,
        )

        self.assertLess(score.risk_score, ALERT_THRESHOLD)
        self.assertFalse(any('mining port' in reason for reason in score.reasons))

    def test_simulated_miner_reaches_alert_threshold(self) -> None:
        score = score_process(
            make_process(
                'python.exe',
                cpu_percent=95.0,
                cmdline='python simulated_miner_args.py --algo randomx --pool stratum+tcp://example.test:3333 --user test',
            ),
            make_network(remote_ports=[3333]),
            self.indicators,
            self.config,
        )

        self.assertGreaterEqual(score.risk_score, ALERT_THRESHOLD)

    def test_specific_stratum_match_suppresses_generic_substring_match(self) -> None:
        score = score_process(
            make_process('python.exe', cpu_percent=0.0, cmdline='python client.py stratum+tcp://example.test:3333'),
            None,
            self.indicators,
            self.config,
        )

        cli_reasons = [reason for reason in score.reasons if 'miner-like CLI indicator' in reason]
        self.assertEqual(len(cli_reasons), 1)
        self.assertIn('stratum+tcp', cli_reasons[0])
        self.assertNotIn('2 miner-like CLI indicators', cli_reasons[0])


if __name__ == '__main__':
    unittest.main()
