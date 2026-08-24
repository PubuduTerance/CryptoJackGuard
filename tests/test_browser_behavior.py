"""Synthetic tests for privacy-preserving browser behavior correlation."""

from __future__ import annotations

from dataclasses import fields
import unittest

from src.collectors.network_collector import ProcessNetworkInfo
from src.collectors.process_collector import ProcessInfo
from src.detection.browser_behavior import (
    BrowserBehaviorDetector,
    BrowserBehaviorResult,
    apply_browser_behavior_signal,
)
from src.detection.scan_scheduler import should_run_dashboard_scan
from src.detection.scoring import ProcessScore, score_process


CONFIG = {
    'high_cpu_threshold': 30.0,
    'high_memory_threshold': 20.0,
    'alert_threshold': 60.0,
    'cpu_non_trivial_threshold': 10.0,
    'suspicious_ports': [3333, 4444, 7777],
    'suspicious_path_keywords': ['miner', 'crypt', 'coins', 'xmr', 'xmrig'],
    'suspicious_cmd_indicators': ['stratum', 'xmrig', '--algo', '--pool'],
    'safe_process_names': ['chrome.exe'],
    'allowlist_process_names': [],
}


def browser_score(
    cpu_percent: float = 80.0,
    reasons: list[str] | None = None,
    anomaly_reasons: list[str] | None = None,
    name: str = 'chrome.exe',
    parent_name: str = '',
    cmdline: str = '',
    risk_score: float = 0.0,
) -> ProcessScore:
    return ProcessScore(
        pid=4242,
        name=name,
        path=rf'C:\Program Files\Browser\{name}',
        cmdline=cmdline,
        cpu_percent=cpu_percent,
        memory_percent=10.0,
        local_ports=[],
        risk_score=risk_score,
        reasons=list(reasons or []),
        anomaly_reasons=list(anomaly_reasons or []),
        parent_name=parent_name,
    )


class BrowserBehaviorTests(unittest.TestCase):
    def test_chrome_high_cpu_alone_does_not_create_cryptojacking_alert(self) -> None:
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=2)
        process = ProcessInfo(
            pid=4242,
            name='chrome.exe',
            path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            cmdline='chrome.exe --type=renderer',
            cpu_percent=80.0,
            memory_percent=10.0,
        )
        score = score_process(process, None, set(), CONFIG)

        result = detector.analyze(score)
        apply_browser_behavior_signal(score, result)

        self.assertTrue(result.is_browser_process)
        self.assertFalse(result.browser_mining_suspicion)
        self.assertLess(score.risk_score, 60.0)

    def test_chrome_stable_normal_cpu_has_no_browser_suspicion(self) -> None:
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=2)
        result = detector.analyze(browser_score(cpu_percent=12.0))

        self.assertFalse(result.sustained_compute)
        self.assertFalse(result.browser_mining_suspicion)

    def test_high_compute_before_required_cycles_is_not_sustained(self) -> None:
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=3)

        result = detector.analyze(browser_score())

        self.assertFalse(result.sustained_compute)

    def test_sustained_compute_without_mining_evidence_is_not_malicious(self) -> None:
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=2)
        detector.analyze(browser_score())
        result = detector.analyze(browser_score())

        self.assertTrue(result.sustained_compute)
        self.assertFalse(result.browser_mining_suspicion)
        self.assertEqual(result.score_contribution, 0.0)

    def test_sustained_cpu_anomaly_with_network_ioc_adds_supporting_score(self) -> None:
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=2, max_score=12.0)
        score = browser_score(
            reasons=["mining network IOC match(es): ['pool.example.test']"],
            anomaly_reasons=['CPU anomaly above recent process baseline'],
            risk_score=58.0,
        )
        detector.analyze(score)
        result = detector.analyze(score)
        apply_browser_behavior_signal(score, result)

        self.assertTrue(result.mining_network_evidence)
        self.assertTrue(result.browser_mining_suspicion)
        self.assertEqual(result.score_contribution, 12.0)
        self.assertEqual(score.risk_score, 70.0)
        self.assertIn('browser CPU anomaly correlated with sustained compute and mining network evidence', score.reasons)

    def test_sustained_cpu_anomaly_with_mining_port_is_supporting_evidence(self) -> None:
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=2)
        score = browser_score(
            reasons=['suspicious remote mining port(s): [3333]'],
            anomaly_reasons=['CPU anomaly above recent process baseline'],
        )
        detector.analyze(score)
        result = detector.analyze(score)

        self.assertTrue(result.browser_mining_suspicion)
        self.assertTrue(result.mining_network_evidence)

    def test_non_browser_high_cpu_process_is_not_analyzed_as_browser(self) -> None:
        result = BrowserBehaviorDetector().analyze(browser_score(name='python.exe'))

        self.assertFalse(result.is_browser_process)
        self.assertFalse(result.browser_mining_suspicion)

    def test_presentation_only_dashboard_rerun_does_not_advance_browser_state(self) -> None:
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=3)
        score = browser_score()
        detector.analyze(score)

        should_scan = should_run_dashboard_scan(True, False, None, None)
        if should_scan:
            detector.analyze(score)

        result = detector.analyze(score)
        self.assertFalse(result.sustained_compute)

    def test_browser_allowlist_does_not_erase_correlated_network_evidence(self) -> None:
        process = ProcessInfo(
            pid=4242,
            name='chrome.exe',
            path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            cmdline='chrome.exe --type=renderer',
            cpu_percent=80.0,
            memory_percent=10.0,
        )
        network = ProcessNetworkInfo(
            pid=4242,
            local_ports=[],
            remote_ports=[3333],
            remote_addresses=['203.0.113.10:3333'],
            statuses=['ESTABLISHED'],
        )
        score = score_process(process, network, set(), CONFIG)
        score.anomaly_reasons = ['CPU anomaly above recent process baseline']
        detector = BrowserBehaviorDetector(cpu_threshold=50.0, sustained_cycles=2)
        detector.analyze(score)
        result = detector.analyze(score)
        apply_browser_behavior_signal(score, result)

        self.assertTrue(any('no reduction due to strong mining evidence' in note for note in score.allowlist_notes))
        self.assertTrue(result.browser_mining_suspicion)
        self.assertGreaterEqual(score.risk_score, 60.0)

    def test_browser_identification_includes_renderer_but_not_generic_electron(self) -> None:
        detector = BrowserBehaviorDetector()
        renderer = browser_score(name='renderer.exe', parent_name='chrome.exe', cmdline='renderer.exe --type=renderer')
        electron = browser_score(name='code.exe', parent_name='chrome.exe', cmdline='code.exe --type=renderer')

        self.assertTrue(detector.analyze(renderer).is_browser_process)
        self.assertFalse(detector.analyze(electron).is_browser_process)

    def test_browser_result_has_no_browsing_history_or_page_content_fields(self) -> None:
        field_names = {item.name for item in fields(BrowserBehaviorResult)}
        banned_fragments = ('history', 'url', 'page', 'content', 'html', 'cookie', 'credential')

        self.assertFalse(any(fragment in name for name in field_names for fragment in banned_fragments))


if __name__ == '__main__':
    unittest.main()
