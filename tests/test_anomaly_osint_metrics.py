"""Tests for lightweight anomaly, network IOC, and timing instrumentation."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from src.detection.anomaly import AnomalyInfo, ProcessAnomalyDetector, apply_anomaly_signal
from src.detection.scan_scheduler import should_run_dashboard_scan
from src.detection.scoring import ProcessScore
from src.intelligence.network_ioc import NetworkIOCMatcher
from src.monitoring.timing import TIMING_FIELDS, build_scan_timings
from src.storage import alert_logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_score(cpu_percent: float = 10.0, memory_percent: float = 5.0, risk_score: float = 0.0) -> ProcessScore:
    return ProcessScore(
        pid=1234,
        name='python.exe',
        path=r'C:\Tools\worker.exe',
        cmdline='python worker.py',
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        local_ports=[],
        risk_score=risk_score,
        reasons=[],
    )


class AnomalyDetectionTests(unittest.TestCase):
    def test_too_few_samples_is_not_anomalous(self) -> None:
        detector = ProcessAnomalyDetector(window_size=5, min_samples=3)
        score = make_score(cpu_percent=90.0)

        self.assertFalse(detector.observe(score).cpu_anomalous)
        self.assertFalse(detector.observe(score).cpu_anomalous)

    def test_stable_cpu_values_are_not_anomalous(self) -> None:
        detector = ProcessAnomalyDetector(window_size=6, min_samples=3)
        for value in (10.0, 11.0, 9.0):
            detector.observe(make_score(cpu_percent=value))

        self.assertFalse(detector.observe(make_score(cpu_percent=10.0)).cpu_anomalous)

    def test_large_cpu_deviation_after_baseline_is_anomalous(self) -> None:
        detector = ProcessAnomalyDetector(window_size=6, min_samples=5, z_threshold=3.0)
        for value in (10.0, 12.0, 8.0, 11.0, 9.0):
            detector.observe(make_score(cpu_percent=value))

        info = detector.observe(make_score(cpu_percent=90.0))

        self.assertTrue(info.cpu_anomalous)
        self.assertGreater(info.cpu_zscore, 3.0)

    def test_zero_variance_baseline_large_cpu_jump_is_anomalous(self) -> None:
        detector = ProcessAnomalyDetector(window_size=6, min_samples=5)
        for _ in range(5):
            detector.observe(make_score(cpu_percent=10.0))

        info = detector.observe(make_score(cpu_percent=90.0))

        self.assertTrue(info.cpu_anomalous)
        self.assertEqual(info.cpu_zscore, 0.0)

    def test_zero_variance_baseline_tiny_cpu_change_is_not_anomalous(self) -> None:
        detector = ProcessAnomalyDetector(window_size=6, min_samples=5)
        for _ in range(5):
            detector.observe(make_score(cpu_percent=5.0))

        self.assertFalse(detector.observe(make_score(cpu_percent=6.0)).cpu_anomalous)

    def test_zero_variance_memory_baseline_uses_delta_fallback(self) -> None:
        detector = ProcessAnomalyDetector(window_size=6, min_samples=5)
        for _ in range(5):
            detector.observe(make_score(memory_percent=2.0))

        self.assertTrue(detector.observe(make_score(memory_percent=12.0)).memory_anomalous)

    def test_stable_high_cpu_zero_variance_baseline_small_change_is_not_anomalous(self) -> None:
        detector = ProcessAnomalyDetector(window_size=6, min_samples=5)
        for _ in range(5):
            detector.observe(make_score(cpu_percent=80.0))

        self.assertFalse(detector.observe(make_score(cpu_percent=82.0)).cpu_anomalous)

    def test_history_is_bounded(self) -> None:
        detector = ProcessAnomalyDetector(window_size=3, min_samples=2)
        score = make_score()
        for value in range(6):
            detector.observe(make_score(cpu_percent=float(value)))

        self.assertEqual(detector.history_size(score), 3)

    def test_stable_high_cpu_baseline_is_not_continuously_anomalous(self) -> None:
        detector = ProcessAnomalyDetector(window_size=6, min_samples=5)
        for value in (88.0, 90.0, 89.0, 91.0, 90.0):
            detector.observe(make_score(cpu_percent=value))

        self.assertFalse(detector.observe(make_score(cpu_percent=90.0)).cpu_anomalous)

    def test_anomaly_alone_stays_below_alert_threshold(self) -> None:
        score = make_score(risk_score=25.0)
        info = AnomalyInfo(cpu_anomalous=True, sample_count=5, reasons=['baseline CPU anomaly'])

        apply_anomaly_signal(score, info, max_points=8.0)

        self.assertLess(score.risk_score, 60.0)

    def test_anomaly_with_miner_evidence_adds_correlated_reason(self) -> None:
        score = make_score(risk_score=70.0)
        score.reasons.append("3 miner-like CLI indicators: ['--algo', '--pool', 'randomx']")
        info = AnomalyInfo(cpu_anomalous=True, sample_count=5, reasons=['baseline CPU anomaly'])

        apply_anomaly_signal(score, info, max_points=8.0)

        self.assertIn('CPU anomaly correlated with mining evidence', score.reasons)
        self.assertEqual(score.risk_score, 78.0)

    def test_network_ioc_evidence_uses_the_correlated_anomaly_cap(self) -> None:
        score = make_score(risk_score=70.0)
        score.reasons.append("mining network IOC match(es): ['pool.example.test']")
        info = AnomalyInfo(cpu_anomalous=True, sample_count=5, reasons=['baseline CPU anomaly'])

        apply_anomaly_signal(score, info, max_points=6.0)

        self.assertEqual(score.risk_score, 76.0)
        self.assertIn('CPU anomaly correlated with mining evidence', score.reasons)

    def test_anomaly_score_honours_configured_cap(self) -> None:
        score = make_score(risk_score=25.0)
        info = AnomalyInfo(cpu_anomalous=True, sample_count=5, reasons=['baseline CPU anomaly'])

        apply_anomaly_signal(score, info, max_points=3.0)

        self.assertEqual(score.risk_score, 28.0)

    def test_presentation_only_rerun_does_not_advance_baseline(self) -> None:
        detector = ProcessAnomalyDetector(window_size=5, min_samples=2)
        score = make_score()
        detector.observe(score)

        should_scan = should_run_dashboard_scan(True, False, None, None)
        if should_scan:
            detector.observe(score)

        self.assertEqual(detector.history_size(score), 1)


class NetworkIOCMatcherTests(unittest.TestCase):
    def test_literal_configured_ip_matches(self) -> None:
        matcher = NetworkIOCMatcher({'203.0.113.10'}, set())

        self.assertEqual(matcher.match_remote_addresses(['203.0.113.10:3333']), ['203.0.113.10'])

    def test_unrelated_ip_does_not_match(self) -> None:
        matcher = NetworkIOCMatcher({'203.0.113.10'}, set())

        self.assertEqual(matcher.match_remote_addresses(['198.51.100.5:443']), [])

    @patch('src.intelligence.network_ioc.socket.getaddrinfo')
    def test_configured_domain_resolution_matches_remote_ip(self, mocked_dns: object) -> None:
        mocked_dns.return_value = [(None, None, None, None, ('203.0.113.20', 0))]
        matcher = NetworkIOCMatcher(set(), {'pool.example.test'}, cache_seconds=300.0)

        matcher.refresh()

        self.assertEqual(matcher.match_remote_addresses(['203.0.113.20:3333']), ['pool.example.test'])

    @patch('src.intelligence.network_ioc.socket.getaddrinfo', side_effect=OSError('offline'))
    def test_dns_failure_is_graceful(self, _mocked_dns: object) -> None:
        matcher = NetworkIOCMatcher(set(), {'pool.example.test'}, cache_seconds=300.0)

        matcher.refresh()

        self.assertEqual(matcher.match_remote_addresses(['203.0.113.20:3333']), [])

    @patch('src.intelligence.network_ioc.socket.getaddrinfo')
    def test_dns_results_are_cached_within_ttl(self, mocked_dns: object) -> None:
        mocked_dns.return_value = [(None, None, None, None, ('203.0.113.20', 0))]
        matcher = NetworkIOCMatcher(set(), {'pool.example.test'}, cache_seconds=300.0)

        matcher.refresh()
        matcher.refresh()

        self.assertEqual(mocked_dns.call_count, 1)

    @patch('src.intelligence.network_ioc.socket.getaddrinfo')
    def test_expired_dns_cache_allows_refresh(self, mocked_dns: object) -> None:
        mocked_dns.return_value = [(None, None, None, None, ('203.0.113.20', 0))]
        matcher = NetworkIOCMatcher(set(), {'pool.example.test'}, cache_seconds=300.0)

        matcher.refresh()
        matcher._domain_cache['pool.example.test'] = (0.0, {'203.0.113.20'})
        matcher.refresh()

        self.assertEqual(mocked_dns.call_count, 2)


class PerformanceMetricsTests(unittest.TestCase):
    def test_timing_record_contains_required_non_negative_stages(self) -> None:
        timings = build_scan_timings(resource_collection_ms=-1.0, scan_duration_ms=5.0)

        self.assertEqual(set(timings), set(TIMING_FIELDS))
        self.assertTrue(all(value >= 0.0 for value in timings.values()))

    def test_metrics_logger_writes_new_timing_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            original_alert_path = alert_logger.ALERTS_LOG_PATH
            original_metrics_path = alert_logger.SYSTEM_METRICS_PATH
            alert_logger.ALERTS_LOG_PATH = temporary_path / 'alerts.jsonl'
            alert_logger.SYSTEM_METRICS_PATH = temporary_path / 'system_metrics.csv'
            try:
                alert_logger.log_scan_metrics(build_scan_timings(scan_duration_ms=5.0))
            finally:
                alert_logger.ALERTS_LOG_PATH = original_alert_path
                alert_logger.SYSTEM_METRICS_PATH = original_metrics_path

            with (temporary_path / 'system_metrics.csv').open('r', encoding='utf-8', newline='') as handle:
                header = next(csv.reader(handle))

        self.assertTrue(set(TIMING_FIELDS).issubset(header))

    def test_dashboard_parser_handles_older_csv_rows_without_timing_columns(self) -> None:
        fake_streamlit = types.ModuleType('streamlit')
        fake_streamlit.cache_data = lambda function: function
        fake_plotly = types.ModuleType('plotly')
        fake_plotly_express = types.ModuleType('plotly.express')
        fake_plotly.express = fake_plotly_express
        fake_autorefresh = types.ModuleType('streamlit_autorefresh')
        fake_autorefresh.st_autorefresh = lambda **_kwargs: 0
        module_name = 'dashboard_metrics_test_module'
        spec = importlib.util.spec_from_file_location(module_name, PROJECT_ROOT / 'dashboard_app.py')
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)

        with patch.dict(sys.modules, {
            'streamlit': fake_streamlit,
            'plotly': fake_plotly,
            'plotly.express': fake_plotly_express,
            'streamlit_autorefresh': fake_autorefresh,
        }):
            spec.loader.exec_module(module)

        rows = module.parse_metrics_rows([{
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'cpu_percent': '10.0',
            'memory_percent': '20.0',
            'gpu_percent': 'N/A',
            'gpu_memory_percent': 'N/A',
            'alerts': '0',
        }])
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]['network_collection_ms'])


if __name__ == '__main__':
    unittest.main()
