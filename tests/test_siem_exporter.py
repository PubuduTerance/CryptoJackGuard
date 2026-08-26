import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.storage import alert_logger
from src.storage.siem_exporter import (
    FACILITY_LOCAL0,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    export_to_siem,
    format_siem_event,
)


class TestSIEMExporter(unittest.TestCase):
    def setUp(self):
        self.sample_alert = {
            "pid": 4321,
            "name": "xmrig.exe",
            "path": "C:\\tools\\xmrig.exe",
            "cmdline": "xmrig.exe --user wallet123 --pass secretToken",
            "score": 88.5,
            "risk_score": 88.5,
            "reasons": ["High sustained CPU", "Stratum network connection"],
            "timestamp": "2026-08-26T04:00:00Z",
        }

    def test_format_siem_event_json(self):
        raw_json = format_siem_event(self.sample_alert, rfc5424=False)
        data = json.loads(raw_json)

        self.assertEqual(data["event_type"], "CRYPTOJACKING_ALERT")
        self.assertEqual(data["source_app"], "CryptoJackGuard")
        self.assertEqual(data["pid"], 4321)
        self.assertEqual(data["name"], "xmrig.exe")
        self.assertEqual(data["score"], 88.5)
        self.assertEqual(data["severity"], "CRITICAL")
        self.assertEqual(data["severity_code"], SEVERITY_CRITICAL)
        self.assertEqual(data["facility"], FACILITY_LOCAL0)
        self.assertIn("High sustained CPU", data["reasons"])
        # Ensure command line credentials are redacted
        self.assertNotIn("secretToken", data["cmdline"])
        self.assertIn("<redacted>", data["cmdline"])

    def test_format_siem_event_response_action(self):
        action_alert = {
            "pid": 9999,
            "name": "miner.exe",
            "path": "C:\\miner.exe",
            "cmdline": "miner.exe",
            "score": 95.0,
            "reasons": ["High CPU"],
            "response_action": "Terminated",
        }
        raw_json = format_siem_event(action_alert, rfc5424=False)
        data = json.loads(raw_json)

        self.assertEqual(data["event_type"], "CRYPTOJACKING_RESPONSE_ACTION")
        self.assertEqual(data["response_action"], "Terminated")

    def test_format_siem_event_rfc5424_syslog_framing(self):
        syslog_msg = format_siem_event(self.sample_alert, rfc5424=True)
        self.assertTrue(syslog_msg.startswith("<"))
        self.assertIn(">1 ", syslog_msg)
        self.assertIn("CryptoJackGuard 4321 ID-CRYPTOJACKING_ALERT", syslog_msg)
        self.assertIn('"score": 88.5', syslog_msg)

    @patch("socket.socket")
    def test_export_to_siem_udp(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        result = export_to_siem(
            alert_record=self.sample_alert,
            syslog_host="10.0.0.50",
            port=514,
            protocol="udp",
        )

        self.assertTrue(result)
        mock_socket_class.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
        mock_sock.sendto.assert_called_once()
        args, kwargs = mock_sock.sendto.call_args
        payload_bytes, target_addr = args
        self.assertEqual(target_addr, ("10.0.0.50", 514))
        self.assertIn(b"CryptoJackGuard", payload_bytes)

    @patch("socket.socket")
    def test_export_to_siem_tcp(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        result = export_to_siem(
            alert_record=self.sample_alert,
            syslog_host="10.0.0.50",
            port=6514,
            protocol="tcp",
        )

        self.assertTrue(result)
        mock_socket_class.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock.connect.assert_called_once_with(("10.0.0.50", 6514))
        mock_sock.sendall.assert_called_once()
        args, kwargs = mock_sock.sendall.call_args
        self.assertTrue(args[0].endswith(b"\n"))

    @patch("socket.socket")
    def test_export_to_siem_socket_error_resilience(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = socket.error("Network unreachable")
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        # Should safely return False and not raise exceptions
        result = export_to_siem(
            alert_record=self.sample_alert,
            syslog_host="192.0.2.1",
            port=514,
            protocol="udp",
        )
        self.assertFalse(result)

    def test_export_to_siem_empty_record(self):
        result = export_to_siem({})
        self.assertFalse(result)


class TestAlertLoggerSIEMIntegration(unittest.TestCase):
    def test_log_alert_triggers_siem_in_enterprise_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_log = Path(temp_dir) / "alerts.jsonl"
            orig_path = alert_logger.ALERTS_LOG_PATH
            alert_logger.ALERTS_LOG_PATH = temp_log

            try:
                with patch("src.storage.alert_logger.export_to_siem") as mock_siem, \
                     patch("src.storage.alert_logger._load_config", return_value={"enterprise_mode": True, "siem_host": "127.0.0.1", "siem_port": 514}):

                    # 1. High risk alert (score >= 60) -> Should export
                    alert = {
                        "pid": 5555,
                        "name": "xmrig.exe",
                        "score": 75.0,
                        "reasons": ["mining signature"],
                    }
                    success = alert_logger.log_alert(alert)
                    self.assertTrue(success)
                    mock_siem.assert_called_once()
                    self.assertEqual(mock_siem.call_args[1]["syslog_host"], "127.0.0.1")
                    self.assertEqual(mock_siem.call_args[1]["port"], 514)

                with patch("src.storage.alert_logger.export_to_siem") as mock_siem, \
                     patch("src.storage.alert_logger._load_config", return_value={"enterprise_mode": True, "siem_host": "127.0.0.1", "siem_port": 514}):

                    # 2. Low risk alert (score < 60) without response action -> Should NOT export
                    low_alert = {
                        "pid": 1234,
                        "name": "calc.exe",
                        "score": 25.0,
                        "reasons": ["minor spike"],
                    }
                    alert_logger.log_alert(low_alert)
                    mock_siem.assert_not_called()

                with patch("src.storage.alert_logger.export_to_siem") as mock_siem, \
                     patch("src.storage.alert_logger._load_config", return_value={"enterprise_mode": True, "siem_host": "127.0.0.1", "siem_port": 514}):

                    # 3. Response action executed -> Should export regardless of score
                    action_alert = {
                        "pid": 7777,
                        "name": "bad.exe",
                        "response_action": "Terminated",
                        "score": 50.0,
                    }
                    alert_logger.log_alert(action_alert)
                    mock_siem.assert_called_once()

            finally:
                alert_logger.ALERTS_LOG_PATH = orig_path

    def test_log_alert_explicit_siem_override(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_log = Path(temp_dir) / "alerts.jsonl"
            orig_path = alert_logger.ALERTS_LOG_PATH
            alert_logger.ALERTS_LOG_PATH = temp_log

            try:
                with patch("src.storage.alert_logger.export_to_siem") as mock_siem, \
                     patch("src.storage.alert_logger._load_config", return_value={"enterprise_mode": False}):

                    # Explicit siem_export=True overrides enterprise_mode=False
                    alert_logger.log_alert(
                        {"pid": 1111, "name": "app.exe", "score": 20.0},
                        siem_export=True,
                        siem_host="siem.corp.internal",
                        siem_port=5514,
                    )
                    mock_siem.assert_called_once()
                    self.assertEqual(mock_siem.call_args[1]["syslog_host"], "siem.corp.internal")
                    self.assertEqual(mock_siem.call_args[1]["port"], 5514)

            finally:
                alert_logger.ALERTS_LOG_PATH = orig_path


if __name__ == "__main__":
    unittest.main()
