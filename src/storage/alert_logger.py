from __future__ import annotations
import csv
import json
from pathlib import Path
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import requests

from src.privacy.redaction import redact_command_line
from src.storage.siem_exporter import export_to_siem

ALERTS_LOG_PATH = Path('logs') / 'alerts.jsonl'
SYSTEM_METRICS_PATH = Path('logs') / 'system_metrics.csv'
CONFIG_PATH = Path('config.json')

SYSTEM_METRICS_FIELDS = [
    'timestamp',
    'cpu_percent',
    'memory_percent',
    'gpu_percent',
    'gpu_memory_percent',
    'processes_scanned',
    'alerts',
    'scan_duration_ms',
    'resource_collection_ms',
    'process_collection_ms',
    'network_collection_ms',
    'scoring_anomaly_ms',
    'persistence_inspection_ms',
    'osint_refresh_ms',
]


def ensure_logs_dir() -> None:
    ALERTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _load_config() -> Dict[str, Any]:
    """Load configuration settings safely."""
    target_path = CONFIG_PATH if CONFIG_PATH.exists() else (PROJECT_ROOT / 'config.json')
    if not target_path.exists():
        return {}
    try:
        with target_path.open('r', encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def log_alert(
    alert: Dict[str, Any],
    siem_export: Optional[bool] = None,
    siem_host: Optional[str] = None,
    siem_port: Optional[int] = None,
    siem_protocol: Optional[str] = None,
) -> bool:
    """Append one alert and return whether persistence succeeded.

    Optionally forwards high-severity alerts and response actions to an enterprise SIEM/Syslog server
    when enterprise_mode is active or siem_export is True.

    Args:
        alert: Alert data dictionary.
        siem_export: Optional explicit boolean flag to enable/disable SIEM forwarding.
        siem_host: Optional SIEM server hostname/IP override.
        siem_port: Optional SIEM server port override.
        siem_protocol: Optional transport protocol override ('udp' or 'tcp').

    Returns:
        True if local file logging succeeded, False otherwise.
    """
    alert_record = {
        'timestamp': _utc_timestamp(),
        **alert,
    }
    if isinstance(alert_record.get('cmdline'), str):
        alert_record['cmdline'] = redact_command_line(alert_record['cmdline'])

    file_success = False
    try:
        ensure_logs_dir()
        with ALERTS_LOG_PATH.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(alert_record, ensure_ascii=False) + '\n')
        file_success = True
    except OSError as exc:
        print(f'Warning: failed to write alert log: {exc}', file=sys.stderr)
        return False

    # Handle Centralized SIEM / Syslog Alerting
    try:
        cfg = _load_config()
        enterprise_enabled = bool(cfg.get('enterprise_mode', False))
        resolved_host = siem_host or str(cfg.get('siem_host', '127.0.0.1'))
        resolved_port = int(siem_port or cfg.get('siem_port', 514))
        resolved_proto = str(siem_protocol or cfg.get('siem_protocol', 'udp'))

        # Forward to Central FastAPI Cloud Backend if enterprise_mode and api_base_url configured
        api_base_url = str(cfg.get('api_base_url') or '').strip().rstrip('/')
        if enterprise_enabled and api_base_url:
            try:
                requests.post(
                    f"{api_base_url}/api/alerts",
                    json=alert_record,
                    timeout=2.5,
                )
            except requests.exceptions.RequestException as req_exc:
                print(f"Warning: Cloud API alert dispatch failed ({api_base_url}): {req_exc}", file=sys.stderr)
            except Exception as api_exc:
                print(f"Warning: Unexpected error dispatching alert to Cloud API: {api_exc}", file=sys.stderr)

        # Determine whether to forward to SIEM
        should_export = False
        if siem_export is True:
            should_export = True
        elif siem_export is None and enterprise_enabled:
            score = float(alert_record.get('score') or alert_record.get('risk_score') or 0.0)
            has_action = bool(alert_record.get('response_action'))
            # Export confirmed high-severity alerts (score >= 60.0) or executed response actions
            if score >= 60.0 or has_action or alert_record.get('confirmed') or alert_record.get('sustained_cycles', 0) >= 1:
                should_export = True

        if should_export:
            export_to_siem(
                alert_record=alert_record,
                syslog_host=resolved_host,
                port=resolved_port,
                protocol=resolved_proto,
            )
    except Exception as exc:
        # Never crash or fail local logging due to SIEM or API export issues
        print(f'Warning: Alert dispatch error: {exc}', file=sys.stderr)

    return file_success


def _normalize_metrics_row(metrics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'timestamp': _utc_timestamp(),
        'cpu_percent': metrics.get('cpu_percent', ''),
        'memory_percent': metrics.get('memory_percent', ''),
        'gpu_percent': 'N/A' if metrics.get('gpu_percent') is None else metrics.get('gpu_percent', ''),
        'gpu_memory_percent': 'N/A' if metrics.get('gpu_memory_percent') is None else metrics.get('gpu_memory_percent', ''),
        'processes_scanned': metrics.get('processes_scanned', ''),
        'alerts': metrics.get('alerts', ''),
        'scan_duration_ms': metrics.get('scan_duration_ms', ''),
        'resource_collection_ms': metrics.get('resource_collection_ms', ''),
        'process_collection_ms': metrics.get('process_collection_ms', ''),
        'network_collection_ms': metrics.get('network_collection_ms', ''),
        'scoring_anomaly_ms': metrics.get('scoring_anomaly_ms', ''),
        'persistence_inspection_ms': metrics.get('persistence_inspection_ms', ''),
        'osint_refresh_ms': metrics.get('osint_refresh_ms', ''),
    }


def _existing_system_metrics_fields() -> list[str]:
    """Keep existing historical CSV headers intact instead of rewriting logs."""
    if not SYSTEM_METRICS_PATH.exists():
        return SYSTEM_METRICS_FIELDS
    try:
        with SYSTEM_METRICS_PATH.open('r', encoding='utf-8', newline='') as handle:
            header = next(csv.reader(handle), None)
    except OSError:
        return SYSTEM_METRICS_FIELDS
    return header or SYSTEM_METRICS_FIELDS


def log_scan_metrics(metrics: Dict[str, Any]) -> None:
    ensure_logs_dir()
    record = _normalize_metrics_row(metrics)
    try:
        file_exists = SYSTEM_METRICS_PATH.exists()
        fieldnames = _existing_system_metrics_fields() if file_exists else SYSTEM_METRICS_FIELDS
        with SYSTEM_METRICS_PATH.open('a', encoding='utf-8', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow({field: record.get(field, '') for field in fieldnames})
    except OSError:
        pass
