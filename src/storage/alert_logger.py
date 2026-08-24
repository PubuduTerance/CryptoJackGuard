from __future__ import annotations
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from src.privacy.redaction import redact_command_line

ALERTS_LOG_PATH = Path('logs') / 'alerts.jsonl'
SYSTEM_METRICS_PATH = Path('logs') / 'system_metrics.csv'
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


def log_alert(alert: Dict[str, Any]) -> bool:
    """Append one alert and return whether persistence succeeded."""
    alert_record = {
        'timestamp': _utc_timestamp(),
        **alert,
    }
    if isinstance(alert_record.get('cmdline'), str):
        alert_record['cmdline'] = redact_command_line(alert_record['cmdline'])

    try:
        ensure_logs_dir()
        with ALERTS_LOG_PATH.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(alert_record, ensure_ascii=False) + '\n')
    except OSError as exc:
        print(f'Warning: failed to write alert log: {exc}', file=sys.stderr)
        return False
    return True


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
