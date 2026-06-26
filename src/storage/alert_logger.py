from __future__ import annotations
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


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
]


def ensure_logs_dir() -> None:
    ALERTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def log_alert(alert: Dict[str, Any]) -> None:
    ensure_logs_dir()
    alert_record = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        **alert,
    }
    try:
        with ALERTS_LOG_PATH.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(alert_record, ensure_ascii=False) + '\n')
    except OSError:
        pass


def _normalize_metrics_row(metrics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'cpu_percent': metrics.get('cpu_percent', ''),
        'memory_percent': metrics.get('memory_percent', ''),
        'gpu_percent': 'N/A' if metrics.get('gpu_percent') is None else metrics.get('gpu_percent', ''),
        'gpu_memory_percent': 'N/A' if metrics.get('gpu_memory_percent') is None else metrics.get('gpu_memory_percent', ''),
        'processes_scanned': metrics.get('processes_scanned', ''),
        'alerts': metrics.get('alerts', ''),
        'scan_duration_ms': metrics.get('scan_duration_ms', ''),
    }


def _ensure_system_metrics_header() -> None:
    if not SYSTEM_METRICS_PATH.exists():
        return

    try:
        with SYSTEM_METRICS_PATH.open('r', encoding='utf-8', newline='') as handle:
            reader = csv.reader(handle)
            existing_header = next(reader, None)
    except OSError:
        return

    if existing_header == SYSTEM_METRICS_FIELDS:
        return

    try:
        with SYSTEM_METRICS_PATH.open('r', encoding='utf-8', newline='') as handle:
            rows = list(csv.DictReader(handle))
    except OSError:
        rows = []

    try:
        with SYSTEM_METRICS_PATH.open('w', encoding='utf-8', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=SYSTEM_METRICS_FIELDS)
            writer.writeheader()
            for row in rows:
                normalized_row = {
                    field: row.get(field, 'N/A' if field.startswith('gpu_') else '')
                    for field in SYSTEM_METRICS_FIELDS
                }
                writer.writerow(normalized_row)
    except OSError:
        pass


def log_scan_metrics(metrics: Dict[str, Any]) -> None:
    ensure_logs_dir()
    record = _normalize_metrics_row(metrics)
    _ensure_system_metrics_header()
    try:
        file_exists = SYSTEM_METRICS_PATH.exists()
        with SYSTEM_METRICS_PATH.open('a', encoding='utf-8', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=SYSTEM_METRICS_FIELDS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(record)
    except OSError:
        pass
