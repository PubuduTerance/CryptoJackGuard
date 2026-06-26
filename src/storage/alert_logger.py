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


def log_scan_metrics(metrics: Dict[str, Any]) -> None:
    ensure_logs_dir()
    record = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        **metrics,
    }
    try:
        file_exists = SYSTEM_METRICS_PATH.exists()
        with SYSTEM_METRICS_PATH.open('a', encoding='utf-8', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=SYSTEM_METRICS_FIELDS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(record)
    except OSError:
        pass
