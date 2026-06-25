from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any


ALERTS_LOG_PATH = Path('logs') / 'alerts.jsonl'


def ensure_alerts_dir() -> None:
    ALERTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def log_alert(alert: Dict[str, Any]) -> None:
    ensure_alerts_dir()
    alert_record = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        **alert,
    }
    try:
        with ALERTS_LOG_PATH.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(alert_record, ensure_ascii=False) + '\n')
    except OSError:
        pass
