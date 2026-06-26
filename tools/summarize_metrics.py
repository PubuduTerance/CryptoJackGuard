"""Evaluate CryptoJackGuard scan metric logs.

This script reads logs/system_metrics.csv and prints a concise summary of
scan cycles, average CPU/memory usage, scan timing, and alert counts.
"""

from __future__ import annotations
import csv
from pathlib import Path
from typing import Any

LOG_PATH = Path('logs') / 'system_metrics.csv'


def parse_float(value: str) -> float | None:
    if not value or value.strip().upper() == 'N/A':
        return None
    try:
        return float(value)
    except ValueError:
        return None


def main() -> int:
    if not LOG_PATH.exists():
        print(f'No metrics log found at {LOG_PATH}.')
        return 1

    total_cycles = 0
    cpu_sum = 0.0
    memory_sum = 0.0
    duration_sum = 0.0
    max_duration = 0.0
    total_alerts = 0

    with LOG_PATH.open('r', encoding='utf-8', newline='') as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            total_cycles += 1
            cpu = parse_float(row.get('cpu_percent', ''))
            memory = parse_float(row.get('memory_percent', ''))
            duration = parse_float(row.get('scan_duration_ms', ''))
            alerts = row.get('alerts', '').strip()

            if cpu is not None:
                cpu_sum += cpu
            if memory is not None:
                memory_sum += memory
            if duration is not None:
                duration_sum += duration
                if duration > max_duration:
                    max_duration = duration
            try:
                total_alerts += int(alerts) if alerts else 0
            except ValueError:
                pass

    if total_cycles == 0:
        print('No scan records found in system_metrics.csv.')
        return 1

    avg_cpu = cpu_sum / total_cycles
    avg_memory = memory_sum / total_cycles
    avg_duration = duration_sum / total_cycles

    print('CryptoJackGuard Evaluation Summary')
    print('----------------------------------')
    print(f'Total scan cycles: {total_cycles}')
    print(f'Average CPU percent: {avg_cpu:.2f}%')
    print(f'Average memory percent: {avg_memory:.2f}%')
    print(f'Average scan duration: {avg_duration:.1f} ms')
    print(f'Maximum scan duration: {max_duration:.1f} ms')
    print(f'Total alerts: {total_alerts}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
