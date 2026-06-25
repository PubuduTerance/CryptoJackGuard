from __future__ import annotations
import json
import sys
from pathlib import Path
from time import sleep
from typing import Dict, Any

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

from src.collectors.network_collector import collect_network_info
from src.collectors.process_collector import collect_processes
from src.collectors.resource_collector import collect_resource_snapshot
from src.detection.scoring import score_process
from src.intelligence.osint_loader import load_mining_indicators
from src.storage.alert_logger import log_alert
from src.response.actions import action_description, list_safe_action_options


CONFIG_PATH = Path('config.json')
DATA_DIR = Path('data')


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}

    try:
        with CONFIG_PATH.open('r', encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def build_dashboard(resource, top_scores, indicators) -> Panel:
    table = Table(title='CryptoJackGuard Process Risk Dashboard', expand=True)
    table.add_column('PID', justify='right')
    table.add_column('Name')
    table.add_column('CPU %', justify='right')
    table.add_column('Mem %', justify='right')
    table.add_column('Score', justify='right')
    table.add_column('Reasons')

    for score in top_scores:
        table.add_row(
            str(score.pid),
            score.name,
            f'{score.cpu_percent:.1f}',
            f'{score.memory_percent:.1f}',
            f'{score.risk_score:.1f}',
            ', '.join(score.reasons),
        )

    resource_text = Text()
    resource_text.append(f'CPU: {resource.cpu_percent:.1f}%  ')
    resource_text.append(f'Memory: {resource.memory_percent:.1f}%  ')
    resource_text.append(f'Avail: {resource.available_mb:.0f} MB\n')
    if resource.gpu_percent is not None:
        resource_text.append(f'GPU: {resource.gpu_percent:.1f}%  GPU Mem: {resource.gpu_memory_percent:.1f}%\n')

    indicator_text = Text(f'Loaded indicators: {len(indicators)} entries')
    indicator_panel = Panel(indicator_text, title='OSINT Indicators', border_style='green')
    dashboard = Panel(
        table,
        title='CryptoJackGuard MVP',
        subtitle='Press Ctrl+C to exit',
        border_style='blue',
    )
    return Panel(Group(resource_text, indicator_panel, dashboard), title='CryptoJackGuard Status')


def find_alerts(scores, threshold):
    return [score for score in scores if score.risk_score >= threshold]


def main() -> int:
    console = Console()
    config = load_config()
    indicators = load_mining_indicators(DATA_DIR / 'mining_iocs.txt')
    alert_threshold = float(config.get('alert_threshold', 60.0))
    refresh_interval = float(config.get('refresh_interval', 3.0))
    sustained_cycles = int(config.get('sustained_cycles', 2))

    alert_history: Dict[str, int] = {}
    logged_alerts: set[str] = set()

    try:
        with Live(console=console, refresh_per_second=4) as live:
            while True:
                resource = collect_resource_snapshot()
                processes = collect_processes()
                network_data = collect_network_info()

                scored = [
                    score_process(proc, network_data.get(proc.pid), indicators, config)
                    for proc in processes
                ]
                scored.sort(key=lambda item: item.risk_score, reverse=True)

                current_keys: set[str] = set()
                for score in scored:
                    if score.risk_score >= alert_threshold:
                        key = f'{score.pid}:{score.path}:{score.cmdline}'
                        current_keys.add(key)
                        alert_history[key] = alert_history.get(key, 0) + 1
                        if alert_history[key] >= sustained_cycles and key not in logged_alerts:
                            log_alert({
                                'pid': score.pid,
                                'name': score.name,
                                'path': score.path,
                                'cmdline': score.cmdline,
                                'score': score.risk_score,
                                'reasons': score.reasons,
                                'sustained_cycles': alert_history[key],
                            })
                            logged_alerts.add(key)

                stale_keys = set(alert_history) - current_keys
                for stale in stale_keys:
                    alert_history.pop(stale, None)
                    logged_alerts.discard(stale)

                top_scores = [score for score in scored if score.risk_score >= alert_threshold][:20]
                dashboard = build_dashboard(resource, top_scores, indicators)
                live.update(dashboard)
                sleep(refresh_interval)
    except KeyboardInterrupt:
        console.print('\n[bold green]CryptoJackGuard stopped by user.[/bold green]')
        return 0
    except Exception as exc:
        console.print(f'[bold red]Unexpected error:[/bold red] {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
