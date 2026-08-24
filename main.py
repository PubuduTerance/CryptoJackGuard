from __future__ import annotations
import argparse
import json
from pathlib import Path
from time import monotonic, sleep
from typing import Dict, Any

import psutil
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

from src.collectors.network_collector import collect_network_info
from src.collectors.process_collector import collect_processes
from src.collectors.resource_collector import collect_resource_snapshot
from src.detection.alert_lifecycle import AlertLifecycle, build_alert_record
from src.detection.scoring import score_process
from src.intelligence.osint_loader import load_mining_indicators, load_allowlisted_processes
from src.storage.alert_logger import log_alert, log_scan_metrics
from src.response.actions import action_description, list_safe_action_options


CONFIG_PATH = Path('config.json')
DATA_DIR = Path('data')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='CryptoJackGuard defensive monitoring tool')
    parser.add_argument(
        '--respond',
        action='store_true',
        help='Enable safe response mode and ask before terminating high-risk processes',
    )
    return parser.parse_args()


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}

    try:
        with CONFIG_PATH.open('r', encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}


def build_dashboard(resource, top_scores, indicators, allowlist_count) -> Panel:
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
    if hasattr(resource, 'available_mb'):
        resource_text.append(f'Avail: {resource.available_mb:.0f} MB\n')
    else:
        resource_text.append('Avail: N/A\n')
    if resource.gpu_percent is not None:
        resource_text.append(f'GPU: {resource.gpu_percent:.1f}%  GPU Mem: {resource.gpu_memory_percent:.1f}%\n')
    else:
        resource_text.append('GPU: N/A  GPU Mem: N/A\n')

    indicator_text = Text(f'Loaded indicators: {len(indicators)} entries')
    indicator_panel = Panel(indicator_text, title='OSINT Indicators', border_style='green')
    allowlist_text = Text(f'Allowlisted processes: {allowlist_count}')
    allowlist_panel = Panel(allowlist_text, title='Process Allowlist', border_style='cyan')
    dashboard = Panel(
        table,
        title='CryptoJackGuard MVP',
        subtitle='Press Ctrl+C to exit',
        border_style='blue',
    )
    return Panel(Group(resource_text, indicator_panel, allowlist_panel, dashboard), title='CryptoJackGuard Status')


CRITICAL_PROCESS_NAMES = {
    'explorer.exe',
    'svchost.exe',
    'wininit.exe',
    'services.exe',
    'lsass.exe',
    'csrss.exe',
    'smss.exe',
    'winlogon.exe',
    'code.exe',
    'chrome.exe',
    'msedge.exe',
}
CRITICAL_PROCESS_PIDS = {0, 4}


def find_alerts(scores, threshold):
    return [score for score in scores if score.risk_score >= threshold]


def is_critical_process(score) -> bool:
    return score.pid in CRITICAL_PROCESS_PIDS or score.name.lower() in CRITICAL_PROCESS_NAMES


def confirm_termination(score, console: Console, live) -> bool:
    live.stop()
    console.print('\n[bold yellow]Safe response mode:[/bold yellow] high-risk process detected')
    console.print(f'  PID: {score.pid}')
    console.print(f'  Name: {score.name}')
    console.print(f'  Path: {score.path or "N/A"}')
    console.print(f'  Score: {score.risk_score:.1f}')
    reasons_text = ', '.join(score.reasons) if score.reasons else 'None'
    console.print(f'  Reasons: {reasons_text}')
    try:
        answer = input("Type 'yes' to terminate this process, or anything else to keep it: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print('[bold red]No response received. Keeping process.[/bold red]')
        live.start()
        return False
    live.start()
    return answer == 'yes'


def terminate_process(score, console: Console) -> tuple[bool, str]:
    try:
        proc = psutil.Process(score.pid)
        proc.terminate()
        proc.wait(timeout=5)
        console.print(f'[bold green]Process {score.pid} terminated successfully.[/bold green]')
        return True, 'terminated'
    except psutil.NoSuchProcess:
        console.print(f'[bold yellow]Process {score.pid} no longer exists.[/bold yellow]')
        return False, 'no such process'
    except psutil.AccessDenied:
        console.print(f'[bold red]Access denied when terminating process {score.pid}.[/bold red]')
        return False, 'access denied'
    except psutil.TimeoutExpired:
        console.print(f'[bold yellow]Termination timed out for process {score.pid}.[/bold yellow]')
        return False, 'timeout expired'
    except Exception as exc:
        console.print(f'[bold red]Failed to terminate process {score.pid}: {exc}[/bold red]')
        return False, str(exc)


def main() -> int:
    console = Console()
    args = parse_args()
    config = load_config()
    indicators = load_mining_indicators(DATA_DIR / 'mining_iocs.txt')
    allowlist_names = load_allowlisted_processes(DATA_DIR / 'allowlist_processes.txt')
    config['allowlist_process_names'] = list(allowlist_names)
    alert_threshold = float(config.get('alert_threshold', 60.0))
    refresh_interval = float(config.get('refresh_interval', 3.0))
    sustained_cycles = int(config.get('sustained_cycles', 2))
    alert_lifecycle = AlertLifecycle(alert_threshold, sustained_cycles)

    try:
        with Live(console=console, refresh_per_second=4) as live:
            while True:
                scan_start = monotonic()
                resource = collect_resource_snapshot()
                processes = collect_processes()
                network_data = collect_network_info()

                scored = [
                    score_process(proc, network_data.get(proc.pid), indicators, config)
                    for proc in processes
                ]
                scored.sort(key=lambda item: item.risk_score, reverse=True)

                scan_duration_ms = (monotonic() - scan_start) * 1000.0
                newly_confirmed_alerts = alert_lifecycle.update(scored)
                for score in newly_confirmed_alerts:
                    log_alert(build_alert_record(score, alert_lifecycle.sustained_cycles))

                    if args.respond:
                        if is_critical_process(score):
                            console.print(f'[bold yellow]Protected process detected: {score.name} (PID {score.pid}). Not terminating.[/bold yellow]')
                            log_alert({
                                'response_action': 'protected process - no termination',
                                'pid': score.pid,
                                'name': score.name,
                                'path': score.path,
                                'score': score.risk_score,
                                'reasons': score.reasons,
                            })
                        elif confirm_termination(score, console, live):
                            terminated, reason = terminate_process(score, console)
                            log_alert({
                                'response_action': reason,
                                'pid': score.pid,
                                'name': score.name,
                                'path': score.path,
                                'score': score.risk_score,
                                'reasons': score.reasons,
                            })
                        else:
                            log_alert({
                                'response_action': 'user declined termination',
                                'pid': score.pid,
                                'name': score.name,
                                'path': score.path,
                                'score': score.risk_score,
                                'reasons': score.reasons,
                            })

                # Metrics count alerts confirmed in this scan, not raw threshold crossings.
                confirmed_alert_count = len(newly_confirmed_alerts)
                log_scan_metrics({
                    'cpu_percent': resource.cpu_percent,
                    'memory_percent': resource.memory_percent,
                    'gpu_percent': resource.gpu_percent,
                    'gpu_memory_percent': resource.gpu_memory_percent,
                    'processes_scanned': len(processes),
                    'alerts': confirmed_alert_count,
                    'scan_duration_ms': round(scan_duration_ms, 1),
                })

                top_scores = [score for score in scored if score.risk_score >= alert_threshold][:20]
                allowlist_count = sum(1 for score in scored if score.allowlisted)
                dashboard = build_dashboard(resource, top_scores, indicators, allowlist_count)
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
