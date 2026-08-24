from __future__ import annotations
import argparse
import json
from pathlib import Path
from time import perf_counter, sleep
from typing import Dict, Any

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

from src.collectors.network_collector import collect_network_info
from src.collectors.persistence_collector import PersistenceInspectionCache, apply_persistence_findings
from src.collectors.process_collector import collect_processes
from src.collectors.resource_collector import collect_resource_snapshot
from src.detection.alert_lifecycle import AlertLifecycle, build_alert_record
from src.detection.anomaly import ProcessAnomalyDetector, apply_anomaly_signal
from src.detection.scoring import score_process
from src.intelligence.network_ioc import NetworkIOCMatcher, load_network_indicators
from src.intelligence.osint_loader import load_mining_indicators, load_allowlisted_processes
from src.monitoring.timing import build_scan_timings
from src.privacy.redaction import redact_command_line
from src.response.actions import is_protected_process, terminate_process
from src.storage.alert_logger import log_alert, log_scan_metrics


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


def find_alerts(scores, threshold):
    return [score for score in scores if score.risk_score >= threshold]


def confirm_termination(score, console: Console, live) -> bool:
    live.stop()
    console.print('\n[bold yellow]Safe response mode:[/bold yellow] high-risk process detected')
    console.print(f'  PID: {score.pid}')
    console.print(f'  Name: {score.name}')
    console.print(f'  Path: {score.path or "N/A"}')
    console.print(f'  Command line: {redact_command_line(score.cmdline) or "N/A"}')
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
    deep_inspection_threshold = float(config.get('deep_inspection_threshold', 40.0))
    persistence_cache_seconds = float(config.get('persistence_cache_seconds', 300.0))
    alert_lifecycle = AlertLifecycle(alert_threshold, sustained_cycles)
    persistence_inspector = PersistenceInspectionCache(persistence_cache_seconds)
    anomaly_detector = ProcessAnomalyDetector(
        window_size=int(config.get('anomaly_window_size', 12)),
        min_samples=int(config.get('anomaly_min_samples', 5)),
        z_threshold=float(config.get('anomaly_z_threshold', 3.0)),
        max_identities=int(config.get('anomaly_max_identities', 500)),
        min_cpu_delta=float(config.get('anomaly_min_cpu_delta', 15.0)),
        min_memory_delta=float(config.get('anomaly_min_memory_delta', 5.0)),
    )
    network_ips, network_domains = load_network_indicators(str(DATA_DIR / 'mining_network_iocs.txt'))
    network_ioc_matcher = NetworkIOCMatcher(
        network_ips,
        network_domains,
        cache_seconds=float(config.get('osint_dns_cache_seconds', 3600.0)),
        dns_timeout_seconds=float(config.get('osint_dns_timeout_seconds', 1.0)),
    )

    try:
        with Live(console=console, refresh_per_second=4) as live:
            while True:
                scan_start = perf_counter()
                resource_start = perf_counter()
                resource = collect_resource_snapshot()
                resource_collection_ms = (perf_counter() - resource_start) * 1000.0
                process_start = perf_counter()
                processes = collect_processes()
                process_collection_ms = (perf_counter() - process_start) * 1000.0
                network_start = perf_counter()
                network_data = collect_network_info()
                network_collection_ms = (perf_counter() - network_start) * 1000.0
                osint_refresh_info = network_ioc_matcher.refresh()

                scoring_start = perf_counter()
                scored = [
                    score_process(proc, network_data.get(proc.pid), indicators, config, network_ioc_matcher)
                    for proc in processes
                ]
                if bool(config.get('anomaly_enabled', True)):
                    anomaly_max_score = float(config.get('anomaly_max_score', 8.0))
                    for score in scored:
                        apply_anomaly_signal(score, anomaly_detector.observe(score), anomaly_max_score)
                scoring_anomaly_ms = (perf_counter() - scoring_start) * 1000.0
                persistence_start = perf_counter()
                persistence_result = persistence_inspector.inspect_if_triggered(
                    scored,
                    deep_inspection_threshold,
                    indicators,
                    config.get('suspicious_cmd_indicators', []),
                )
                apply_persistence_findings(scored, persistence_result.findings)
                persistence_inspection_ms = (perf_counter() - persistence_start) * 1000.0
                scored.sort(key=lambda item: item.risk_score, reverse=True)

                scan_duration_ms = (perf_counter() - scan_start) * 1000.0
                timings = build_scan_timings(
                    resource_collection_ms=resource_collection_ms,
                    process_collection_ms=process_collection_ms,
                    network_collection_ms=network_collection_ms,
                    scoring_anomaly_ms=scoring_anomaly_ms,
                    persistence_inspection_ms=persistence_inspection_ms,
                    osint_refresh_ms=osint_refresh_info.duration_ms,
                    scan_duration_ms=scan_duration_ms,
                )
                newly_confirmed_alerts = alert_lifecycle.update(scored)
                for score in newly_confirmed_alerts:
                    log_alert(build_alert_record(score, alert_lifecycle.sustained_cycles))

                    if args.respond:
                        if is_protected_process(score.pid, score.name):
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
                            termination_result = terminate_process(score.pid, score.name)
                            if termination_result.success:
                                console.print(f'[bold green]Process {score.pid} terminated successfully.[/bold green]')
                            else:
                                console.print(f'[bold yellow]Process {score.pid} was not terminated: {termination_result.status}.[/bold yellow]')
                            log_alert({
                                'response_action': termination_result.status,
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
                    **{name: round(value, 1) for name, value in timings.items()},
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
