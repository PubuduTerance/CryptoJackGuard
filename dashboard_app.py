from __future__ import annotations
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Union
from time import monotonic, perf_counter

import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh


def ensure_backend_is_running(api_base_url: str = "http://127.0.0.1:8000") -> None:
    """Detect if FastAPI backend is responsive, silently starting it in the background if offline."""
    url = f"{api_base_url.rstrip('/')}/api/status"
    try:
        resp = requests.get(url, timeout=1.0)
        if resp.status_code == 200:
            return
    except Exception:
        pass

    try:
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "src.backend.main:app", "--host", "127.0.0.1", "--port", "8000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
    except Exception as exc:
        print(f"Warning: Could not auto-start backend server: {exc}", file=sys.stderr)


from src.collectors.network_collector import collect_network_info
from src.collectors.persistence_collector import PersistenceInspectionCache, apply_persistence_findings
from src.collectors.process_collector import collect_processes
from src.collectors.resource_collector import collect_resource_snapshot
from src.detection.alert_lifecycle import AlertLifecycle, build_alert_record
from src.detection.anomaly import ProcessAnomalyDetector, apply_anomaly_signal
from src.detection.browser_behavior import BrowserBehaviorDetector, apply_browser_behavior_signal
from src.detection.ml_fusion import apply_ml_signal
from src.detection.scan_scheduler import should_run_dashboard_scan
from src.detection.scoring import score_process
from src.intelligence.network_ioc import NetworkIOCMatcher, load_network_indicators
from src.intelligence.osint_loader import load_mining_indicators, load_allowlisted_processes
from src.ml.model_registry import load_model
from src.monitoring.timing import build_scan_timings
from src.privacy.redaction import redact_command_line
from src.storage.alert_logger import log_alert, log_scan_metrics


LOG_DIR = Path('logs')
METRICS_LOG = LOG_DIR / 'system_metrics.csv'
ALERTS_LOG = LOG_DIR / 'alerts.jsonl'
CONFIG_PATH = Path('config.json')
DATA_DIR = Path('data')


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open('r', encoding='utf-8') as handle:
            return json.load(handle)
    except Exception:
        return {}


def parse_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
    try:
        if not value or str(value).upper() == 'N/A':
            return None
        return float(value)
    except (ValueError, TypeError):
        return None


def parse_int(value: Any) -> Optional[int]:
    parsed = parse_float(value)
    return None if parsed is None else int(parsed)


@st.cache_data
def load_metrics_history() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not METRICS_LOG.exists():
        return rows

    with METRICS_LOG.open('r', encoding='utf-8', newline='') as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(row)
    return rows


def _format_reasons(reasons: Any) -> str:
    if isinstance(reasons, list):
        return ', '.join(str(reason) for reason in reasons)
    if reasons:
        return str(reasons)
    return 'N/A'


def load_recent_alerts(
    limit: int = 10,
    token: Optional[str] = None,
    api_base_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []

    # 1. Fetch from Centralized Cloud FastAPI backend if authenticated
    if token:
        base_url = (api_base_url or "http://127.0.0.1:8000").rstrip("/")
        try:
            res = requests.get(
                f"{base_url}/api/alerts",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit},
                timeout=3.0,
            )
            if res.status_code == 200:
                raw_alerts = res.json().get("alerts", [])
                for record in raw_alerts:
                    details = record.get("details") or {}
                    alerts.append({
                        'Timestamp': record.get('timestamp', 'N/A'),
                        'PID': record.get('pid', 'N/A'),
                        'Name': record.get('process_name') or record.get('name', 'N/A'),
                        'Score': record.get('risk_score') or record.get('score', 'N/A'),
                        'Action': record.get('action_taken') or record.get('response_action') or 'alert',
                        'Path': details.get('path', 'N/A'),
                        'Reasons': _format_reasons(details.get('reasons') or record.get('reasons')),
                    })
                if alerts:
                    return alerts[:limit]
        except Exception:
            pass

    # 2. Fallback to local alerts.jsonl log
    if not ALERTS_LOG.exists():
        return alerts

    try:
        with ALERTS_LOG.open('r', encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                alerts.append({
                    'Timestamp': record.get('timestamp', 'N/A'),
                    'PID': record.get('pid', 'N/A'),
                    'Name': record.get('name', 'N/A'),
                    'Score': record.get('score', 'N/A'),
                    'Action': record.get('response_action') or 'alert',
                    'Path': record.get('path', 'N/A'),
                    'Reasons': _format_reasons(record.get('reasons')),
                })
    except OSError:
        return []

    alerts.sort(key=lambda item: item.get('Timestamp', ''), reverse=True)
    return alerts[:limit]


def build_metric_cards(
    resource: Any,
    alerts_count: int,
    last_scan_ms: float,
    processes_count: int,
    allowlist_count: int,
    timings: Optional[Dict[str, float]] = None,
) -> None:
    cpu_value = f'{resource.cpu_percent:.1f} %'
    memory_value = f'{resource.memory_percent:.1f} %'
    gpu_value = 'N/A' if resource.gpu_percent is None else f'{resource.gpu_percent:.1f} %'
    gpu_mem_value = 'N/A' if resource.gpu_memory_percent is None else f'{resource.gpu_memory_percent:.1f} %'
    last_scan_value = f'{last_scan_ms:.1f} ms' if last_scan_ms is not None else 'N/A'

    col1, col2, col3 = st.columns(3)
    col1.metric('CPU %', cpu_value)
    col2.metric('Memory %', memory_value)
    col3.metric('GPU %', gpu_value)

    col4, col5, col6 = st.columns(3)
    col4.metric('GPU memory %', gpu_mem_value)
    col5.metric('Processes scanned', processes_count)
    col6.metric('Allowlisted processes', allowlist_count)

    st.metric('Last scan duration', last_scan_value)
    if timings:
        st.caption(
            'Performance — '
            f"process: {timings.get('process_collection_ms', 0.0):.1f} ms, "
            f"network: {timings.get('network_collection_ms', 0.0):.1f} ms, "
            f"scoring: {timings.get('scoring_anomaly_ms', 0.0):.1f} ms"
        )


def risk_level(score: float) -> str:
    if score >= 80:
        return 'High'
    if score >= 60:
        return 'Medium'
    return 'Low'


def risk_color(level: str) -> str:
    return {
        'High': 'orange',
        'Medium': 'yellow',
        'Low': 'green',
    }.get(level, 'blue')


def format_process_rows(scores: List[Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for score in scores:
        level = risk_level(score.risk_score)
        ml_conf = getattr(score, 'ml_confidence', 0.0)
        rows.append(
            {
                'PID': score.pid,
                'Name': score.name,
                'CPU %': f'{score.cpu_percent:.1f}',
                'Memory %': f'{score.memory_percent:.1f}',
                'Score': f'{score.risk_score:.1f}',
                'ML Confidence': f'{ml_conf * 100.0:.1f}%',
                'Risk level': level,
                'Reasons': ', '.join(score.reasons),
                'Executable path': score.path or 'N/A',
            }
        )
    return rows


def parse_metrics_rows(metrics: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    parsed: List[Dict[str, Any]] = []
    for row in metrics:
        ts_text = row.get('timestamp', '')
        if not ts_text:
            continue
        try:
            timestamp = datetime.fromisoformat(ts_text.replace('Z', '+00:00'))
        except Exception:
            continue

        parsed.append({
            'timestamp': timestamp,
            'cpu_percent': parse_float(row.get('cpu_percent')),
            'memory_percent': parse_float(row.get('memory_percent')),
            'gpu_percent': parse_float(row.get('gpu_percent')),
            'gpu_memory_percent': parse_float(row.get('gpu_memory_percent')),
            'alerts': parse_int(row.get('alerts')),
            'resource_collection_ms': parse_float(row.get('resource_collection_ms')),
            'process_collection_ms': parse_float(row.get('process_collection_ms')),
            'network_collection_ms': parse_float(row.get('network_collection_ms')),
            'scoring_anomaly_ms': parse_float(row.get('scoring_anomaly_ms')),
            'persistence_inspection_ms': parse_float(row.get('persistence_inspection_ms')),
            'osint_refresh_ms': parse_float(row.get('osint_refresh_ms')),
        })

    parsed.sort(key=lambda item: item['timestamp'])
    return parsed


def filter_metrics_by_range(metrics: List[Dict[str, Any]], time_window: Optional[timedelta]) -> List[Dict[str, Any]]:
    if time_window is None or not metrics:
        return metrics[-100:]
    cutoff = datetime.now(timezone.utc) - time_window
    filtered = [row for row in metrics if row['timestamp'] >= cutoff]
    return filtered[-100:]


def insert_gaps(rows: List[Dict[str, Any]], field: str, max_gap: timedelta) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    previous_timestamp: Optional[datetime] = None
    for row in rows:
        if previous_timestamp is not None and row['timestamp'] - previous_timestamp > max_gap:
            result.append({'timestamp': row['timestamp'], field: None})
        result.append({'timestamp': row['timestamp'], field: row[field]})
        previous_timestamp = row['timestamp']
    return result


def build_metrics_chart(rows: List[Dict[str, Any]], field: str, title: str, y_label: str) -> bool:
    series = insert_gaps(rows, field, timedelta(minutes=2))
    valid_points = [item for item in series if item[field] is not None]
    if len(valid_points) < 2:
        return False
    fig = px.line(
        series,
        x='timestamp',
        y=field,
        title=title,
        labels={field: y_label},
        template='plotly_dark',
    )
    fig.update_layout(xaxis=dict(showspikes=True), yaxis=dict(showgrid=True))
    st.plotly_chart(fig, use_container_width=True)
    return True


def load_recent_metrics_summary(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {
        'last_scan_ms': 0.0,
        'alert_count': 0,
        'cpu_history': [],
        'memory_history': [],
        'gpu_history': [],
        'gpu_memory_history': [],
        'alert_history': [],
        'timestamps': [],
    }

    for row in metrics:
        ts_text = row.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts_text.replace('Z', '+00:00'))
        except Exception:
            continue
        summary['timestamps'].append(ts)
        summary['cpu_history'].append(parse_float(row.get('cpu_percent', '')))
        summary['memory_history'].append(parse_float(row.get('memory_percent', '')))
        summary['gpu_history'].append(parse_float(row.get('gpu_percent', '')))
        summary['gpu_memory_history'].append(parse_float(row.get('gpu_memory_percent', '')))
        summary['alert_history'].append(int(row.get('alerts', '0') or 0))
        duration = parse_float(row.get('scan_duration_ms', ''))
        if duration is not None:
            summary['last_scan_ms'] = duration

    summary['alert_count'] = summary['alert_history'][-1] if summary['alert_history'] else 0
    return summary


def _render_process_detail(score: Any, network_info: Any) -> None:
    st.markdown('### Selected process details')

    # Recommended action based on score.risk_score
    if score.risk_score >= 60.0:
        recommended_action = 'High Risk - User confirmation required for termination'
    elif score.risk_score >= 40.0:
        recommended_action = 'Medium Risk - Monitor closely'
    else:
        recommended_action = 'Low Risk - Safe'

    left, right = st.columns([1, 1])
    with left:
        st.markdown(f'- **PID:** {score.pid}')
        st.markdown(f'- **Name:** {score.name}')
        st.markdown(f'- **Executable path:** {score.path or "N/A"}')
        st.markdown(f'- **Parent PID:** {score.ppid if score.ppid is not None else "N/A"}')
        st.markdown(f'- **Parent process:** {score.parent_name or "N/A"}')
        st.markdown(f'- **Parent path:** {score.parent_path or "N/A"}')
        st.markdown(f'- **Command line:** {redact_command_line(score.cmdline) or "N/A"}')
        st.markdown(f'- **CPU %:** {score.cpu_percent:.1f}')
        st.markdown(f'- **Memory %:** {score.memory_percent:.1f}')
    with right:
        st.markdown(f'- **Recommended Action:** {recommended_action}')
        level = risk_level(score.risk_score)
        color = risk_color(level)
        st.markdown(f'- **Score:** {score.risk_score:.1f}')
        st.markdown(f'- **Risk level:** <span style="color:{color};font-weight:600">{level}</span>', unsafe_allow_html=True)
        st.markdown(f'- **Matched reasons:**')
        if score.reasons:
            for reason in score.reasons:
                st.markdown(f'  - {reason}')
        else:
            st.markdown('  - N/A')

    if score.allowlisted:
        st.markdown(f'- **Allowlist status:** Yes')
        if score.allowlist_notes:
            for note in score.allowlist_notes:
                st.markdown(f'  - {note}')

    if score.anomaly_sample_count:
        st.markdown(f'- **Baseline samples:** {score.anomaly_sample_count}')
        if score.anomaly_reasons:
            for reason in score.anomaly_reasons:
                st.markdown(f'  - {reason}')

    ml_conf = getattr(score, 'ml_confidence', 0.0)
    st.markdown('#### 🧠 Machine Learning Engine')
    st.markdown(f'- **ML Confidence:** {ml_conf * 100.0:.1f}%')
    if ml_conf >= 0.7:
        st.markdown('- **ML Classification:** High Cryptojacking Probability')
    elif ml_conf >= 0.4:
        st.markdown('- **ML Classification:** Moderate Suspicion')
    else:
        st.markdown('- **ML Classification:** Benign / Low Risk')

    browser_behavior = getattr(score, 'browser_behavior', None)
    if browser_behavior is not None:
        st.markdown('#### 🕵️ Browser Behavior')
        st.markdown(f'- **Browser process:** {"Yes" if browser_behavior.is_browser_process else "No"}')
        st.markdown(f'- **Sustained compute:** {"Yes" if browser_behavior.sustained_compute else "No"}')
        st.markdown(f'- **Browser mining suspicion:** {"Yes" if browser_behavior.browser_mining_suspicion else "No"}')
        if browser_behavior.reasons:
            for reason in browser_behavior.reasons:
                st.markdown(f'  - {reason}')

    if network_info:
        st.markdown('#### 🌐 Network Connections')
        if network_info.local_ports:
            st.markdown(f'- **Local ports:** {sorted(network_info.local_ports)}')
        if network_info.remote_addresses:
            st.markdown(f'- **Remote endpoints:**')
            for remote in sorted(network_info.remote_addresses):
                st.markdown(f'  - {remote}')
        if network_info.remote_ports:
            st.markdown(f'- **Remote ports:** {sorted(network_info.remote_ports)}')
        if network_info.statuses:
            st.markdown(f'- **Connection states:** {sorted(network_info.statuses)}')
        if not (network_info.local_ports or network_info.remote_addresses or network_info.remote_ports or network_info.statuses):
            st.markdown('- No network connections observed.')


def get_dashboard_alert_lifecycle(config: Dict[str, Any]) -> AlertLifecycle:
    """Keep alert confirmation state across normal Streamlit reruns."""
    try:
        alert_threshold = float(config.get('alert_threshold', 60.0))
    except (TypeError, ValueError):
        alert_threshold = 60.0
    try:
        sustained_cycles = int(config.get('sustained_cycles', 2))
    except (TypeError, ValueError):
        sustained_cycles = 2
    lifecycle = st.session_state.get('alert_lifecycle')

    if (
        not isinstance(lifecycle, AlertLifecycle)
        or lifecycle.alert_threshold != alert_threshold
        or lifecycle.sustained_cycles != max(1, sustained_cycles)
    ):
        lifecycle = AlertLifecycle(alert_threshold, sustained_cycles)
        st.session_state['alert_lifecycle'] = lifecycle

    return lifecycle


def get_dashboard_persistence_inspector(config: Dict[str, Any]) -> PersistenceInspectionCache:
    try:
        cache_seconds = float(config.get('persistence_cache_seconds', 300.0))
    except (TypeError, ValueError):
        cache_seconds = 300.0
    inspector = st.session_state.get('persistence_inspector')
    if not isinstance(inspector, PersistenceInspectionCache) or inspector.cache_seconds != max(0.0, cache_seconds):
        inspector = PersistenceInspectionCache(cache_seconds)
        st.session_state['persistence_inspector'] = inspector
    return inspector


def get_dashboard_anomaly_detector(config: Dict[str, Any]) -> ProcessAnomalyDetector:
    detector = st.session_state.get('anomaly_detector')
    settings = (
        int(config.get('anomaly_window_size', 12)),
        int(config.get('anomaly_min_samples', 5)),
        float(config.get('anomaly_z_threshold', 3.0)),
        int(config.get('anomaly_max_identities', 500)),
        float(config.get('anomaly_min_cpu_delta', 15.0)),
        float(config.get('anomaly_min_memory_delta', 5.0)),
    )
    if (
        not isinstance(detector, ProcessAnomalyDetector)
        or (
            detector.window_size,
            detector.min_samples,
            detector.z_threshold,
            detector.max_identities,
            detector.min_cpu_delta,
            detector.min_memory_delta,
        ) != settings
    ):
        detector = ProcessAnomalyDetector(*settings)
        st.session_state['anomaly_detector'] = detector
    return detector


def get_dashboard_network_ioc_matcher(config: Dict[str, Any]) -> NetworkIOCMatcher:
    matcher = st.session_state.get('network_ioc_matcher')
    try:
        cache_seconds = float(config.get('osint_dns_cache_seconds', 3600.0))
        timeout_seconds = float(config.get('osint_dns_timeout_seconds', 1.0))
    except (TypeError, ValueError):
        cache_seconds, timeout_seconds = 3600.0, 1.0
    if (
        not isinstance(matcher, NetworkIOCMatcher)
        or matcher.cache_seconds != max(1.0, cache_seconds)
        or matcher.dns_timeout_seconds != max(0.1, timeout_seconds)
    ):
        literal_ips, domains = load_network_indicators(str(DATA_DIR / 'mining_network_iocs.txt'))
        matcher = NetworkIOCMatcher(literal_ips, domains, cache_seconds, timeout_seconds)
        st.session_state['network_ioc_matcher'] = matcher
    return matcher


def get_dashboard_browser_detector(config: Dict[str, Any]) -> BrowserBehaviorDetector:
    detector = st.session_state.get('browser_behavior_detector')
    settings = (
        float(config.get('browser_cpu_threshold', 50.0)),
        int(config.get('browser_sustained_cycles', 2)),
        float(config.get('browser_max_score', 12.0)),
        int(config.get('browser_max_identities', 200)),
    )
    if (
        not isinstance(detector, BrowserBehaviorDetector)
        or (detector.cpu_threshold, detector.sustained_cycles, detector.max_score, detector.max_identities) != settings
    ):
        detector = BrowserBehaviorDetector(*settings)
        st.session_state['browser_behavior_detector'] = detector
    return detector


def get_dashboard_ml_model(model_path: Union[Path, str] = 'models/rf_cryptojack_model.pkl') -> Optional[Any]:
    """Load and cache the Random Forest cryptojacking ML model in session state."""
    model = st.session_state.get('ml_model')
    if model is None:
        try:
            model = load_model(model_path)
            st.session_state['ml_model'] = model
        except Exception:
            model = None
    return model


def run_dashboard_scan(
    config: Dict[str, Any],
    alert_lifecycle: AlertLifecycle,
    persistence_inspector: PersistenceInspectionCache,
    anomaly_detector: ProcessAnomalyDetector,
    network_ioc_matcher: NetworkIOCMatcher,
    browser_detector: BrowserBehaviorDetector,
    ml_model: Optional[Any] = None,
) -> Dict[str, Any]:
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
    indicators_list = load_mining_indicators(DATA_DIR / 'mining_iocs.txt')
    allowlist_names = load_allowlisted_processes(DATA_DIR / 'allowlist_processes.txt')
    config['allowlist_process_names'] = list(allowlist_names)

    scoring_start = perf_counter()
    scored = [
        score_process(proc, network_data.get(proc.pid), indicators_list, config, network_ioc_matcher)
        for proc in processes
    ]
    if ml_model is not None:
        for proc, score in zip(processes, scored):
            apply_ml_signal(score, proc, network_data.get(proc.pid), ml_model)
    if bool(config.get('anomaly_enabled', True)):
        anomaly_max_score = float(config.get('anomaly_max_score', 8.0))
        for score in scored:
            apply_anomaly_signal(score, anomaly_detector.observe(score), anomaly_max_score)
    if bool(config.get('browser_behavior_enabled', True)):
        for score in scored:
            apply_browser_behavior_signal(score, browser_detector.analyze(score))
        browser_detector.prune(scored)
    scoring_anomaly_ms = (perf_counter() - scoring_start) * 1000.0
    try:
        deep_inspection_threshold = float(config.get('deep_inspection_threshold', 40.0))
    except (TypeError, ValueError):
        deep_inspection_threshold = 40.0
    persistence_start = perf_counter()
    persistence_result = persistence_inspector.inspect_if_triggered(
        scored,
        deep_inspection_threshold,
        indicators_list,
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
    # Metrics count alerts confirmed in this scan, not raw threshold crossings.
    confirmed_alert_count = len(newly_confirmed_alerts)

    try:
        log_scan_metrics({
            'cpu_percent': resource.cpu_percent,
            'memory_percent': resource.memory_percent,
            'gpu_percent': resource.gpu_percent,
            'gpu_memory_percent': resource.gpu_memory_percent,
            'processes_scanned': len(processes),
            'alerts': confirmed_alert_count,
            'scan_duration_ms': round(scan_duration_ms, 1),
            **{name: round(value, 1) for name, value in timings.items() if name != 'scan_duration_ms'},
        })
        try:
            load_metrics_history.clear()
        except Exception:
            pass
    except Exception:
        pass

    return {
        'resource': resource,
        'processes': processes,
        'network_data': network_data,
        'scored': scored,
        'newly_confirmed_alerts': newly_confirmed_alerts,
        'persistence_result': persistence_result,
        'timings': timings,
        'scan_duration_ms': scan_duration_ms,
        'scan_time': datetime.now(timezone.utc),
    }


def main() -> None:
    config = load_config()
    api_base_url = str(config.get('api_base_url') or 'http://127.0.0.1:8000').rstrip('/')

    # Automatically ensure FastAPI cloud backend is active
    ensure_backend_is_running(api_base_url)

    st.set_page_config(
        page_title='CryptoJackGuard Enterprise Dashboard',
        layout='wide',
        initial_sidebar_state='expanded',
    )


    # -----------------------------------------------------------------------
    # 1. Enterprise Authentication Check
    # -----------------------------------------------------------------------
    if not st.session_state.get('token'):
        st.markdown(
            """
            <div style="text-align: center; margin-top: 30px; margin-bottom: 25px;">
                <h1>🛡️ CryptoJackGuard Enterprise Portal</h1>
                <p style="color: #9aa0a6; font-size: 1.1rem;">
                    Centralized Cryptojacking Defense & Cloud Telemetry Center
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col1, col2, col3 = st.columns([1, 1.5, 1])
        with col2:
            with st.form('enterprise_login_form'):
                st.subheader('Sign In')
                username = st.text_input('Username', value='admin', key='login_username')
                password = st.text_input('Password', type='password', key='login_password')
                submit_btn = st.form_submit_button('Authenticate & Open Dashboard', use_container_width=True)

                if submit_btn:
                    try:
                        resp = requests.post(
                            f"{api_base_url}/api/login",
                            json={"username": username, "password": password},
                            timeout=5.0,
                        )
                        if resp.status_code == 200:
                            auth_data = resp.json()
                            st.session_state['token'] = auth_data.get('access_token')
                            st.session_state['username'] = auth_data.get('username', username)
                            st.session_state['role'] = auth_data.get('role', 'admin')
                            st.success('Authentication successful! Loading dashboard...')
                            st.rerun()
                        else:
                            st.error('Invalid credentials. Please check your username and password.')
                    except requests.exceptions.RequestException as err:
                        st.error(f'Backend API unreachable at {api_base_url}. Error: {err}')
        return

    # -----------------------------------------------------------------------
    # 2. Authenticated Dashboard Interface
    # -----------------------------------------------------------------------
    st.markdown('# CryptoJackGuard Enterprise Dashboard')
    st.markdown('### Real-Time Cryptojacking Detection & Cloud Telemetry')
    st.success('🛡️ System Status: Protected - CryptoJackGuard is actively monitoring.')
    st.markdown('---')

    time_range_options = [
        ('Last 5 minutes', timedelta(minutes=5)),
        ('Last 15 minutes', timedelta(minutes=15)),
        ('Last 30 minutes', timedelta(minutes=30)),
        ('Last 1 hour', timedelta(hours=1)),
        ('All data', None),
    ]
    with st.sidebar:
        st.markdown(f"**👤 Operator:** `{st.session_state.get('username', 'admin')}`")
        st.caption(f"Role: {str(st.session_state.get('role', 'admin')).upper()} | Cloud Sync: Connected")

        # PDF Security Report Download
        user_token = st.session_state.get('token')
        if user_token:
            try:
                rep_res = requests.get(
                    f"{api_base_url}/api/reports/pdf",
                    headers={"Authorization": f"Bearer {user_token}"},
                    timeout=5.0,
                )
                if rep_res.status_code == 200 and rep_res.content:
                    st.download_button(
                        label="📄 Download Security Report (PDF)",
                        data=rep_res.content,
                        file_name="CryptoJackGuard_Report.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key="btn_download_security_report_pdf",
                    )
            except Exception:
                pass

        if st.button('🚪 Logout', key='btn_logout', use_container_width=True):
            st.session_state.pop('token', None)
            st.session_state.pop('username', None)
            st.session_state.pop('role', None)
            st.rerun()

        st.markdown('---')
        st.header('Controls')
        enable_auto = st.checkbox(
            'Enable auto refresh',
            value=False,
            key='enable_auto_refresh',
            help='When enabled the dashboard refreshes every 5 seconds. Default OFF for stability.',
        )
        auto_refresh_tick: Optional[int] = None
        # If auto-refresh is enabled, use streamlit-autorefresh safely.
        if enable_auto:
            try:
                auto_refresh_tick = st_autorefresh(interval=5000, limit=None, key='auto_refresh')
            except Exception:
                # Avoid crashing on shutdown or environments where autorefresh may fail
                pass

        refresh_now = st.button('Refresh now', key='manual_refresh')

        st.markdown('---')
        st.header('Metrics time range')
        time_range_label = st.selectbox(
            'Time range',
            [label for label, _ in time_range_options],
            index=2,
            key='metrics_time_range',
        )



    previous_auto_refresh_tick = st.session_state.get('last_auto_refresh_tick')
    should_scan = should_run_dashboard_scan(
        has_previous_scan='last_scan' in st.session_state,
        manual_refresh=refresh_now,
        auto_refresh_tick=auto_refresh_tick,
        previous_auto_refresh_tick=previous_auto_refresh_tick,
    )
    if auto_refresh_tick is None:
        st.session_state.pop('last_auto_refresh_tick', None)
    else:
        st.session_state['last_auto_refresh_tick'] = auto_refresh_tick

    if should_scan:
        alert_lifecycle = get_dashboard_alert_lifecycle(config)
        persistence_inspector = get_dashboard_persistence_inspector(config)
        anomaly_detector = get_dashboard_anomaly_detector(config)
        network_ioc_matcher = get_dashboard_network_ioc_matcher(config)
        browser_detector = get_dashboard_browser_detector(config)
        ml_model = get_dashboard_ml_model()
        scan_state = run_dashboard_scan(
            config,
            alert_lifecycle,
            persistence_inspector,
            anomaly_detector,
            network_ioc_matcher,
            browser_detector,
            ml_model,
        )
        st.session_state['last_scan'] = scan_state
    else:
        scan_state = st.session_state['last_scan']

    resource = scan_state['resource']
    processes = scan_state['processes']
    network_data = scan_state['network_data']
    scored = scan_state['scored']
    scan_duration_ms = scan_state['scan_duration_ms']
    timings = scan_state.get('timings', {})

    # Reload parsed metrics from disk so charts include the latest scan
    parsed_metrics = parse_metrics_rows(load_metrics_history())
    selected_range = next(window for label, window in time_range_options if label == time_range_label)
    filtered_metrics = filter_metrics_by_range(parsed_metrics, selected_range)

    metrics_history = load_metrics_history()
    metrics_summary = load_recent_metrics_summary(metrics_history)

    cols = st.columns([1, 1, 1])
    with cols[0]:
        st.markdown('### Live metrics')
    with cols[1]:
        st.markdown('### Scan status')
    with cols[2]:
        st.markdown('### Summary')

    allowlist_count = sum(1 for score in scored if score.allowlisted)
    build_metric_cards(
        resource,
        metrics_summary['alert_count'],
        scan_duration_ms,
        len(processes),
        allowlist_count,
        timings,
    )

    st.markdown('---')

    show_low_risk = st.checkbox('Show low-risk processes', value=False)
    display_scores = [
        score for score in scored
        if score.risk_score > 0
        and (show_low_risk or score.risk_score >= 40)
    ]

    with st.expander('Suspicious process details', expanded=True):
        if display_scores:
            process_rows = format_process_rows(display_scores[:50])
            options = [
                f"PID {row['PID']} - {row['Name']} - {row['Risk level']} - {row['Score']}"
                for row in process_rows
            ]
            selected_index = st.selectbox(
                'Select a suspicious process for more details',
                list(range(len(options))),
                format_func=lambda idx: options[idx],
                key='selected_process_index',
            )
            st.table(process_rows)
            selected_score = display_scores[selected_index]
            selected_network = network_data.get(selected_score.pid)
            st.markdown('---')
            _render_process_detail(selected_score, selected_network)
        else:
            st.success('✅ No suspicious processes detected at this time.')

    chart_cols = st.columns(2)
    with chart_cols[0]:
        if filtered_metrics:
            cpu_ok = build_metrics_chart(filtered_metrics, 'cpu_percent', 'CPU Usage History', 'CPU %')
            mem_ok = build_metrics_chart(filtered_metrics, 'memory_percent', 'Memory Usage History', 'Memory %')
            if not cpu_ok and not mem_ok:
                st.info('Not enough recent metrics yet. Run the detector for a few scan cycles.')
        else:
            st.info('Not enough recent metrics yet. Run the detector for a few scan cycles.')

    with chart_cols[1]:
        if filtered_metrics:
            gpu_ok = build_metrics_chart(filtered_metrics, 'gpu_percent', 'GPU Usage History', 'GPU %')
            gpu_mem_ok = build_metrics_chart(filtered_metrics, 'gpu_memory_percent', 'GPU Memory History', 'GPU memory %')
            if not gpu_ok and not gpu_mem_ok:
                st.info('Not enough recent metrics yet. Run the detector for a few scan cycles.')
        else:
            st.info('Not enough recent metrics yet. Run the detector for a few scan cycles.')

    if filtered_metrics:
        alert_df = [{'timestamp': row['timestamp'], 'alerts': row['alerts'] or 0} for row in filtered_metrics if row['alerts'] is not None]
        if alert_df:
            fig_alerts = px.bar(alert_df, x='timestamp', y='alerts', title='Alerts Over Time', labels={'alerts': 'Alerts'}, template='plotly_dark')
            st.plotly_chart(fig_alerts, use_container_width=True)
        else:
            st.info('Not enough recent metrics yet. Run the detector for a few scan cycles.')
    else:
        st.info('Not enough recent metrics yet. Run the detector for a few scan cycles.')

    st.markdown('---')
    with st.container():
        st.subheader('Recent alerts')
        alert_items = load_recent_alerts(
            10,
            token=st.session_state.get('token'),
            api_base_url=api_base_url,
        )
        if not alert_items:
            st.info('No recent suspicious activity.')
        else:
            st.dataframe(alert_items, use_container_width=True, hide_index=True)

    st.markdown('---')
    st.markdown(
        'This dashboard is defensive and privacy-friendly. It does not terminate processes automatically, ' 
        'does not collect browser history, and does not inspect packet payloads.'
    )


if __name__ == '__main__':
    main()
