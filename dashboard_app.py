from __future__ import annotations
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from src.collectors.network_collector import collect_network_info
from src.collectors.process_collector import collect_processes
from src.collectors.resource_collector import collect_resource_snapshot
from src.detection.scoring import score_process
from src.intelligence.osint_loader import load_mining_indicators, load_allowlisted_processes


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


def parse_float(value: str) -> Optional[float]:
    if value is None:
        return None
    value = value.strip()
    if not value or value.upper() == 'N/A':
        return None
    try:
        return float(value)
    except ValueError:
        return None


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


@st.cache_data
def load_alert_history(limit: int = 10) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    if not ALERTS_LOG.exists():
        return alerts

    with ALERTS_LOG.open('r', encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                alerts.append(record)
            except json.JSONDecodeError:
                continue
    alerts.sort(key=lambda item: item.get('timestamp', ''), reverse=True)
    return alerts[:limit]


def build_metric_cards(resource: Any, alerts_count: int, last_scan_ms: float, processes_count: int, allowlist_count: int) -> None:
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
        rows.append(
            {
                'PID': score.pid,
                'Name': score.name,
                'CPU %': f'{score.cpu_percent:.1f}',
                'Memory %': f'{score.memory_percent:.1f}',
                'Score': f'{score.risk_score:.1f}',
                'Risk level': level,
                'Reasons': ', '.join(score.reasons),
                'Executable path': score.path or 'N/A',
            }
        )
    return rows


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

    left, right = st.columns([1, 1])
    with left:
        st.markdown(f'- **PID:** {score.pid}')
        st.markdown(f'- **Name:** {score.name}')
        st.markdown(f'- **Executable path:** {score.path or "N/A"}')
        st.markdown(f'- **Command line:** {score.cmdline or "N/A"}')
        st.markdown(f'- **CPU %:** {score.cpu_percent:.1f}')
        st.markdown(f'- **Memory %:** {score.memory_percent:.1f}')
    with right:
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

    if network_info:
        st.markdown('#### Network connections')
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


def main() -> None:
    st.set_page_config(
        page_title='CryptoJackGuard v1.2 Advanced Dashboard',
        layout='wide',
        initial_sidebar_state='expanded',
    )

    st_autorefresh(interval=5000, limit=None, key='auto_refresh')

    st.markdown('# CryptoJackGuard v1.2 Advanced Dashboard')
    st.markdown('### Real-Time Cryptojacking Detection Dashboard')
    st.markdown('---')

    config = load_config()
    indicators = load_metrics_history()  # reuse cache to keep sidebar stable
    resource = collect_resource_snapshot()
    processes = collect_processes()
    network_data = collect_network_info()
    indicators_list = load_mining_indicators(DATA_DIR / 'mining_iocs.txt')
    allowlist_names = load_allowlisted_processes(DATA_DIR / 'allowlist_processes.txt')
    config['allowlist_process_names'] = list(allowlist_names)

    scored = [
        score_process(proc, network_data.get(proc.pid), indicators_list, config)
        for proc in processes
    ]
    scored.sort(key=lambda item: item.risk_score, reverse=True)
    suspicious_scores = [score for score in scored if score.risk_score > 0]

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
        metrics_summary['last_scan_ms'],
        len(processes),
        allowlist_count,
    )

    st.markdown('---')

    default_scores = [score for score in scored if score.risk_score >= 40]
    low_risk_scores = [score for score in scored if 0 < score.risk_score < 40]
    show_low_risk = st.checkbox('Show low-risk processes', value=False)
    display_scores = default_scores + low_risk_scores if show_low_risk else default_scores

    with st.expander('Suspicious process details', expanded=True):
        if display_scores:
            process_rows = format_process_rows(display_scores[:50])
            options = [
                f"PID {row['PID']} — {row['Name']} — {row['Risk level']} — {row['Score']}"
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
            st.info('No suspicious processes detected.')

    chart_cols = st.columns(2)
    with chart_cols[0]:
        if metrics_history:
            cpu_df = [
                {'timestamp': metrics_summary['timestamps'][i], 'value': metrics_summary['cpu_history'][i]}
                for i in range(len(metrics_summary['timestamps']))
                if metrics_summary['cpu_history'][i] is not None
            ]
            if cpu_df:
                fig_cpu = px.line(cpu_df, x='timestamp', y='value', title='CPU Usage History', labels={'value': 'CPU %'})
                st.plotly_chart(fig_cpu, use_container_width=True)

            mem_df = [
                {'timestamp': metrics_summary['timestamps'][i], 'value': metrics_summary['memory_history'][i]}
                for i in range(len(metrics_summary['timestamps']))
                if metrics_summary['memory_history'][i] is not None
            ]
            if mem_df:
                fig_mem = px.line(mem_df, x='timestamp', y='value', title='Memory Usage History', labels={'value': 'Memory %'})
                st.plotly_chart(fig_mem, use_container_width=True)

    with chart_cols[1]:
        if metrics_history:
            gpu_df = [
                {'timestamp': metrics_summary['timestamps'][i], 'value': metrics_summary['gpu_history'][i]}
                for i in range(len(metrics_summary['timestamps']))
                if metrics_summary['gpu_history'][i] is not None
            ]
            if gpu_df:
                fig_gpu = px.line(gpu_df, x='timestamp', y='value', title='GPU Usage History', labels={'value': 'GPU %'})
                st.plotly_chart(fig_gpu, use_container_width=True)

            gpu_mem_df = [
                {'timestamp': metrics_summary['timestamps'][i], 'value': metrics_summary['gpu_memory_history'][i]}
                for i in range(len(metrics_summary['timestamps']))
                if metrics_summary['gpu_memory_history'][i] is not None
            ]
            if gpu_mem_df:
                fig_gpu_mem = px.line(gpu_mem_df, x='timestamp', y='value', title='GPU Memory History', labels={'value': 'GPU memory %'})
                st.plotly_chart(fig_gpu_mem, use_container_width=True)

    if metrics_history and metrics_summary['timestamps']:
        alert_df = [
            {'timestamp': metrics_summary['timestamps'][i], 'alerts': metrics_summary['alert_history'][i]}
            for i in range(len(metrics_summary['timestamps']))
        ]
        fig_alerts = px.bar(alert_df, x='timestamp', y='alerts', title='Alerts Over Time', labels={'alerts': 'Alerts'})
        st.plotly_chart(fig_alerts, use_container_width=True)

    st.markdown('---')
    with st.container():
        st.subheader('Recent alerts')
        alert_items = load_alert_history(10)
        if not alert_items:
            st.info('No recent suspicious activity.')
        else:
            for alert in alert_items:
                ts = alert.get('timestamp', 'Unknown')
                pid = alert.get('pid', 'N/A')
                name = alert.get('name', 'N/A')
                score = alert.get('score', 'N/A')
                reasons = ', '.join(alert.get('reasons', [])) if isinstance(alert.get('reasons'), list) else alert.get('reasons', 'N/A')
                response_action = alert.get('response_action')
                status = f' | Action: {response_action}' if response_action else ''
                st.markdown(f'**{ts}** — PID {pid} — {name} — Score {score}{status}')
                st.caption(reasons)

    st.markdown('---')
    st.markdown(
        'This dashboard is defensive and privacy-friendly. It does not terminate processes automatically, ' 
        'does not collect browser history, and does not inspect packet payloads.'
    )


if __name__ == '__main__':
    main()
