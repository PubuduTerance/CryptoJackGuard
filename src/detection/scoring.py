from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from src.collectors.network_collector import ProcessNetworkInfo
from src.collectors.process_collector import ProcessInfo


@dataclass
class ProcessScore:
    pid: int
    name: str
    path: str
    cmdline: str
    cpu_percent: float
    memory_percent: float
    local_ports: List[int]
    risk_score: float
    reasons: List[str]
    allowlisted: bool = False
    allowlist_notes: List[str] = field(default_factory=list)


def _matches_indicator(text: str, indicators: Set[str]) -> bool:
    lower_text = text.lower()
    return any(indicator in lower_text for indicator in indicators)


def _select_specific_indicator_matches(text: str, indicators: Set[str]) -> List[str]:
    """Return CLI matches without counting a generic substring twice.

    Longer indicators are considered first, so ``stratum+tcp`` takes
    precedence over its generic ``stratum`` substring.
    """
    selected: List[str] = []
    for indicator in sorted(indicators, key=lambda value: (-len(value), value)):
        if indicator not in text:
            continue
        if any(indicator in selected_indicator for selected_indicator in selected):
            continue
        selected.append(indicator)
    return sorted(selected)


def score_process(
    process: ProcessInfo,
    network_info: Optional[ProcessNetworkInfo],
    indicators: Set[str],
    config: Dict,
) -> ProcessScore:
    score = 0.0
    reasons: List[str] = []

    cpu_threshold = float(config.get('high_cpu_threshold', 30.0))
    memory_threshold = float(config.get('high_memory_threshold', 20.0))
    suspicious_ports = set(config.get('suspicious_ports', []))
    suspicious_path_keywords = set(config.get('suspicious_path_keywords', []))
    suspicious_cmd_indicators = list(config.get('suspicious_cmd_indicators', []))
    # small CPU level to consider "non-trivial" CPU use when combined with
    # suspicious indicators. This is intentionally low so CPU alone doesn't
    # trigger high-risk alerts.
    cpu_non_trivial = float(config.get('cpu_non_trivial_threshold', 10.0))
    safe_names = set(name.lower() for name in config.get('safe_process_names', []))
    allowlist_names = set(name.lower() for name in config.get('allowlist_process_names', []))

    name_lower = process.name.lower()
    path_lower = process.path.lower()
    cmdline_lower = process.cmdline.lower()
    safe_name = name_lower in safe_names
    allowlisted = name_lower in allowlist_names

    if process.pid == 0:
        return ProcessScore(
            pid=process.pid,
            name=process.name,
            path=process.path,
            cmdline=process.cmdline,
            cpu_percent=process.cpu_percent,
            memory_percent=process.memory_percent,
            local_ports=network_info.local_ports if network_info else [],
            risk_score=0.0,
            reasons=[],
            allowlisted=allowlisted,
        )

    normalized_cpu = min(process.cpu_percent, 100.0)
    if normalized_cpu >= cpu_threshold:
        score += 25.0
        reasons.append(f'high CPU usage ({normalized_cpu:.1f}%)')

    if process.memory_percent >= memory_threshold:
        score += 20.0
        reasons.append(f'high memory usage ({process.memory_percent:.1f}%)')

    known_miner_name = bool(indicators and _matches_indicator(name_lower, indicators))
    miner_ioc_in_path_or_cmdline = bool(
        indicators and (_matches_indicator(path_lower, indicators) or _matches_indicator(cmdline_lower, indicators))
    )
    suspicious_binary_path = bool(
        path_lower and any(keyword in path_lower for keyword in suspicious_path_keywords)
    )

    if known_miner_name:
        score += 30.0
        reasons.append('known miner executable name')

    if miner_ioc_in_path_or_cmdline:
        score += 20.0
        reasons.append('mining indicator found in process path or command line')

    if suspicious_binary_path:
        score += 15.0
        reasons.append('suspicious binary path')

    # Count miner-like command line indicators. Use the configured list plus
    # any external indicators provided. We report which indicators matched
    # so the dashboard can show precise reasons.
    combined_indicators = set(i.lower() for i in suspicious_cmd_indicators) | set(indicators)
    weak_indicators = {'--user', '--url', '--pass'}
    strong_indicators = {
        'stratum',
        'stratum+tcp',
        'stratum+ssl',
        'randomx',
        'rx/0',
        'xmrig',
        '--algo',
        '--coin',
        '--pool',
        'donate-level',
        '--donate-level',
    }
    browser_webview_names = {
        'msedgewebview2.exe',
        'steamwebhelper.exe',
        'code.exe',
        'cefsharp.browsersubprocess.exe',
    }

    matched_strong = _select_specific_indicator_matches(
        cmdline_lower,
        {indicator for indicator in combined_indicators if indicator in strong_indicators},
    )
    matched_weak = sorted({indicator for indicator in combined_indicators if indicator in cmdline_lower and indicator in weak_indicators})

    if matched_strong:
        num_matched = len(matched_strong)
        if num_matched == 1:
            score += 10.0
            reasons.append(f'1 miner-like CLI indicator: {matched_strong}')
        elif num_matched == 2:
            score += 25.0
            reasons.append(f'2 miner-like CLI indicators: {matched_strong}')
        else:
            score += 45.0
            reasons.append(f'{num_matched} miner-like CLI indicators: {matched_strong}')

        if matched_weak:
            reasons.append(f'additional weak CLI indicators: {matched_weak}')

        if normalized_cpu >= cpu_non_trivial:
            score += 10.0
            reasons.append(f'combined: miner-like args + CPU {normalized_cpu:.1f}%')
    elif matched_weak:
        is_browser_webview = name_lower in browser_webview_names
        if not is_browser_webview:
            reasons.append(f'weak CLI indicators present: {matched_weak}')
        # weak indicators alone should not contribute to miner score

    has_mining_network_signal = False
    if network_info:
        ports = set(network_info.local_ports)
        matching_ports = ports & suspicious_ports
        remote_matching = any(
            indicator in remote.lower()
            for remote in network_info.remote_addresses
            for indicator in indicators
        )
        if matching_ports:
            score += 25.0
            reasons.append(f'suspicious mining port(s): {sorted(matching_ports)}')
            has_mining_network_signal = True
        elif network_info.remote_ports and suspicious_ports.intersection(network_info.remote_ports):
            score += 25.0
            reasons.append(f'suspicious remote mining port(s): {sorted(suspicious_ports.intersection(network_info.remote_ports))}')
            has_mining_network_signal = True
        elif remote_matching:
            score += 25.0
            reasons.append('remote address matches mining IOC')
            has_mining_network_signal = True

    # Special-case softer scoring for python processes running miner tools.
    if name_lower == 'python.exe' and 'xmrig' in cmdline_lower:
        score += 10.0
        reasons.append('python process running miner-like tool')

    allowlist_notes: List[str] = []
    correlated_mining_signals = sum((
        normalized_cpu >= cpu_non_trivial,
        suspicious_binary_path,
        known_miner_name or miner_ioc_in_path_or_cmdline,
        bool(matched_strong),
        has_mining_network_signal,
    ))
    has_strong_mining_evidence = (
        known_miner_name
        or miner_ioc_in_path_or_cmdline
        or bool(matched_strong)
        or has_mining_network_signal
        or correlated_mining_signals >= 2
    )

    if safe_name or allowlisted:
        trust_sources: List[str] = []
        if safe_name:
            trust_sources.append('safe process name')
        if allowlisted:
            trust_sources.append('allowlisted process')
        trust_label = ' and '.join(trust_sources)

        if has_strong_mining_evidence:
            allowlist_notes.append(f'{trust_label}; no reduction due to strong mining evidence')
        elif score > 0:
            score = max(0.0, score - 35.0)
            allowlist_notes.append(f'{trust_label}; normal behavior de-emphasized')

    if allowlist_notes:
        reasons.extend(allowlist_notes)

    score = min(score, 100.0)

    return ProcessScore(
        pid=process.pid,
        name=process.name,
        path=process.path,
        cmdline=process.cmdline,
        cpu_percent=process.cpu_percent,
        memory_percent=process.memory_percent,
        local_ports=network_info.local_ports if network_info else [],
        risk_score=score,
        reasons=reasons,
        allowlisted=allowlisted,
        allowlist_notes=allowlist_notes,
    )
