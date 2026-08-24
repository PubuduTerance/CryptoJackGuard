"""Privacy-preserving browser cryptojacking behavior correlation.

This module intentionally uses only endpoint telemetry already collected by
CryptoJackGuard. It never opens browser profiles or databases and never reads
URLs, page content, scripts, cookies, credentials, or network payloads.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Iterable, List

from src.detection.scoring import ProcessScore


BROWSER_PROCESS_NAMES = {
    'chrome.exe',
    'msedge.exe',
    'firefox.exe',
    'brave.exe',
    'opera.exe',
    'msedgewebview2.exe',
}
CHROMIUM_BROWSER_NAMES = BROWSER_PROCESS_NAMES - {'firefox.exe'}


@dataclass
class BrowserBehaviorResult:
    """Explainable result containing no browsing or page-content metadata."""

    is_browser_process: bool = False
    sustained_compute: bool = False
    cpu_anomalous: bool = False
    mining_network_evidence: bool = False
    browser_mining_suspicion: bool = False
    score_contribution: float = 0.0
    reasons: List[str] = field(default_factory=list)


class BrowserBehaviorDetector:
    """Track bounded, consecutive high-compute cycles for browser processes."""

    def __init__(
        self,
        cpu_threshold: float = 50.0,
        sustained_cycles: int = 2,
        max_score: float = 12.0,
        max_identities: int = 200,
    ) -> None:
        self.cpu_threshold = max(0.0, cpu_threshold)
        self.sustained_cycles = max(1, sustained_cycles)
        self.max_score = max(0.0, max_score)
        self.max_identities = max(1, max_identities)
        self._high_compute_cycles: OrderedDict[str, int] = OrderedDict()

    @staticmethod
    def process_identity(score: ProcessScore) -> str:
        """Use process metadata only; command lines and browser data are excluded."""
        return f'{score.pid}:{score.name.lower()}:{score.path.lower()}'

    @staticmethod
    def is_browser_process(score: ProcessScore) -> bool:
        name = score.name.lower()
        if name in BROWSER_PROCESS_NAMES:
            return True

        # Chromium renderer children normally retain the browser executable
        # name. The parent/type fallback supports limited metadata cases while
        # explicitly avoiding generic Electron applications such as code.exe.
        return (
            score.parent_name.lower() in CHROMIUM_BROWSER_NAMES
            and '--type=renderer' in score.cmdline.lower()
            and name not in {'code.exe', 'electron.exe'}
        )

    @staticmethod
    def _has_cpu_anomaly(score: ProcessScore) -> bool:
        return any(
            'cpu anomaly' in reason.lower()
            or 'cpu usage is significantly above recent process baseline' in reason.lower()
            for reason in score.anomaly_reasons
        )

    @staticmethod
    def _mining_evidence(score: ProcessScore) -> tuple[bool, bool]:
        reasons = [reason.lower() for reason in score.reasons]
        network_evidence = any(
            'mining network ioc' in reason
            or 'remote address matches mining ioc' in reason
            or 'mining port' in reason
            for reason in reasons
        )
        cli_evidence = any(
            'miner-like cli indicator' in reason
            or 'miner-like args' in reason
            or 'mining indicator found in process path or command line' in reason
            for reason in reasons
        )
        return network_evidence, network_evidence or cli_evidence

    def analyze(self, score: ProcessScore) -> BrowserBehaviorResult:
        """Advance one real monitoring cycle for a single scored process."""
        if not self.is_browser_process(score):
            return BrowserBehaviorResult()

        identity = self.process_identity(score)
        high_compute = score.cpu_percent >= self.cpu_threshold
        previous_cycles = self._high_compute_cycles.get(identity, 0)
        if high_compute:
            cycles = previous_cycles + 1
        else:
            cycles = 0
        self._high_compute_cycles[identity] = cycles
        self._high_compute_cycles.move_to_end(identity)
        while len(self._high_compute_cycles) > self.max_identities:
            self._high_compute_cycles.popitem(last=False)

        cpu_anomalous = self._has_cpu_anomaly(score)
        network_evidence, mining_evidence = self._mining_evidence(score)
        sustained = cycles >= self.sustained_cycles
        result = BrowserBehaviorResult(
            is_browser_process=True,
            sustained_compute=sustained,
            cpu_anomalous=cpu_anomalous,
            mining_network_evidence=network_evidence,
        )
        if high_compute:
            result.reasons.append(
                f'browser high compute observed ({cycles}/{self.sustained_cycles} sustained cycles)'
            )
        if sustained:
            result.reasons.append('browser sustained high compute')

        # High browser CPU is common. A contribution requires all three:
        # sustained high compute, anomaly evidence, and mining-related support.
        if sustained and cpu_anomalous and mining_evidence:
            result.browser_mining_suspicion = True
            result.score_contribution = self.max_score
            evidence_label = 'mining network evidence' if network_evidence else 'miner-specific command-line evidence'
            result.reasons.append(
                f'browser CPU anomaly correlated with sustained compute and {evidence_label}'
            )
        return result

    def prune(self, active_scores: Iterable[ProcessScore]) -> None:
        """Discard browser state for processes absent from the completed scan."""
        active_keys = {
            self.process_identity(score)
            for score in active_scores
            if self.is_browser_process(score)
        }
        self._high_compute_cycles = OrderedDict(
            (identity, cycles)
            for identity, cycles in self._high_compute_cycles.items()
            if identity in active_keys
        )


def apply_browser_behavior_signal(score: ProcessScore, result: BrowserBehaviorResult) -> None:
    """Attach browser findings and add only strongly correlated supporting risk."""
    score.browser_behavior = result
    if not result.browser_mining_suspicion or result.score_contribution <= 0.0:
        return

    score.risk_score = min(100.0, score.risk_score + result.score_contribution)
    score.reasons.extend(result.reasons[-1:])
