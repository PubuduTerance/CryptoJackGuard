"""Lightweight rolling process-resource anomaly support."""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Deque, Dict, Iterable, List, Tuple

from src.detection.scoring import ProcessScore


@dataclass
class AnomalyInfo:
    cpu_anomalous: bool = False
    memory_anomalous: bool = False
    cpu_zscore: float = 0.0
    memory_zscore: float = 0.0
    sample_count: int = 0
    anomaly_points: float = 0.0
    reasons: List[str] = field(default_factory=list)


class ProcessAnomalyDetector:
    """Maintain bounded rolling CPU and memory baselines per process name/path."""

    _MINIMUM_DEVIATION_EPSILON = 0.01

    def __init__(
        self,
        window_size: int = 12,
        min_samples: int = 5,
        z_threshold: float = 3.0,
        max_identities: int = 500,
        min_cpu_delta: float = 15.0,
        min_memory_delta: float = 5.0,
    ) -> None:
        self.window_size = max(1, window_size)
        self.min_samples = max(1, min_samples)
        self.z_threshold = max(0.1, z_threshold)
        self.max_identities = max(1, max_identities)
        self.min_cpu_delta = max(0.0, min_cpu_delta)
        self.min_memory_delta = max(0.0, min_memory_delta)
        self._observations: OrderedDict[str, Deque[Tuple[float, float]]] = OrderedDict()

    @staticmethod
    def process_identity(score: ProcessScore) -> str:
        """Use name/path only so anomaly state does not retain raw CLI secrets."""
        return f'{score.name.lower()}:{score.path.lower()}'

    def _is_high_anomaly(self, value: float, samples: Iterable[float], minimum_delta: float) -> Tuple[bool, float]:
        """Use z-score normally and a conservative delta when variance is tiny."""
        values = list(samples)
        baseline = mean(values)
        deviation = pstdev(values)
        if deviation <= self._MINIMUM_DEVIATION_EPSILON:
            return value - baseline >= minimum_delta, 0.0

        zscore = (value - baseline) / deviation
        return zscore >= self.z_threshold, zscore

    def observe(self, score: ProcessScore) -> AnomalyInfo:
        """Evaluate current usage against prior samples, then retain this sample."""
        identity = self.process_identity(score)
        history = self._observations.get(identity)
        if history is None:
            if len(self._observations) >= self.max_identities:
                self._observations.popitem(last=False)
            history = deque(maxlen=self.window_size)
            self._observations[identity] = history
        else:
            self._observations.move_to_end(identity)

        info = AnomalyInfo(sample_count=len(history))
        if len(history) >= self.min_samples:
            cpu_samples = [sample[0] for sample in history]
            memory_samples = [sample[1] for sample in history]
            info.cpu_anomalous, info.cpu_zscore = self._is_high_anomaly(
                score.cpu_percent,
                cpu_samples,
                self.min_cpu_delta,
            )
            info.memory_anomalous, info.memory_zscore = self._is_high_anomaly(
                score.memory_percent,
                memory_samples,
                self.min_memory_delta,
            )
            if info.cpu_anomalous:
                info.reasons.append('CPU usage is significantly above recent process baseline')
            if info.memory_anomalous:
                info.reasons.append('memory usage is significantly above recent process baseline')

        history.append((score.cpu_percent, score.memory_percent))
        return info

    def history_size(self, score: ProcessScore) -> int:
        history = self._observations.get(self.process_identity(score))
        return len(history) if history is not None else 0


def _has_mining_evidence(score: ProcessScore) -> bool:
    mining_reason_fragments = (
        'known miner executable',
        'mining indicator',
        'miner-like cli indicator',
        'miner-like args',
        'mining port',
        'mining ioc',
        'network ioc',
    )
    return any(
        fragment in reason.lower()
        for reason in score.reasons
        for fragment in mining_reason_fragments
    )


def apply_anomaly_signal(score: ProcessScore, info: AnomalyInfo, max_points: float = 8.0) -> None:
    """Apply a modest anomaly contribution without replacing heuristic evidence."""
    max_points = max(0.0, float(max_points))
    score.anomaly_sample_count = info.sample_count
    score.anomaly_reasons = list(info.reasons)
    if not info.reasons:
        return

    mining_evidence = _has_mining_evidence(score)
    if info.cpu_anomalous:
        points = min(max_points, 5.0 if not mining_evidence else 8.0)
        reason = (
            'CPU anomaly correlated with mining evidence'
            if mining_evidence
            else 'CPU anomaly above recent process baseline'
        )
    else:
        points = min(max_points, 3.0)
        reason = 'memory anomaly above recent process baseline'

    score.risk_score = min(100.0, score.risk_score + points)
    score.anomaly_reasons.append(reason)
    score.reasons.append(reason)
    info.anomaly_points = points
