from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

import psutil

try:
    import GPUtil
except (ImportError, ModuleNotFoundError):
    GPUtil = None


@dataclass
class ResourceSnapshot:
    cpu_percent: float
    memory_percent: float
    available_mb: float
    gpu_percent: Optional[float]
    gpu_memory_percent: Optional[float]


def collect_resource_snapshot() -> ResourceSnapshot:
    cpu_percent = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory()
    available_mb = memory.available / 1024 / 1024

    gpu_percent: Optional[float] = None
    gpu_memory_percent: Optional[float] = None

    if GPUtil is not None:
        try:
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu_percent = sum(gpu.load for gpu in gpus) / len(gpus) * 100
                gpu_memory_percent = sum(gpu.memoryUtil for gpu in gpus) / len(gpus) * 100
        except Exception:
            gpu_percent = None
            gpu_memory_percent = None

    return ResourceSnapshot(
        cpu_percent=cpu_percent,
        memory_percent=memory.percent,
        available_mb=available_mb,
        gpu_percent=gpu_percent,
        gpu_memory_percent=gpu_memory_percent,
    )
