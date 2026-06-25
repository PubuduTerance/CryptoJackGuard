from __future__ import annotations
from dataclasses import dataclass
from typing import List

import psutil


@dataclass
class ProcessInfo:
    pid: int
    name: str
    path: str
    cmdline: str
    cpu_percent: float
    memory_percent: float


def collect_processes() -> List[ProcessInfo]:
    processes: List[ProcessInfo] = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            name = str(info.get('name') or '')
            path = str(info.get('exe') or '')
            cmdline = ' '.join(info.get('cmdline') or [])
            cpu_percent = proc.cpu_percent(interval=0.0)
            memory_percent = proc.memory_percent()

            processes.append(
                ProcessInfo(
                    pid=proc.pid,
                    name=name,
                    path=path,
                    cmdline=cmdline,
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return processes
