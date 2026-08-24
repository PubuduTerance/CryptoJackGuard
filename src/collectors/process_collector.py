from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

import psutil


@dataclass
class ProcessInfo:
    pid: int
    name: str
    path: str
    cmdline: str
    cpu_percent: float
    memory_percent: float
    ppid: Optional[int] = None
    parent_name: str = ''
    parent_path: str = ''


def collect_processes() -> List[ProcessInfo]:
    processes: List[ProcessInfo] = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
        try:
            info = proc.info
            name = str(info.get('name') or '')
            path = str(info.get('exe') or '')
            cmdline = ' '.join(info.get('cmdline') or [])
            cpu_percent = proc.cpu_percent(interval=0.0)
            memory_percent = proc.memory_percent()
            ppid_value = info.get('ppid')
            ppid = int(ppid_value) if ppid_value is not None else None
            parent_name = ''
            parent_path = ''
            if ppid is not None:
                try:
                    parent = proc.parent()
                    if parent is not None:
                        parent_name = parent.name() or ''
                        parent_path = parent.exe() or ''
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            processes.append(
                ProcessInfo(
                    pid=proc.pid,
                    name=name,
                    path=path,
                    cmdline=cmdline,
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    ppid=ppid,
                    parent_name=parent_name,
                    parent_path=parent_path,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return processes
