from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

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


_PROCESS_ATTRIBUTES = ['pid', 'name', 'exe', 'cmdline', 'ppid']
_MAX_COLLECTION_WORKERS = 16


@dataclass
class _ProcessSnapshot:
    pid: int
    name: str
    path: str
    cmdline: str
    cpu_percent: float
    memory_percent: float
    ppid: Optional[int]


def _as_string(value: Any) -> str:
    return str(value) if value is not None else ''


def _command_line(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ' '.join(str(part) for part in value)
    return _as_string(value)


def _collect_snapshot(proc: psutil.Process) -> Optional[_ProcessSnapshot]:
    """Read one process without failing the complete scan on access errors."""
    try:
        with proc.oneshot():
            info = proc.as_dict(attrs=_PROCESS_ATTRIBUTES, ad_value=None)
            try:
                cpu_percent = proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                cpu_percent = 0.0
            try:
                memory_percent = proc.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                memory_percent = 0.0

        ppid_value = info.get('ppid')
        return _ProcessSnapshot(
            pid=proc.pid,
            name=_as_string(info.get('name')),
            path=_as_string(info.get('exe')),
            cmdline=_command_line(info.get('cmdline')),
            cpu_percent=float(cpu_percent),
            memory_percent=float(memory_percent),
            ppid=int(ppid_value) if ppid_value is not None else None,
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    except Exception:
        return None


def collect_processes() -> List[ProcessInfo]:
    """Collect direct process telemetry using bounded parallel OS queries.

    ``cpu_percent(None)`` is non-blocking. The first sighting of a process
    can therefore be 0.0; psutil's process iterator reuses process objects,
    so later monitoring cycles produce a CPU reading since the prior sample.
    """
    try:
        process_references = list(psutil.process_iter())
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return []

    snapshots: List[_ProcessSnapshot] = []
    worker_count = min(_MAX_COLLECTION_WORKERS, max(1, len(process_references)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(_collect_snapshot, proc) for proc in process_references]
        for future in as_completed(futures):
            try:
                snapshot = future.result()
            except Exception:
                snapshot = None
            if snapshot is not None:
                snapshots.append(snapshot)

    parent_metadata: Dict[int, _ProcessSnapshot] = {
        snapshot.pid: snapshot
        for snapshot in snapshots
    }
    processes: List[ProcessInfo] = []
    for snapshot in snapshots:
        parent = parent_metadata.get(snapshot.ppid) if snapshot.ppid is not None else None
        processes.append(
            ProcessInfo(
                pid=snapshot.pid,
                name=snapshot.name,
                path=snapshot.path,
                cmdline=snapshot.cmdline,
                cpu_percent=snapshot.cpu_percent,
                memory_percent=snapshot.memory_percent,
                ppid=snapshot.ppid,
                parent_name=parent.name if parent is not None else '',
                parent_path=parent.path if parent is not None else '',
            )
        )

    return processes
