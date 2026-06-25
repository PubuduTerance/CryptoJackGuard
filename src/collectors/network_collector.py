from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List

import psutil


@dataclass
class ProcessNetworkInfo:
    pid: int
    local_ports: List[int]
    remote_ports: List[int]
    remote_addresses: List[str]
    statuses: List[str]


def collect_network_info() -> Dict[int, ProcessNetworkInfo]:
    mapping: Dict[int, ProcessNetworkInfo] = {}

    try:
        connections = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, psutil.NotImplementedError):
        return mapping

    for conn in connections:
        if conn.pid is None:
            continue

        try:
            local_port = conn.laddr.port if conn.laddr else None
            remote_address = f'{conn.raddr.ip}:{conn.raddr.port}' if conn.raddr else ''
            remote_port = conn.raddr.port if conn.raddr else None

            record = mapping.setdefault(
                conn.pid,
                ProcessNetworkInfo(pid=conn.pid, local_ports=[], remote_ports=[], remote_addresses=[], statuses=[]),
            )

            if local_port and local_port not in record.local_ports:
                record.local_ports.append(local_port)

            if remote_port and remote_port not in record.remote_ports:
                record.remote_ports.append(remote_port)

            if remote_address and remote_address not in record.remote_addresses:
                record.remote_addresses.append(remote_address)

            status = conn.status or ''
            if status and status not in record.statuses:
                record.statuses.append(status)
        except Exception:
            continue

    return mapping
