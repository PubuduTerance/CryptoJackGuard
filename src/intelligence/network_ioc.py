"""Conservative network IOC matching with configured-domain DNS caching."""

from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass
from time import monotonic
from typing import Dict, Iterable, List, Set, Tuple


@dataclass
class NetworkIOCRefreshInfo:
    duration_ms: float = 0.0
    domains_refreshed: int = 0


def load_network_indicators(indicator_file: str) -> Tuple[Set[str], Set[str]]:
    """Load literal IPs and configured domains from a small local IOC file."""
    literal_ips: Set[str] = set()
    domains: Set[str] = set()
    try:
        with open(indicator_file, 'r', encoding='utf-8') as handle:
            for raw_line in handle:
                value = raw_line.strip().lower()
                if not value or value.startswith('#'):
                    continue
                try:
                    literal_ips.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    domains.add(value)
    except OSError:
        pass
    return literal_ips, domains


class NetworkIOCMatcher:
    """Match literal IOCs and cached addresses for explicitly configured domains."""

    def __init__(
        self,
        literal_ips: Iterable[str],
        domains: Iterable[str],
        cache_seconds: float = 3600.0,
        dns_timeout_seconds: float = 1.0,
    ) -> None:
        self.literal_ips = {str(ipaddress.ip_address(value)) for value in literal_ips}
        self.domains = {domain.lower() for domain in domains}
        self.cache_seconds = max(1.0, cache_seconds)
        self.dns_timeout_seconds = max(0.1, dns_timeout_seconds)
        self._domain_cache: Dict[str, Tuple[float, Set[str]]] = {}

    @staticmethod
    def _resolve_with_timeout(domain: str, timeout_seconds: float) -> Set[str]:
        resolved: Set[str] = set()

        def resolve() -> None:
            try:
                for result in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
                    resolved.add(result[4][0])
            except OSError:
                return

        thread = threading.Thread(target=resolve, daemon=True)
        thread.start()
        thread.join(timeout_seconds)
        return resolved if not thread.is_alive() else set()

    def refresh(self) -> NetworkIOCRefreshInfo:
        """Resolve only configured domains whose DNS cache entries have expired."""
        start = monotonic()
        refreshed = 0
        now = monotonic()
        for domain in self.domains:
            cached = self._domain_cache.get(domain)
            if cached is not None and now - cached[0] < self.cache_seconds:
                continue
            addresses = self._resolve_with_timeout(domain, self.dns_timeout_seconds)
            self._domain_cache[domain] = (now, addresses)
            refreshed += 1
        return NetworkIOCRefreshInfo(
            duration_ms=(monotonic() - start) * 1000.0,
            domains_refreshed=refreshed,
        )

    @staticmethod
    def _extract_ip(endpoint: str) -> str:
        value = endpoint.strip().strip('[]')
        if ':' in value:
            value = value.rsplit(':', 1)[0].strip('[]')
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return ''

    def match_remote_addresses(self, remote_addresses: Iterable[str]) -> List[str]:
        """Return configured IOC labels matching collected remote IP endpoints."""
        matches: Set[str] = set()
        resolved_addresses: Dict[str, Set[str]] = {
            domain: addresses
            for domain, (_, addresses) in self._domain_cache.items()
        }
        for endpoint in remote_addresses:
            address = self._extract_ip(endpoint)
            if not address:
                continue
            if address in self.literal_ips:
                matches.add(address)
            for domain, addresses in resolved_addresses.items():
                if address in addresses:
                    matches.add(domain)
        return sorted(matches)
