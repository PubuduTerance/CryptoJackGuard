from __future__ import annotations
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.collectors.network_collector import ProcessNetworkInfo
from src.collectors.process_collector import ProcessInfo
from src.intelligence.osint_loader import load_mining_indicators

# Standard fallback indicators when IOC file is not available
DEFAULT_SUSPICIOUS_KEYWORDS: Set[str] = {
    "xmrig",
    "minergate",
    "coinhive",
    "cryptonight",
    "cryptominer",
    "xmr-stak",
    "nicehash",
    "minerd",
    "cpuminer",
    "ccminer",
    "sgminer",
    "stratum",
    "stratum+tcp",
    "stratum+ssl",
    "cryptonight-lite",
    "randomx",
    "donate-level",
    "pool.minexmr.com",
    "supportxmr.com",
    "nanopool",
    "hashvault",
    "moneroocean",
}

FEATURE_NAMES: List[str] = [
    "cpu_percent",
    "memory_percent",
    "cmdline_length",
    "network_connections_count",
    "suspicious_keyword_count",
]


class ProcessFeatureExtractor:
    """Extracts numerical features from process telemetry and network data for ML-based cryptojacking detection."""

    def __init__(
        self,
        keywords: Optional[Union[Set[str], List[str]]] = None,
        indicator_file: Optional[Union[Path, str]] = None,
    ) -> None:
        """Initialize the feature extractor with customizable IOC keywords.

        Args:
            keywords: Optional explicit set/list of suspicious keywords.
            indicator_file: Optional path to a file containing mining indicators.
        """
        if keywords is not None:
            self.keywords: Set[str] = {str(kw).lower().strip() for kw in keywords if str(kw).strip()}
        elif indicator_file is not None:
            path = Path(indicator_file)
            loaded = load_mining_indicators(path)
            self.keywords = loaded if loaded else DEFAULT_SUSPICIOUS_KEYWORDS.copy()
        else:
            default_path = Path(__file__).resolve().parent.parent.parent / "data" / "mining_iocs.txt"
            loaded = load_mining_indicators(default_path) if default_path.exists() else set()
            self.keywords = loaded if loaded else DEFAULT_SUSPICIOUS_KEYWORDS.copy()

    def count_suspicious_keywords(self, text: str) -> int:
        """Count the number of distinct suspicious mining keywords present in text.

        Args:
            text: Command line, process name, or string to analyze.

        Returns:
            The count of matching suspicious keywords.
        """
        if not text:
            return 0
        lower_text = text.lower()
        return sum(1 for kw in self.keywords if kw in lower_text)

    def _resolve_network_count(
        self,
        pid: Optional[int],
        network_data: Optional[Union[Dict[int, ProcessNetworkInfo], ProcessNetworkInfo, Dict[str, Any], List[Any], int]],
    ) -> int:
        """Resolve the number of active network connections for a process."""
        if network_data is None:
            return 0

        # Direct integer count
        if isinstance(network_data, int):
            return max(0, network_data)

        # Map of PID -> ProcessNetworkInfo or dict
        if isinstance(network_data, dict):
            if pid is not None and pid in network_data:
                target = network_data[pid]
                if isinstance(target, ProcessNetworkInfo):
                    return len(target.remote_addresses) or len(target.remote_ports)
                if isinstance(target, dict):
                    addrs = target.get("remote_addresses") or target.get("remote_ports") or []
                    return len(addrs) if isinstance(addrs, list) else int(target.get("connections_count", 0))
                if isinstance(target, int):
                    return max(0, target)

            # Dictionary representing a single process network info
            if "remote_addresses" in network_data:
                addrs = network_data["remote_addresses"]
                return len(addrs) if isinstance(addrs, list) else 0
            if "remote_ports" in network_data:
                ports = network_data["remote_ports"]
                return len(ports) if isinstance(ports, list) else 0
            if "connections_count" in network_data:
                return int(network_data["connections_count"])

        # Single ProcessNetworkInfo dataclass
        if isinstance(network_data, ProcessNetworkInfo):
            return len(network_data.remote_addresses) or len(network_data.remote_ports)

        # List of remote connections / addresses
        if isinstance(network_data, list):
            return len(network_data)

        return 0

    def extract(
        self,
        process: Union[ProcessInfo, Dict[str, Any], Any],
        network_data: Optional[Union[Dict[int, ProcessNetworkInfo], ProcessNetworkInfo, Dict[str, Any], List[Any], int]] = None,
    ) -> Dict[str, Union[float, int]]:
        """Extract a structured feature dictionary from process telemetry and network data.

        Extracted features:
        - cpu_percent: float
        - memory_percent: float
        - cmdline_length: int
        - network_connections_count: int
        - suspicious_keyword_count: int

        Args:
            process: ProcessInfo dataclass or dictionary containing process telemetry.
            network_data: Network mapping dict (PID -> ProcessNetworkInfo),
                          single ProcessNetworkInfo, list of connections, or connection count.

        Returns:
            Dictionary containing the 5 extracted features.
        """
        # Safely extract process attributes
        if isinstance(process, dict):
            pid = process.get("pid")
            name = str(process.get("name") or "")
            cmdline = str(process.get("cmdline") or "")
            cpu_percent = float(process.get("cpu_percent") or 0.0)
            memory_percent = float(process.get("memory_percent") or 0.0)
        else:
            pid = getattr(process, "pid", None)
            name = str(getattr(process, "name", "") or "")
            cmdline = str(getattr(process, "cmdline", "") or "")
            cpu_percent = float(getattr(process, "cpu_percent", 0.0) or 0.0)
            memory_percent = float(getattr(process, "memory_percent", 0.0) or 0.0)

        # Calculate cmdline length
        cmdline_length = len(cmdline)

        # Resolve network connections count
        network_connections_count = self._resolve_network_count(pid, network_data)

        # Count suspicious keywords in command-line and process name
        search_text = f"{name} {cmdline}".strip()
        suspicious_keyword_count = self.count_suspicious_keywords(search_text)

        return {
            "cpu_percent": float(cpu_percent),
            "memory_percent": float(memory_percent),
            "cmdline_length": int(cmdline_length),
            "network_connections_count": int(network_connections_count),
            "suspicious_keyword_count": int(suspicious_keyword_count),
        }

    def extract_vector(
        self,
        process: Union[ProcessInfo, Dict[str, Any], Any],
        network_data: Optional[Union[Dict[int, ProcessNetworkInfo], ProcessNetworkInfo, Dict[str, Any], List[Any], int]] = None,
    ) -> List[float]:
        """Extract features as a numerical array (list of floats) ordered by FEATURE_NAMES."""
        features = self.extract(process, network_data)
        return [float(features[name]) for name in FEATURE_NAMES]
