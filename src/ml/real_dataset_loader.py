from __future__ import annotations
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from src.ml.dataset_generator import generate_synthetic_dataset
from src.ml.feature_extractor import FEATURE_NAMES


def generate_minos_benchmark_dataset(
    count: int = 500,
    benign_ratio: float = 0.6,
    random_seed: Optional[int] = 42,
) -> pd.DataFrame:
    """Generate process telemetry samples modeling the academic MINOS cryptojacking benchmark.

    MINOS benchmarks evaluate detection across:
    1. Legitimate high-compute intensive applications (compilers, video encoding, simulations).
    2. Full-throttle WebAssembly (Wasm) and native CPU cryptominers.
    3. Throttled/stealth evasion cryptominers (CPU restricted to lower percentages).
    4. Obfuscated miner processes.

    Args:
        count: Total number of MINOS benchmark samples to generate.
        benign_ratio: Ratio of benign samples (default: 0.6 = 60% benign, 40% malicious).
        random_seed: Optional random seed for reproducible generation.

    Returns:
        pandas.DataFrame containing MINOS benchmark feature samples.
    """
    if random_seed is not None:
        random.seed(random_seed)

    benign_target = int(count * benign_ratio)
    malicious_target = count - benign_target
    rows: List[Dict[str, Any]] = []

    # 1. BENIGN MINOS profiles
    for _ in range(benign_target):
        r = random.random()
        if r < 0.35:
            # Low / background system service
            cpu = round(random.uniform(0.1, 8.0), 2)
            mem = round(random.uniform(0.5, 15.0), 2)
            cmd_len = random.randint(12, 90)
            net_conn = 0 if random.random() < 0.7 else random.randint(1, 2)
        elif r < 0.65:
            # Standard interactive productivity software
            cpu = round(random.uniform(5.0, 30.0), 2)
            mem = round(random.uniform(3.0, 25.0), 2)
            cmd_len = random.randint(20, 140)
            net_conn = random.randint(0, 3)
        else:
            # High-load compute intensive (compilation, rendering, data processing)
            # High CPU but legitimate (0 suspicious mining keywords)
            cpu = round(random.uniform(45.0, 96.0), 2)
            mem = round(random.uniform(10.0, 65.0), 2)
            cmd_len = random.randint(30, 220)
            net_conn = random.randint(0, 5)

        rows.append({
            "cpu_percent": cpu,
            "memory_percent": mem,
            "cmdline_length": cmd_len,
            "network_connections_count": net_conn,
            "suspicious_keyword_count": 0,
            "label": "BENIGN",
        })

    # 2. MALICIOUS MINOS profiles
    for _ in range(malicious_target):
        r = random.random()
        if r < 0.50:
            # Full-throttle WebAssembly / native miner (e.g., Coinhive, XMRig)
            cpu = round(random.uniform(75.0, 99.8), 2)
            mem = round(random.uniform(8.0, 42.0), 2)
            cmd_len = random.randint(50, 280)
            net_conn = random.randint(1, 6)
            suspicious_kw = random.randint(1, 4)
        elif r < 0.80:
            # Throttled / stealth evasion miner (CPU restricted to bypass naive thresholds)
            cpu = round(random.uniform(26.0, 54.0), 2)
            mem = round(random.uniform(5.0, 30.0), 2)
            cmd_len = random.randint(45, 230)
            net_conn = random.randint(1, 4)
            suspicious_kw = random.randint(1, 3)
        else:
            # Obfuscated / renamed miner process with stratum communication
            cpu = round(random.uniform(55.0, 88.0), 2)
            mem = round(random.uniform(10.0, 45.0), 2)
            cmd_len = random.randint(70, 310)
            net_conn = random.randint(1, 5)
            suspicious_kw = random.randint(1, 3)

        rows.append({
            "cpu_percent": cpu,
            "memory_percent": mem,
            "cmdline_length": cmd_len,
            "network_connections_count": net_conn,
            "suspicious_keyword_count": suspicious_kw,
            "label": "MALICIOUS",
        })

    df = pd.DataFrame(rows)
    return df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)


def generate_cryptic_bytes_dataset(
    count: int = 500,
    benign_ratio: float = 0.6,
    random_seed: Optional[int] = 42,
) -> pd.DataFrame:
    """Generate process telemetry samples modeling the Cryptic Bytes real-world Monero telemetry signature dataset.

    Cryptic Bytes signatures capture enterprise endpoint telemetry:
    1. Multi-threaded memory-heavy RandomX / CryptoNight miners.
    2. Stratum protocol socket connections and pool flags.
    3. Enterprise network servers and developer tools with high connection counts.

    Args:
        count: Total number of Cryptic Bytes samples to generate.
        benign_ratio: Ratio of benign samples.
        random_seed: Optional random seed for reproducible generation.

    Returns:
        pandas.DataFrame containing Cryptic Bytes benchmark feature samples.
    """
    if random_seed is not None:
        random.seed(random_seed)

    benign_target = int(count * benign_ratio)
    malicious_target = count - benign_target
    rows: List[Dict[str, Any]] = []

    # 1. BENIGN Enterprise workloads (Databases, web servers, build tools, container agents)
    for _ in range(benign_target):
        r = random.random()
        if r < 0.40:
            # Background enterprise daemons / monitoring agents
            cpu = round(random.uniform(0.2, 12.0), 2)
            mem = round(random.uniform(1.0, 20.0), 2)
            cmd_len = random.randint(20, 110)
            net_conn = random.randint(0, 4)
        elif r < 0.75:
            # Enterprise network applications / browsers / collaboration tools
            cpu = round(random.uniform(5.0, 38.0), 2)
            mem = round(random.uniform(8.0, 35.0), 2)
            cmd_len = random.randint(40, 200)
            net_conn = random.randint(2, 12)  # High legitimate network connections
        else:
            # High compute server / database engine (PostgreSQL, build node)
            cpu = round(random.uniform(40.0, 92.0), 2)
            mem = round(random.uniform(15.0, 60.0), 2)
            cmd_len = random.randint(50, 260)
            net_conn = random.randint(3, 16)

        rows.append({
            "cpu_percent": cpu,
            "memory_percent": mem,
            "cmdline_length": cmd_len,
            "network_connections_count": net_conn,
            "suspicious_keyword_count": 0,
            "label": "BENIGN",
        })

    # 2. MALICIOUS Cryptic Bytes telemetry signatures
    for _ in range(malicious_target):
        r = random.random()
        if r < 0.60:
            # Native RandomX / CryptoNight enterprise cryptominer
            cpu = round(random.uniform(80.0, 99.9), 2)
            mem = round(random.uniform(12.0, 55.0), 2)  # Memory-hard scratchpad usage
            cmd_len = random.randint(70, 350)           # Pool url, wallet, algo flags
            net_conn = random.randint(1, 8)             # Active mining pool connections
            suspicious_kw = random.randint(1, 4)
        else:
            # Injected / living-off-the-land miner
            cpu = round(random.uniform(42.0, 78.0), 2)
            mem = round(random.uniform(8.0, 38.0), 2)
            cmd_len = random.randint(55, 220)
            net_conn = random.randint(1, 4)
            suspicious_kw = random.randint(1, 3)

        rows.append({
            "cpu_percent": cpu,
            "memory_percent": mem,
            "cmdline_length": cmd_len,
            "network_connections_count": net_conn,
            "suspicious_keyword_count": suspicious_kw,
            "label": "MALICIOUS",
        })

    df = pd.DataFrame(rows)
    return df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)


def build_enterprise_dataset(
    output_path: Optional[Union[Path, str]] = None,
    synthetic_benign: int = 1000,
    synthetic_malicious: int = 500,
    minos_count: int = 500,
    cryptic_bytes_count: int = 500,
    random_seed: Optional[int] = 42,
) -> pd.DataFrame:
    """Combine synthetic baseline data with MINOS and Cryptic Bytes academic/telemetry benchmark signatures.

    Produces a robust mixed training dataset suitable for enterprise/office deployment.

    Args:
        output_path: Destination path for CSV. Defaults to 'data/enterprise_training_dataset.csv'.
        synthetic_benign: Number of synthetic benign samples.
        synthetic_malicious: Number of synthetic malicious samples.
        minos_count: Number of MINOS benchmark samples.
        cryptic_bytes_count: Number of Cryptic Bytes telemetry samples.
        random_seed: Random seed for reproducibility.

    Returns:
        pandas.DataFrame with combined mixed training dataset.
    """
    if random_seed is not None:
        random.seed(random_seed)

    # 1. Generate synthetic baseline dataset in memory
    df_synthetic = generate_synthetic_dataset(
        output_path=False,
        benign_count=synthetic_benign,
        malicious_count=synthetic_malicious,
        random_seed=random_seed,
    )

    # 2. Generate MINOS academic benchmark dataset
    df_minos = generate_minos_benchmark_dataset(
        count=minos_count,
        benign_ratio=0.6,
        random_seed=random_seed + 1 if random_seed is not None else None,
    )

    # 3. Generate Cryptic Bytes enterprise telemetry dataset
    df_cryptic = generate_cryptic_bytes_dataset(
        count=cryptic_bytes_count,
        benign_ratio=0.6,
        random_seed=random_seed + 2 if random_seed is not None else None,
    )

    # 4. Concatenate and shuffle
    combined = pd.concat([df_synthetic, df_minos, df_cryptic], ignore_index=True)
    combined = combined[FEATURE_NAMES + ["label"]]
    combined = combined.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    # 5. Resolve output path
    if output_path is None:
        base_dir = Path(__file__).resolve().parent.parent.parent
        resolved_path = base_dir / "data" / "enterprise_training_dataset.csv"
    else:
        resolved_path = Path(output_path)

    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(resolved_path, index=False)

    benign_total = (combined["label"] == "BENIGN").sum()
    malicious_total = (combined["label"] == "MALICIOUS").sum()
    print(f"[+] Enterprise dataset built: {len(combined)} total samples ({benign_total} BENIGN, {malicious_total} MALICIOUS).")
    print(f"[+] Saved to: {resolved_path}")

    return combined


if __name__ == "__main__":
    build_enterprise_dataset()
