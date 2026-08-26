from __future__ import annotations
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Union

import pandas as pd


def generate_synthetic_dataset(
    output_path: Optional[Union[Path, str]] = None,
    benign_count: int = 1000,
    malicious_count: int = 500,
    random_seed: Optional[int] = 42,
) -> pd.DataFrame:
    """Generate a synthetic dataset of process features for training ML cryptojacking detection models.

    Args:
        output_path: Optional file path to save the generated CSV. Defaults to 'data/synthetic_training_data.csv'.
        benign_count: Number of benign samples to generate (default: 1000).
        malicious_count: Number of malicious samples to generate (default: 500).
        random_seed: Optional random seed for reproducible dataset generation.

    Returns:
        pandas.DataFrame containing generated samples with feature columns and 'label'.
    """
    if random_seed is not None:
        random.seed(random_seed)

    rows: List[Dict[str, Any]] = []

    # 1. Generate BENIGN samples
    # Characteristics: normal/low CPU (<35%) or high-CPU legitimate task (video, games, server),
    # normal memory (<30%), realistic command-line lengths, 0 to moderate network connections, 0 suspicious keywords.
    for _ in range(benign_count):
        # 50% idle/low activity (0.0 - 5.0%), 35% active standard apps (5.0 - 35.0%), 15% high CPU legitimate workloads (40.0 - 95.0%)
        r = random.random()
        if r < 0.50:
            cpu = round(random.uniform(0.0, 5.0), 2)
        elif r < 0.85:
            cpu = round(random.uniform(5.1, 35.0), 2)
        else:
            cpu = round(random.uniform(40.0, 95.0), 2)

        mem = round(random.uniform(0.2, 30.0), 2)
        cmd_len = random.randint(10, 140)

        # 60% of benign processes have 0 network connections, 40% have 1-4
        if random.random() < 0.60:
            net_conn = 0
        else:
            net_conn = random.randint(1, 4)

        suspicious_kw = 0  # Benign processes have 0 suspicious mining keywords

        rows.append({
            "cpu_percent": cpu,
            "memory_percent": mem,
            "cmdline_length": cmd_len,
            "network_connections_count": net_conn,
            "suspicious_keyword_count": suspicious_kw,
            "label": "BENIGN",
        })

    # 2. Generate MALICIOUS samples (Cryptojackers)
    # Characteristics: high sustained CPU (>70%), moderate to high memory,
    # network connections present (>= 1, pool/stratum), suspicious keywords present (>= 1).
    for _ in range(malicious_count):
        cpu = round(random.uniform(70.1, 99.9), 2)
        mem = round(random.uniform(4.0, 45.0), 2)
        cmd_len = random.randint(60, 320)  # Longer flags/wallet/pool arguments
        net_conn = random.randint(1, 8)    # Mining pool / C2 connection(s) present
        suspicious_kw = random.randint(1, 4)  # Contains mining indicators (xmrig, stratum, etc.)

        rows.append({
            "cpu_percent": cpu,
            "memory_percent": mem,
            "cmdline_length": cmd_len,
            "network_connections_count": net_conn,
            "suspicious_keyword_count": suspicious_kw,
            "label": "MALICIOUS",
        })

    # Create DataFrame and shuffle samples
    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    # Determine destination if writing to disk
    if output_path is False or output_path == "":
        return df

    if output_path is None:
        base_dir = Path(__file__).resolve().parent.parent.parent
        resolved_path = base_dir / "data" / "synthetic_training_data.csv"
    else:
        resolved_path = Path(output_path)

    # Ensure parent directory exists and save CSV
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(resolved_path, index=False)
    print(f"[+] Successfully generated {len(df)} synthetic samples ({benign_count} BENIGN, {malicious_count} MALICIOUS).")
    print(f"[+] Saved to: {resolved_path}")

    return df


def generate_enterprise_dataset(
    output_path: Optional[Union[Path, str]] = None,
    synthetic_benign: int = 1000,
    synthetic_malicious: int = 500,
    minos_count: int = 500,
    cryptic_bytes_count: int = 500,
    random_seed: Optional[int] = 42,
) -> pd.DataFrame:
    """Generate enterprise mixed dataset combining synthetic baseline, MINOS, and Cryptic Bytes benchmarks."""
    from src.ml.real_dataset_loader import build_enterprise_dataset
    return build_enterprise_dataset(
        output_path=output_path,
        synthetic_benign=synthetic_benign,
        synthetic_malicious=synthetic_malicious,
        minos_count=minos_count,
        cryptic_bytes_count=cryptic_bytes_count,
        random_seed=random_seed,
    )


if __name__ == "__main__":
    generate_synthetic_dataset()
    generate_enterprise_dataset()
