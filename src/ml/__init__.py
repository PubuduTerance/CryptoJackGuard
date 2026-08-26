"""Machine Learning detection engine for CryptoJackGuard.

This package provides feature extraction, dataset generation, model training,
registry management, and inference capabilities for detecting cryptojacking on endpoints.
"""

from src.ml.dataset_generator import (
    generate_enterprise_dataset,
    generate_synthetic_dataset,
)
from src.ml.feature_extractor import (
    FEATURE_NAMES,
    ProcessFeatureExtractor,
)
from src.ml.model import CryptoJackModel
from src.ml.model_registry import load_model, save_model
from src.ml.real_dataset_loader import (
    build_enterprise_dataset,
    generate_cryptic_bytes_dataset,
    generate_minos_benchmark_dataset,
)

__all__ = [
    "FEATURE_NAMES",
    "ProcessFeatureExtractor",
    "CryptoJackModel",
    "save_model",
    "load_model",
    "generate_synthetic_dataset",
    "generate_enterprise_dataset",
    "build_enterprise_dataset",
    "generate_minos_benchmark_dataset",
    "generate_cryptic_bytes_dataset",
]

