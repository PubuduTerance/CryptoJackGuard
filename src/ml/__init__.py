"""Machine Learning detection engine for CryptoJackGuard.

This package provides feature extraction, dataset generation, model training,
registry management, and inference capabilities for detecting cryptojacking on endpoints.
"""

from src.ml.feature_extractor import (
    FEATURE_NAMES,
    ProcessFeatureExtractor,
)
from src.ml.model import CryptoJackModel
from src.ml.model_registry import load_model, save_model

__all__ = [
    "FEATURE_NAMES",
    "ProcessFeatureExtractor",
    "CryptoJackModel",
    "save_model",
    "load_model",
]
