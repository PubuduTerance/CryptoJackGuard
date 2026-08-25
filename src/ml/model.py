from __future__ import annotations
from pathlib import Path
import sys
from typing import Any, List, Optional, Sequence, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from src.ml.feature_extractor import FEATURE_NAMES


class CryptoJackModel:
    """Random Forest classifier for cryptojacking detection."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: Optional[int] = 10,
        random_state: Optional[int] = 42,
        **kwargs: Any,
    ) -> None:
        """Initialize the Random Forest model with configurable hyperparameters."""
        self.feature_names: List[str] = list(FEATURE_NAMES)
        self.classifier: RandomForestClassifier = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            **kwargs,
        )
        self.is_trained: bool = False

    def train(self, X: Any, y: Any) -> CryptoJackModel:
        """Train the Random Forest model on feature matrix X and target labels y.

        Args:
            X: Feature matrix (DataFrame, NumPy array, or list of feature vectors).
            y: Target labels (Series, NumPy array, or list of labels).

        Returns:
            Self instance after fitting.
        """
        self.classifier.fit(X, y)
        self.is_trained = True
        return self

    def _prepare_input(self, X: Any) -> Any:
        """Ensure input samples match feature names if passed as a list or array."""
        if isinstance(X, (list, tuple)) and X and isinstance(X[0], (list, tuple)):
            if getattr(self, "feature_names", None) and len(X[0]) == len(self.feature_names):
                import pandas as pd
                return pd.DataFrame(X, columns=self.feature_names)
        return X

    def predict(self, X: Any) -> np.ndarray:
        """Predict binary class labels (0 = BENIGN, 1 = MALICIOUS) for input samples."""
        return self.classifier.predict(self._prepare_input(X))

    def predict_proba(self, X: Any) -> np.ndarray:
        """Predict class probabilities / confidence scores for input samples.

        Returns:
            2D array of shape (n_samples, n_classes) with probability estimates.
        """
        return self.classifier.predict_proba(self._prepare_input(X))

    def predict_risk_score(self, X: Any) -> Union[float, List[float]]:
        """Convenience method to return malicious probability score (0.0 - 1.0)."""
        proba = self.predict_proba(X)
        if len(proba.shape) == 2 and proba.shape[1] >= 2:
            scores = proba[:, 1].tolist()
            return scores[0] if len(scores) == 1 else scores
        return 0.0
