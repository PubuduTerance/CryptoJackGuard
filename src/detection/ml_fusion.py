from __future__ import annotations
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.collectors.network_collector import ProcessNetworkInfo
from src.collectors.process_collector import ProcessInfo
from src.detection.scoring import ProcessScore
from src.ml.feature_extractor import ProcessFeatureExtractor

_DEFAULT_EXTRACTOR: Optional[ProcessFeatureExtractor] = None


def get_default_feature_extractor() -> ProcessFeatureExtractor:
    """Get or create the singleton feature extractor instance."""
    global _DEFAULT_EXTRACTOR
    if _DEFAULT_EXTRACTOR is None:
        _DEFAULT_EXTRACTOR = ProcessFeatureExtractor()
    return _DEFAULT_EXTRACTOR


def apply_ml_signal(
    score_obj: ProcessScore,
    proc: Union[ProcessInfo, Dict[str, Any], Any],
    network: Optional[Union[ProcessNetworkInfo, Dict[str, Any], Any]],
    ml_model: Any,
    extractor: Optional[ProcessFeatureExtractor] = None,
) -> float:
    """Apply machine learning cryptojacking prediction signal to a ProcessScore object.

    a. Extracts features using the ProcessFeatureExtractor.
    b. Obtains the probability score using ml_model.predict_risk_score([vector]).
    c. Sets score_obj.ml_confidence = confidence.
    d. Implements hybrid risk fusion: ml_scaled = confidence * 100.0.
       If ml_scaled > score_obj.risk_score, updates score_obj.risk_score = ml_scaled.
    e. If confidence >= 0.7, appends a reason to score_obj.reasons.

    Args:
        score_obj: The ProcessScore dataclass instance to update in-place.
        proc: Process telemetry information.
        network: Process network information.
        ml_model: Trained ML classifier model supporting predict_risk_score.
        extractor: Optional ProcessFeatureExtractor instance.

    Returns:
        The extracted confidence score (float between 0.0 and 1.0).
    """
    if ml_model is None or score_obj is None:
        return 0.0

    try:
        active_extractor = extractor or get_default_feature_extractor()
        vector = active_extractor.extract_vector(proc, network)

        # Get risk probability prediction from the model
        prediction_result = ml_model.predict_risk_score([vector])

        if isinstance(prediction_result, (list, tuple)):
            confidence = float(prediction_result[0])
        else:
            confidence = float(prediction_result)

        confidence = max(0.0, min(1.0, confidence))
    except Exception:
        confidence = 0.0

    # Set ML confidence on the score object
    score_obj.ml_confidence = confidence

    # Hybrid fusion: avoid double-counting by taking max risk signal
    ml_scaled = confidence * 100.0
    if ml_scaled > score_obj.risk_score:
        score_obj.risk_score = min(100.0, ml_scaled)

    # Add descriptive reason when ML prediction has high confidence
    if confidence >= 0.7:
        reason_msg = f"ML Detection: High Confidence ({confidence * 100.0:.1f}%)"
        if reason_msg not in score_obj.reasons:
            score_obj.reasons.append(reason_msg)

    return confidence
