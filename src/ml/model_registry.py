from __future__ import annotations
from pathlib import Path
from typing import Any, Optional, Union

import joblib

DEFAULT_MODEL_DIR: Path = Path(__file__).resolve().parent.parent.parent / "models"
DEFAULT_MODEL_FILENAME: str = "rf_cryptojack_model.pkl"


def save_model(
    model: Any,
    filepath: Optional[Union[Path, str]] = None,
) -> Path:
    """Save a trained ML model to disk using joblib.

    Args:
        model: Trained model object or pipeline.
        filepath: Destination file path. If omitted or a filename is given without
                  a directory, it defaults to 'models/<filename>'.

    Returns:
        Path to the saved model file.
    """
    if filepath is None:
        destination = DEFAULT_MODEL_DIR / DEFAULT_MODEL_FILENAME
    else:
        target = Path(filepath)
        if target.parent == Path("."):
            destination = DEFAULT_MODEL_DIR / target.name
        else:
            destination = target

    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, destination)
    return destination


def load_model(
    filepath: Optional[Union[Path, str]] = None,
) -> Any:
    """Load a trained ML model from disk using joblib.

    Args:
        filepath: Path to the serialized model file. Defaults to 'models/rf_cryptojack_model.pkl'.

    Returns:
        Loaded model object.

    Raises:
        FileNotFoundError: If the model file does not exist.
    """
    if filepath is None:
        target_path = DEFAULT_MODEL_DIR / DEFAULT_MODEL_FILENAME
    else:
        target = Path(filepath)
        if target.parent == Path(".") and not target.exists():
            target_path = DEFAULT_MODEL_DIR / target.name
        else:
            target_path = target

    if not target_path.exists():
        raise FileNotFoundError(f"Model file not found at: {target_path}")

    return joblib.load(target_path)
