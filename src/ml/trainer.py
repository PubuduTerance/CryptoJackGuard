from __future__ import annotations
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Union

# Ensure project root is in sys.path when executed directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from src.ml.feature_extractor import FEATURE_NAMES
from src.ml.model import CryptoJackModel
from src.ml.model_registry import save_model


def train_and_evaluate(
    data_path: Optional[Union[Path, str]] = None,
    model_save_path: Optional[Union[Path, str]] = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Load dataset, train CryptoJackModel, evaluate metrics, and save serialized model.

    Args:
        data_path: Path to dataset CSV file. Defaults to 'data/synthetic_training_data.csv'.
        model_save_path: Output path for saved model. Defaults to 'models/rf_cryptojack_model.pkl'.
        test_size: Ratio of data reserved for testing (default: 0.2 for 80/20 split).
        random_state: Random seed for reproducibility.

    Returns:
        Dictionary containing trained model, test data, and computed metrics.
    """
    # 1. Resolve dataset path
    if data_path is None:
        base_dir = Path(__file__).resolve().parent.parent.parent
        resolved_data_path = base_dir / "data" / "synthetic_training_data.csv"
    else:
        resolved_data_path = Path(data_path)

    if not resolved_data_path.exists():
        raise FileNotFoundError(f"Training dataset not found at: {resolved_data_path}")

    # 2. Load dataset
    print("=" * 60)
    print(f"[*] Loading training data from: {resolved_data_path}")
    df = pd.read_csv(resolved_data_path)
    print(f"[*] Total dataset rows: {len(df)} | Columns: {list(df.columns)}")

    # 3. Separate features and target labels
    # Map 'BENIGN' -> 0, 'MALICIOUS' -> 1
    X = df[FEATURE_NAMES]
    if df["label"].dtype == object or isinstance(df["label"].iloc[0], str):
        label_map = {"BENIGN": 0, "MALICIOUS": 1}
        y = df["label"].map(label_map).fillna(0).astype(int)
    else:
        y = df["label"].astype(int)

    # 4. Train/Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )
    print(f"[*] Training set size: {len(X_train)} samples")
    print(f"[*] Testing set size:  {len(X_test)} samples")
    print("=" * 60)

    # 5. Initialize and train CryptoJackModel
    print("[*] Training CryptoJackModel (RandomForestClassifier)...")
    model = CryptoJackModel(n_estimators=100, max_depth=10, random_state=random_state)
    model.train(X_train, y_train)
    print("[+] Model training completed successfully.")
    print("=" * 60)

    # 6. Evaluate model on test set
    y_pred = model.predict(X_test)
    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["BENIGN (0)", "MALICIOUS (1)"])

    print("               MODEL EVALUATION METRICS")
    print("-" * 60)
    print(f"  Accuracy:         {accuracy * 100:.2f}%")
    print(f"  Precision:        {precision * 100:.2f}%")
    print(f"  Recall:           {recall * 100:.2f}%")
    print(f"  F1 Score:         {f1 * 100:.2f}%")
    print("-" * 60)
    print("Confusion Matrix:")
    print(f"  [TN={cm[0, 0]:<4}  FP={cm[0, 1]:<4}]  (Actual BENIGN)")
    print(f"  [FN={cm[1, 0]:<4}  TP={cm[1, 1]:<4}]  (Actual MALICIOUS)")
    print("-" * 60)
    print("Detailed Classification Report:\n" + report)
    print("=" * 60)

    # 7. Save trained model
    saved_path = save_model(model, model_save_path or "rf_cryptojack_model.pkl")
    print(f"[+] Trained model saved to: {saved_path}")
    print("=" * 60)

    return {
        "model": model,
        "saved_path": saved_path,
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "confusion_matrix": cm,
        },
        "test_data": (X_test, y_test, y_pred),
    }


if __name__ == "__main__":
    train_and_evaluate()
