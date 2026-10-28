"""Probability calibrator for combined risk scoring using Logistic Regression."""
import logging
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

log = logging.getLogger(__name__)


class Calibrator:
    def __init__(self) -> None:
        self.model: LogisticRegression | None = None
        self.fitted = False

    def fit(self, X: np.ndarray | pd.DataFrame, y: np.ndarray | pd.Series) -> bool:
        """Fit logistic regression calibrator if at least 20 rows and both classes exist."""
        if X is None or y is None:
            return False

        n_rows = len(X)
        if n_rows < 20:
            return False

        unique_labels = np.unique(y)
        if len(unique_labels) < 2:
            return False

        try:
            x_arr = X.values if hasattr(X, "values") else np.asarray(X)
            y_arr = y.values if hasattr(y, "values") else np.asarray(y)

            self.model = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
            self.model.fit(x_arr, y_arr)
            self.fitted = True
            return True
        except Exception as exc:
            log.warning("Calibrator fit failed: %s", exc)
            self.fitted = False
            return False

    def predict_proba(self, X: np.ndarray | pd.DataFrame) -> np.ndarray | None:
        """Return array of probabilities for positive class (1), or None if not fitted."""
        if not self.fitted or self.model is None or X is None or len(X) == 0:
            return None

        try:
            x_arr = X.values if hasattr(X, "values") else np.asarray(X)
            # Probability of class 1
            if len(self.model.classes_) == 2:
                idx_pos = int(np.where(self.model.classes_ == 1)[0][0]) if 1 in self.model.classes_ else 1
                return self.model.predict_proba(x_arr)[:, idx_pos]
            return None
        except Exception as exc:
            log.warning("Calibrator predict_proba failed: %s", exc)
            return None
