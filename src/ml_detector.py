"""
ML-based Threat Detector
Uses Isolation Forest for anomaly detection.
Feature set is aligned with traffic_monitor.py (live inference features).
"""
import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config_loader import get_config


class MLDetector:
    def __init__(self):
        cfg = get_config()
        self.model_path = cfg['paths']['model']
        self.scaler_path = cfg['paths']['scaler']
        self.feature_names_path = cfg['paths']['feature_names']
        self.threshold = cfg['detection']['threshold']
        self.contamination = cfg['detection']['contamination']

        self.model = self._load_or_create_model()
        self.scaler = self._load_scaler()
        self.feature_names = self._load_feature_names()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _load_or_create_model(self):
        if os.path.exists(self.model_path):
            print(f"[MLDetector] Loaded model from {self.model_path}")
            return joblib.load(self.model_path)
        print("[MLDetector] No saved model found – using untrained IsolationForest.")
        return IsolationForest(contamination=self.contamination, random_state=42)

    def _load_scaler(self):
        if os.path.exists(self.scaler_path):
            print(f"[MLDetector] Loaded scaler from {self.scaler_path}")
            return joblib.load(self.scaler_path)
        return None

    def _load_feature_names(self):
        if os.path.exists(self.feature_names_path):
            return joblib.load(self.feature_names_path)
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(self, features: np.ndarray):
        """
        Predict whether traffic is malicious.

        Parameters
        ----------
        features : np.ndarray, shape (1, n_features)

        Returns
        -------
        is_threat : bool
        confidence : float  (0.0 – 1.0)
        """
        try:
            if features is None or features.size == 0:
                return False, 0.0

            if self.scaler is not None:
                # Validate feature count matches scaler expectation
                expected = self.scaler.n_features_in_
                if features.shape[1] != expected:
                    print(
                        f"[MLDetector] Feature count mismatch: "
                        f"got {features.shape[1]}, expected {expected}. Skipping prediction."
                    )
                    return False, 0.0
                features = self.scaler.transform(features)

            prediction = self.model.predict(features)
            raw_score = self.model.score_samples(features)[0]

            # score_samples returns negative values; more negative = more anomalous.
            # Map to [0, 1] confidence where 1 = very anomalous.
            confidence = float(np.clip(-raw_score, 0, 1))
            is_threat = bool(prediction[0] == -1) and confidence >= self.threshold

            return is_threat, confidence

        except Exception as exc:
            print(f"[MLDetector] Prediction error: {exc}")
            return False, 0.0

    def train(self, X_train, y_train=None):
        """Fit the model and persist it to disk."""
        print("[MLDetector] Training model...")
        self.model.fit(X_train)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f"[MLDetector] Model saved to {self.model_path}")
