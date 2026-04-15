"""
ML-based Threat Detector
Uses Isolation Forest for anomaly detection
"""
from sklearn.ensemble import IsolationForest
import joblib
import os
import numpy as np

class MLDetector:
    def __init__(self, model_path='models/detector.pkl', scaler_path='models/scaler.pkl'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = self.load_or_create_model()
        self.scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None

    def load_or_create_model(self):
        if os.path.exists(self.model_path):
            print(f"Loaded model from {self.model_path}")
            return joblib.load(self.model_path)
        return IsolationForest(contamination=0.1, random_state=42)

    def predict(self, features):
        """Predict if traffic is malicious. Returns (is_threat, confidence)."""
        try:
            if self.scaler:
                features = self.scaler.transform(features)
            prediction = self.model.predict(features)
            score = self.model.score_samples(features)[0]
            # Normalize confidence to 0-1 range
            confidence = float(np.clip(abs(score), 0, 1))
            is_threat = prediction[0] == -1
            return is_threat, confidence
        except Exception as e:
            print(f"Prediction error: {e}")
            return False, 0.0

    def train(self, X_train, y_train=None):
        """Train the detection model and save it"""
        self.model.fit(X_train)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
