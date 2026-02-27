"""
ML-based Threat Detector
Uses machine learning models for intrusion detection
"""
from sklearn.ensemble import RandomForestClassifier, IsolationForest
import joblib
import os

class MLDetector:
    def __init__(self, model_path='models/detector.pkl'):
        self.model_path = model_path
        self.model = self.load_or_create_model()
        
    def load_or_create_model(self):
        """Load existing model or create new one"""
        if os.path.exists(self.model_path):
            return joblib.load(self.model_path)
        else:
            # Create anomaly detection model
            return IsolationForest(contamination=0.1, random_state=42)
    
    def predict(self, features):
        """Predict if traffic is malicious"""
        try:
            prediction = self.model.predict(features)
            # -1 for anomaly, 1 for normal
            is_threat = prediction[0] == -1
            confidence = abs(self.model.score_samples(features)[0])
            return is_threat, confidence
        except:
            # Model not trained yet
            return False, 0.0
    
    def train(self, X_train, y_train):
        """Train the detection model"""
        self.model.fit(X_train, y_train)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f"Model trained and saved to {self.model_path}")
