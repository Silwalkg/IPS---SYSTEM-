"""
Model Training Script
Train ML models on network traffic data
"""
import pandas as pd
import numpy as np
from ml_detector import MLDetector
from sklearn.model_selection import train_test_split

def load_training_data():
    """Load or generate training data"""
    # TODO: Load actual network traffic dataset
    # For now, generate sample data
    n_samples = 1000
    n_features = 6
    
    # Generate normal traffic
    normal = np.random.randn(n_samples, n_features)
    
    # Generate anomalous traffic
    anomalous = np.random.randn(100, n_features) * 3 + 5
    
    X = np.vstack([normal, anomalous])
    y = np.array([1] * n_samples + [-1] * 100)
    
    return X, y

def main():
    print("Loading training data...")
    X, y = load_training_data()
    
    print("Training model...")
    detector = MLDetector()
    detector.train(X, y)
    
    print("Training complete!")

if __name__ == "__main__":
    main()
