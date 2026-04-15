"""
Model Training Script
Supports CICIDS 2017 and KDD Cup 99 datasets
"""
import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from ml_detector import MLDetector

DATA_DIR = "data"

def load_cicids(filepath):
    """Load and preprocess CICIDS 2017 dataset"""
    print(f"Loading CICIDS dataset from {filepath}...")
    df = pd.read_csv(filepath)

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Drop rows with inf or NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Label column
    label_col = "Label"
    df[label_col] = df[label_col].str.strip()

    # Encode: BENIGN = 1, everything else = -1 (threat)
    df["target"] = df[label_col].apply(lambda x: 1 if x == "BENIGN" else -1)

    # Drop non-numeric and label columns
    drop_cols = [label_col] + list(df.select_dtypes(exclude=[np.number]).columns)
    X = df.drop(columns=drop_cols + ["target"], errors="ignore")
    y = df["target"]

    return X.values, y.values, list(X.columns)


def load_kdd(filepath):
    """Load and preprocess KDD Cup 99 dataset"""
    print(f"Loading KDD dataset from {filepath}...")

    columns = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
        "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
    ]

    df = pd.read_csv(filepath, names=columns)

    # Encode categorical columns
    le = LabelEncoder()
    for col in ["protocol_type", "service", "flag"]:
        df[col] = le.fit_transform(df[col])

    # Encode label: normal = 1, attack = -1
    df["target"] = df["label"].apply(lambda x: 1 if x.strip() == "normal." else -1)

    X = df.drop(columns=["label", "target"])
    y = df["target"]

    return X.values, y.values, list(X.columns)


def detect_and_load():
    """Auto-detect dataset in data/ folder"""
    for f in os.listdir(DATA_DIR):
        path = os.path.join(DATA_DIR, f)
        if f.endswith(".csv"):
            # Peek at columns to identify dataset
            cols = pd.read_csv(path, nrows=0).columns.str.strip().tolist()
            if "Label" in cols and "Flow Duration" in cols:
                return load_cicids(path)
            elif "label" in [c.lower() for c in cols] and len(cols) >= 41:
                return load_kdd(path)
    return None


def evaluate(model, X_test, y_test):
    """Print evaluation metrics"""
    preds = model.model.predict(X_test)
    print("\n--- Evaluation Report ---")
    print(classification_report(y_test, preds, target_names=["Threat", "Normal"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))


def main():
    result = detect_and_load()

    if result is None:
        print("\nNo dataset found in data/ folder.")
        print("Please download one of the following:")
        print("  CICIDS 2017: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("  KDD Cup 99:  http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html")
        print("Place the CSV file(s) inside the data/ folder and re-run.\n")
        return

    X, y, feature_names = result
    print(f"Dataset loaded: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"Threats: {(y == -1).sum()} | Normal: {(y == 1).sum()}")

    # Scale features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Save scaler for inference
    import joblib
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler, "models/scaler.pkl")
    joblib.dump(feature_names, "models/feature_names.pkl")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining model...")
    detector = MLDetector()
    detector.train(X_train, y_train)

    evaluate(detector, X_test, y_test)
    print("\nModel saved to models/detector.pkl")


if __name__ == "__main__":
    main()
