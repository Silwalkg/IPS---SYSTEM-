"""
Model Training Script

Feature alignment strategy:
  The KDD99 dataset has 40+ features but a live packet only exposes a subset.
  We extract the 7 KDD features that map directly to raw packet fields:

    KDD feature       | Packet field
    ------------------|---------------------------
    duration          | always 0 for single packet
    protocol_type     | IP.proto  (encoded: tcp=1, udp=2, icmp=0, other=3)
    src_bytes         | packet length (proxy)
    dst_bytes         | 0 (unknown from single packet)
    land              | 1 if src_ip==dst_ip and sport==dport, else 0
    wrong_fragment    | IP.frag (fragmentation offset > 0)
    urgent            | TCP urgent flag (1/0)

  Plus one extra live feature:
    dst_port          | TCP/UDP destination port

  Total: 8 features — matches traffic_monitor.py N_FEATURES exactly.

  This means we train on the KDD dataset but only keep these 8 columns,
  giving us real attack/normal distributions while staying compatible
  with live inference.
"""
import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, os.path.dirname(__file__))
from config_loader import get_config
from ml_detector import MLDetector

# Resolve data directory — walk up until we find a non-empty data/ folder
def _find_data_dir():
    """Walk up the directory tree to find a data/ folder that contains CSV files."""
    base = os.path.abspath(os.path.dirname(__file__))
    for _ in range(5):
        candidate = os.path.join(base, 'data')
        if os.path.isdir(candidate):
            # Check recursively for any CSV file
            for root, dirs, files in os.walk(candidate):
                if any(f.endswith('.csv') for f in files):
                    return candidate
        base = os.path.dirname(base)
    # fallback — just use the nearest data/ dir
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))

DATA_DIR = _find_data_dir()

# -----------------------------------------------------------------------
# Feature names — must stay in sync with traffic_monitor.py
# -----------------------------------------------------------------------
LIVE_FEATURES = [
    "duration",       # 0 for single packets
    "protocol_type",  # encoded: 0=icmp, 1=tcp, 2=udp, 3=other
    "src_bytes",      # packet length as proxy
    "dst_bytes",      # 0 (unknown)
    "land",           # 1 if src==dst ip+port
    "wrong_fragment", # IP fragmentation flag
    "urgent",         # TCP URG flag
    "dst_port",       # destination port
]
N_FEATURES = len(LIVE_FEATURES)  # 8


# -----------------------------------------------------------------------
# KDD loaders — extract only the 8 aligned features
# -----------------------------------------------------------------------

def _proto_encode(val):
    """Encode protocol string to int."""
    v = str(val).strip().lower()
    if v == 'tcp':  return 1
    if v == 'udp':  return 2
    if v == 'icmp': return 0
    return 3


def load_kdd_cleaned(filepath: str):
    """
    Load the pre-cleaned Kaggle KDD99 CSV (connection_type label).
    Extract only the 8 features that map to live packet fields.
    """
    print(f"[train] Loading cleaned KDD99 from {filepath}...")
    # Read in chunks to handle large files
    chunks = []
    for chunk in pd.read_csv(filepath, chunksize=200_000):
        chunks.append(chunk)
    df = pd.concat(chunks, ignore_index=True)

    # Encode protocol
    df["protocol_type"] = df["protocol_type"].apply(_proto_encode)

    # Build the 8-feature matrix
    X = pd.DataFrame()
    X["duration"]       = df["duration"].astype(float)
    X["protocol_type"]  = df["protocol_type"].astype(float)
    X["src_bytes"]      = df["src_bytes"].astype(float)
    X["dst_bytes"]      = df["dst_bytes"].astype(float)
    X["land"]           = df["land"].astype(float)
    X["wrong_fragment"] = df["wrong_fragment"].astype(float)
    X["urgent"]         = df["urgent"].astype(float)
    # dst_port not in KDD — use dst_host_srv_count as a proxy (connection density)
    X["dst_port"]       = df.get("dst_host_srv_count", pd.Series(0, index=df.index)).astype(float)

    # Labels: normal=1, attack=-1
    label_col = "connection_type"
    y = df[label_col].apply(lambda x: 1 if str(x).strip().lower() == "normal" else -1)

    print(f"[train] Attack types: {df[label_col].value_counts().to_dict()}")
    return X.values, y.values, LIVE_FEATURES


def load_kdd_raw(filepath: str):
    """Load raw KDD99 CSV (41 columns, label column)."""
    print(f"[train] Loading raw KDD99 from {filepath}...")
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
    df["protocol_type"] = df["protocol_type"].apply(_proto_encode)

    X = pd.DataFrame()
    X["duration"]       = df["duration"].astype(float)
    X["protocol_type"]  = df["protocol_type"].astype(float)
    X["src_bytes"]      = df["src_bytes"].astype(float)
    X["dst_bytes"]      = df["dst_bytes"].astype(float)
    X["land"]           = df["land"].astype(float)
    X["wrong_fragment"] = df["wrong_fragment"].astype(float)
    X["urgent"]         = df["urgent"].astype(float)
    X["dst_port"]       = df["dst_host_srv_count"].astype(float)

    y = df["label"].apply(lambda x: 1 if str(x).strip() == "normal." else -1)
    return X.values, y.values, LIVE_FEATURES


def load_cicids(filepath: str):
    """Load CICIDS 2017 — map to 8 live features."""
    print(f"[train] Loading CICIDS 2017 from {filepath}...")
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    X = pd.DataFrame()
    X["duration"]       = df.get("Flow Duration", pd.Series(0, index=df.index)).astype(float)
    X["protocol_type"]  = df.get("Protocol", pd.Series(0, index=df.index)).astype(float)
    X["src_bytes"]      = df.get("Total Length of Fwd Packets", pd.Series(0, index=df.index)).astype(float)
    X["dst_bytes"]      = df.get("Total Length of Bwd Packets", pd.Series(0, index=df.index)).astype(float)
    X["land"]           = 0
    X["wrong_fragment"] = df.get("Fwd Header Length", pd.Series(0, index=df.index)).astype(float)
    X["urgent"]         = df.get("URG Flag Count", pd.Series(0, index=df.index)).astype(float)
    X["dst_port"]       = df.get("Destination Port", pd.Series(0, index=df.index)).astype(float)

    label_col = "Label"
    y = df[label_col].apply(lambda x: 1 if str(x).strip() == "BENIGN" else -1)
    return X.values, y.values, LIVE_FEATURES


# -----------------------------------------------------------------------
# Synthetic fallback
# -----------------------------------------------------------------------

def generate_synthetic_live_data(n_normal: int = 10000, n_attack: int = 2000):
    """Generate synthetic data matching the 8 live features."""
    rng = np.random.default_rng(42)

    normal = np.column_stack([
        np.zeros(n_normal),                              # duration=0
        rng.choice([1, 2], n_normal),                    # protocol: tcp/udp
        rng.integers(40, 1500, n_normal),                # src_bytes
        np.zeros(n_normal),                              # dst_bytes=0
        np.zeros(n_normal),                              # land=0
        np.zeros(n_normal),                              # wrong_fragment=0
        np.zeros(n_normal),                              # urgent=0
        rng.choice([80, 443, 53, 8080, 22], n_normal),  # dst_port
    ]).astype(np.float32)

    attack = np.column_stack([
        np.zeros(n_attack),                              # duration=0
        rng.choice([0, 1, 2, 3], n_attack),              # any protocol
        rng.integers(40, 80, n_attack),                  # tiny packets (scan)
        np.zeros(n_attack),
        rng.choice([0, 1], n_attack, p=[0.95, 0.05]),   # occasional land attack
        rng.choice([0, 1], n_attack, p=[0.8, 0.2]),     # fragmentation
        rng.choice([0, 1], n_attack, p=[0.7, 0.3]),     # urgent flag abuse
        rng.integers(1, 1024, n_attack),                 # scanning low ports
    ]).astype(np.float32)

    X = np.vstack([normal, attack])
    y = np.array([1] * n_normal + [-1] * n_attack)
    return X, y, LIVE_FEATURES


# -----------------------------------------------------------------------
# Dataset auto-detection
# -----------------------------------------------------------------------

def detect_and_load():
    """Walk data/ folder and load the first recognised dataset."""
    if not os.path.isdir(DATA_DIR):
        return None

    for root, dirs, files in os.walk(DATA_DIR):
        for fname in sorted(files):
            if not fname.endswith(".csv"):
                continue
            path = os.path.join(root, fname)
            try:
                cols = pd.read_csv(path, nrows=0).columns.str.strip().tolist()
            except Exception:
                continue
            col_lower = [c.lower() for c in cols]

            if "Label" in cols and "Flow Duration" in cols:
                return load_cicids(path)
            if "connection_type" in col_lower and "src_bytes" in col_lower:
                return load_kdd_cleaned(path)
            if len(cols) >= 41 and "label" in col_lower and "src_bytes" in col_lower:
                return load_kdd_raw(path)
    return None


# -----------------------------------------------------------------------
# Evaluation
# -----------------------------------------------------------------------

def evaluate(detector: MLDetector, X_test: np.ndarray, y_test: np.ndarray):
    preds = detector.model.predict(X_test)
    print("\n--- Evaluation Report ---")
    print(classification_report(y_test, preds, target_names=["Threat (-1)", "Normal (1)"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

def main():
    cfg = get_config()
    model_path      = cfg['paths']['model']
    scaler_path     = cfg['paths']['scaler']
    feat_names_path = cfg['paths']['feature_names']

    print(f"[train] Searching for dataset in: {DATA_DIR}")
    result = detect_and_load()

    if result is None:
        print("[train] No dataset found — using synthetic data.")
        X, y, feature_names = generate_synthetic_live_data()
    else:
        X, y, feature_names = result

    print(f"[train] Samples: {X.shape[0]:,} | Features: {X.shape[1]}")
    print(f"[train] Normal: {(y==1).sum():,} | Threats: {(y==-1).sum():,}")

    # Clean up any NaN/inf that slipped through
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(scaler, scaler_path)
    joblib.dump(feature_names, feat_names_path)
    print(f"[train] Scaler saved → {scaler_path}")
    print(f"[train] Feature names saved → {feat_names_path}")

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    detector = MLDetector()
    detector.train(X_train, y_train)
    evaluate(detector, X_test, y_test)
    print(f"\n[train] Done. Model saved → {model_path}")


if __name__ == "__main__":
    main()
