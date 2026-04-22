# AI-Based Intrusion Prevention System (IPS)

An intelligent IPS that monitors live network traffic and uses Machine Learning (Isolation Forest) to detect and automatically block threats in real time.

> **Requires Python 3.10+**

---

## Features

- Real-time packet capture via Scapy
- ML-based anomaly detection (Isolation Forest)
- Automatic IP blocking via OS firewall (iptables / Windows Firewall / pfctl)
- Email alerts (SMTP / Gmail)
- Configurable thresholds and network interface
- Supports CICIDS 2017 and KDD Cup 99 training datasets
- Synthetic data fallback for bootstrapping without a dataset

---

## Project Structure

```
IPS---SYSTEM--main/
├── config/
│   └── config.json          # All settings (interface, thresholds, email, paths)
├── data/                    # Threat logs + optional training CSVs (auto-created)
├── models/                  # Saved model, scaler, feature names (auto-created)
├── src/
│   ├── main.py              # Entry point
│   ├── config_loader.py     # Loads config/config.json
│   ├── traffic_monitor.py   # Packet capture & feature extraction
│   ├── ml_detector.py       # Isolation Forest inference
│   ├── response_handler.py  # Logging, firewall blocking, email alerts
│   └── train_model.py       # Model training script
├── requirements.txt
└── setup.py
```

---

## Quick Start

Open a terminal **inside the `IPS---SYSTEM--main` folder** before running any commands.

### 1. Install dependencies

```bash
python setup.py
```

Or manually:

```bash
pip install -r requirements.txt
```

### 2. Train the model

Without a dataset (uses synthetic data to bootstrap):

```bash
python src/train_model.py
```

With a real dataset — place the CSV in `data/` then run the same command.
The script auto-detects CICIDS 2017 and KDD Cup 99 formats.

### 3. Configure (optional)

Edit `config/config.json`:

| Setting | Description |
|---|---|
| `monitoring.interface` | Network interface to sniff (`null` = all interfaces) |
| `monitoring.capture_filter` | BPF filter string e.g. `"tcp or udp"` |
| `detection.threshold` | Minimum anomaly score to flag as threat (0–1) |
| `response.auto_block` | Enable/disable automatic IP blocking |
| `response.block_confidence_threshold` | Minimum confidence to trigger a block |
| `response.alert_email.enabled` | Enable email alerts |

### 4. Run the IPS

Packet capture requires elevated privileges.

**Linux / macOS:**
```bash
sudo python src/main.py
```

**Windows — open PowerShell or CMD as Administrator, then:**
```powershell
python src/main.py
```

---

## Email Alerts

Set `response.alert_email.enabled` to `true` in `config.json` and fill in your credentials:

```json
"alert_email": {
  "enabled": true,
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "sender": "your@gmail.com",
  "password": "your_app_password",
  "recipients": ["admin@example.com"]
}
```

For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833) — not your regular account password.

---

## Firewall Blocking

| OS | Method |
|---|---|
| Linux | `iptables -A INPUT -s <ip> -j DROP` |
| Windows | `netsh advfirewall firewall add rule ...` |
| macOS | `pfctl -t blocklist -T add <ip>` |

Blocking requires root/Administrator privileges. Set `response.auto_block` to `false` to disable.

---

## Training Datasets

| Dataset | URL |
|---|---|
| CICIDS 2017 | https://www.unb.ca/cic/datasets/ids-2017.html |
| KDD Cup 99 | http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html |

Place the CSV file inside `data/` and run `python src/train_model.py`.

---

## Dependencies

| Package | Purpose |
|---|---|
| scapy | Live packet capture |
| scikit-learn | Isolation Forest model |
| numpy / pandas | Feature processing |
| joblib | Model serialisation |

---

## Troubleshooting

**`can't open file '...\setup.py': No such file or directory`**
Your terminal is not in the right folder. Make sure you `cd` into `IPS---SYSTEM--main` first:
```powershell
cd "F:\My Projects\IPS---SYSTEM--main"
python setup.py
```

**`sudo is disabled on this machine` (Windows)**
Windows does not use `sudo`. Instead, right-click PowerShell or CMD and choose **"Run as Administrator"**, then run `python src/main.py` normally.

**Packet capture returns no traffic**
- Confirm you are running as root/Administrator
- Check that `monitoring.interface` in `config.json` matches your actual network adapter name (e.g. `"Ethernet"`, `"Wi-Fi"`, `"eth0"`)
- On Windows you can list interfaces with: `python -c "from scapy.all import get_if_list; print(get_if_list())"`

**Model not found / untrained model warning**
Run `python src/train_model.py` before starting the IPS. The model must be trained at least once before inference works properly.
