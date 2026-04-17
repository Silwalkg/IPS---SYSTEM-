"""
Setup script for AI-Based IPS
Creates required directories and verifies dependencies.
"""
import os
import sys
import subprocess


REQUIRED_DIRS = ['data', 'models']


def create_dirs():
    for d in REQUIRED_DIRS:
        os.makedirs(d, exist_ok=True)
        print(f"  [OK] {d}/")


def install_deps():
    print("\nInstalling dependencies...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])


def main():
    print("=== IPS Setup ===\n")
    print("Creating directories...")
    create_dirs()
    install_deps()
    print("\n[Setup complete]")
    print("\nNext steps:")
    print("  1. (Optional) Place a dataset CSV in data/ for better accuracy")
    print("     - CICIDS 2017: https://www.unb.ca/cic/datasets/ids-2017.html")
    print("     - KDD Cup 99:  http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html")
    print("  2. Train the model:")
    print("     python src/train_model.py")
    print("  3. (Optional) Edit config/config.json to set your network interface,")
    print("     email alerts, and blocking thresholds.")
    print("  4. Run the IPS (requires root/admin for packet capture):")
    print("     sudo python src/main.py")


if __name__ == "__main__":
    main()
