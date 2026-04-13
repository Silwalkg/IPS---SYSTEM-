"""
AI-Based Intrusion Prevention System
Main entry point
"""
import os
import sys
import platform


def check_privileges():
    """Warn if not running with elevated privileges (required for packet capture)."""
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = (os.geteuid() == 0)

        if not is_admin:
            print(
                "[WARNING] Packet capture typically requires root/administrator privileges.\n"
                "          Run with 'sudo python src/main.py' on Linux/macOS,\n"
                "          or as Administrator on Windows.\n"
            )
    except Exception:
        pass  # Non-critical check


def ensure_directories():
    """Create required directories if they don't exist."""
    for directory in ('data', 'models'):
        os.makedirs(directory, exist_ok=True)


def main():
    print("=" * 50)
    print("  AI-Based Intrusion Prevention System (IPS)")
    print("=" * 50)

    check_privileges()
    ensure_directories()

    # Load config first so all modules can access it
    from config_loader import load_config
    load_config()

    from ml_detector import MLDetector
    from response_handler import ResponseHandler
    from traffic_monitor import TrafficMonitor

    try:
        detector = MLDetector()
        response_handler = ResponseHandler()
        monitor = TrafficMonitor(detector, response_handler)
    except Exception as exc:
        print(f"[ERROR] Failed to initialise IPS components: {exc}")
        sys.exit(1)

    print("[IPS] System ready. Starting traffic monitor...\n")
    monitor.start()


if __name__ == "__main__":
    main()
