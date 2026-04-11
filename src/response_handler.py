"""
Automated Response Handler
Logs threats, sends email alerts, and blocks malicious IPs via firewall.
"""
import os
import sys
import logging
import platform
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from scapy.all import IP
from config_loader import get_config


class ResponseHandler:
    def __init__(self):
        cfg = get_config()
        self.response_cfg = cfg['response']
        self.auto_block = self.response_cfg.get('auto_block', True)
        self.block_threshold = self.response_cfg.get('block_confidence_threshold', 0.7)
        self.email_cfg = self.response_cfg.get('alert_email', {})
        self.blocked_ips = set()

        self._setup_logging()
        self._detect_platform()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _setup_logging(self):
        """Configure logging for threat events."""
        log_file = self.response_cfg.get('log_file', 'data/threats.log')
        log_level = self.response_cfg.get('log_level', 'INFO')

        # Ensure directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            filename=log_file,
            level=getattr(logging, log_level.upper(), logging.INFO),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _detect_platform(self):
        """Detect OS for firewall integration."""
        self.os_type = platform.system().lower()
        if self.os_type not in ('linux', 'windows', 'darwin'):
            print(f"[ResponseHandler] Warning: OS '{self.os_type}' may not support firewall blocking.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def handle_threat(self, packet, confidence: float):
        """
        Handle a detected threat: log it, optionally block the IP, optionally send email.
        """
        src_ip = packet[IP].src if IP in packet else "unknown"

        # Log the threat
        self.logger.warning(f"Threat from {src_ip} | confidence={confidence:.3f}")

        # Block if confidence exceeds threshold
        if self.auto_block and confidence >= self.block_threshold:
            self.block_ip(src_ip)

        # Send email alert if enabled
        if self.email_cfg.get('enabled', False):
            self._send_email_alert(src_ip, confidence)

    def block_ip(self, ip: str):
        """Block an IP address using OS-specific firewall commands."""
        if ip in self.blocked_ips or ip == "unknown":
            return

        self.blocked_ips.add(ip)
        self.logger.critical(f"Blocking IP: {ip}")
        print(f"[BLOCKED] {ip}")

        try:
            if self.os_type == 'linux':
                self._block_ip_linux(ip)
            elif self.os_type == 'windows':
                self._block_ip_windows(ip)
            elif self.os_type == 'darwin':
                self._block_ip_macos(ip)
            else:
                print(f"[ResponseHandler] Firewall blocking not implemented for {self.os_type}")
        except Exception as exc:
            self.logger.error(f"Failed to block {ip}: {exc}")
            print(f"[ResponseHandler] Error blocking {ip}: {exc}")

    # ------------------------------------------------------------------
    # Firewall integration (OS-specific)
    # ------------------------------------------------------------------

    def _block_ip_linux(self, ip: str):
        """Block IP using iptables (Linux)."""
        # Drop all incoming packets from this IP
        subprocess.run(
            ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
            check=True,
            capture_output=True
        )

    def _block_ip_windows(self, ip: str):
        """Block IP using netsh (Windows Firewall)."""
        rule_name = f"IPS_Block_{ip.replace('.', '_')}"
        subprocess.run(
            [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip}'
            ],
            check=True,
            capture_output=True
        )

    def _block_ip_macos(self, ip: str):
        """Block IP using pfctl (macOS)."""
        # Add IP to a pf table (requires pf to be configured)
        subprocess.run(
            ['pfctl', '-t', 'blocklist', '-T', 'add', ip],
            check=True,
            capture_output=True
        )

    # ------------------------------------------------------------------
    # Email alerting
    # ------------------------------------------------------------------

    def _send_email_alert(self, src_ip: str, confidence: float):
        """Send an email alert about the threat."""
        try:
            smtp_host = self.email_cfg.get('smtp_host', 'smtp.gmail.com')
            smtp_port = self.email_cfg.get('smtp_port', 587)
            sender = self.email_cfg.get('sender')
            password = self.email_cfg.get('password')
            recipients = self.email_cfg.get('recipients', [])

            if not sender or not password or not recipients:
                self.logger.warning("Email alert enabled but credentials/recipients missing.")
                return

            subject = f"[IPS ALERT] Threat detected from {src_ip}"
            body = f"""
IPS Threat Alert
================
Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Source IP:  {src_ip}
Confidence: {confidence:.3f}
Action:     {'Blocked' if confidence >= self.block_threshold else 'Logged'}

This is an automated alert from your AI-Based IPS.
"""

            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(sender, password)
                server.send_message(msg)

            self.logger.info(f"Email alert sent for {src_ip}")

        except Exception as exc:
            self.logger.error(f"Failed to send email alert: {exc}")
