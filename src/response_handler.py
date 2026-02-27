"""
Automated Response Handler
Takes action when threats are detected
"""
import logging
from datetime import datetime

class ResponseHandler:
    def __init__(self):
        self.setup_logging()
        self.blocked_ips = set()
        
    def setup_logging(self):
        """Configure logging for threats"""
        logging.basicConfig(
            filename='data/threats.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def handle_threat(self, packet, confidence):
        """Handle detected threat"""
        src_ip = packet[0][1].src if len(packet) > 1 else "unknown"
        
        # Log the threat
        logging.warning(f"Threat from {src_ip} - Confidence: {confidence:.2f}")
        
        # Block if high confidence
        if confidence > 0.8:
            self.block_ip(src_ip)
    
    def block_ip(self, ip):
        """Block malicious IP address"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            print(f"[BLOCKED] IP address: {ip}")
            logging.critical(f"Blocked IP: {ip}")
            # Add actual blocking logic here (firewall rules, etc.)
