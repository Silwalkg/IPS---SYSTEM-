"""
Network Traffic Monitor
Captures and analyzes network packets
"""
from scapy.all import sniff, IP, TCP, UDP
import numpy as np

class TrafficMonitor:
    def __init__(self, detector, response_handler):
        self.detector = detector
        self.response_handler = response_handler
        
    def extract_features(self, packet):
        """Extract features from network packet"""
        features = []
        
        if IP in packet:
            features.extend([
                len(packet),
                packet[IP].ttl,
                packet[IP].proto
            ])
            
            if TCP in packet:
                features.extend([
                    packet[TCP].sport,
                    packet[TCP].dport,
                    packet[TCP].flags
                ])
            elif UDP in packet:
                features.extend([
                    packet[UDP].sport,
                    packet[UDP].dport,
                    0  # No flags for UDP
                ])
        
        return np.array(features).reshape(1, -1)
    
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            features = self.extract_features(packet)
            is_threat, confidence = self.detector.predict(features)
            
            if is_threat:
                print(f"[ALERT] Threat detected! Confidence: {confidence:.2f}")
                self.response_handler.handle_threat(packet, confidence)
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start(self):
        """Start monitoring network traffic"""
        print("Monitoring network traffic...")
        sniff(prn=self.packet_callback, store=False)
