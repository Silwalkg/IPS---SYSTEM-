"""
Network Traffic Monitor
Captures and analyses network packets in real time.

Feature vector — must stay in sync with train_model.py LIVE_FEATURES (N=8):
  0  duration        – always 0 for a single raw packet
  1  protocol_type   – 0=icmp, 1=tcp, 2=udp, 3=other
  2  src_bytes       – total packet length (proxy for src_bytes)
  3  dst_bytes       – 0 (unknown from a single packet)
  4  land            – 1 if src_ip==dst_ip and sport==dport, else 0
  5  wrong_fragment  – 1 if IP fragment offset > 0, else 0
  6  urgent          – 1 if TCP URG flag set, else 0
  7  dst_port        – TCP/UDP destination port (0 if neither)
"""
import signal
import sys
import numpy as np
from scapy.all import sniff, IP, TCP, UDP

from config_loader import get_config

# Number of features extracted per packet – must stay in sync with train_model.py
N_FEATURES = 8


class TrafficMonitor:
    def __init__(self, detector, response_handler):
        self.detector = detector
        self.response_handler = response_handler
        cfg = get_config()
        self.interface = cfg['monitoring'].get('interface') or None
        self.capture_filter = cfg['monitoring'].get('capture_filter', 'tcp or udp')
        self._running = False
        self._packet_count = 0

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_features(self, packet) -> np.ndarray | None:
        """
        Extract the 8-feature vector aligned with KDD99 training features.
        Returns None if the packet has no IP layer.
        """
        if IP not in packet:
            return None

        ip = packet[IP]

        # protocol_type: 0=icmp, 1=tcp, 2=udp, 3=other
        proto_map = {6: 1, 17: 2, 1: 0}
        protocol_type = proto_map.get(int(ip.proto), 3)

        src_bytes = len(packet)
        dst_bytes = 0  # unknown from a single packet

        # land: 1 if src and dst are the same host+port
        land = 0
        dst_port = 0
        urgent = 0

        if TCP in packet:
            tcp = packet[TCP]
            dst_port = int(tcp.dport)
            urgent = 1 if tcp.flags & 0x20 else 0  # URG flag
            if ip.src == ip.dst and tcp.sport == tcp.dport:
                land = 1
        elif UDP in packet:
            udp = packet[UDP]
            dst_port = int(udp.dport)
            if ip.src == ip.dst and udp.sport == udp.dport:
                land = 1

        # wrong_fragment: fragmented packet
        wrong_fragment = 1 if int(ip.frag) > 0 else 0

        features = np.array(
            [0, protocol_type, src_bytes, dst_bytes, land, wrong_fragment, urgent, dst_port],
            dtype=np.float32
        ).reshape(1, -1)

        return features

    # ------------------------------------------------------------------
    # Packet callback
    # ------------------------------------------------------------------

    def packet_callback(self, packet):
        """Process each captured packet."""
        self._packet_count += 1
        try:
            features = self.extract_features(packet)
            if features is None:
                return

            is_threat, confidence = self.detector.predict(features)
            src_ip = packet[IP].src if IP in packet else "unknown"

            # Print every 50th packet so user can see traffic is flowing
            if self._packet_count % 50 == 0:
                print(f"[TrafficMonitor] Packets processed: {self._packet_count} | Last src: {src_ip} | score: {confidence:.3f}")

            if is_threat:
                print(f"[ALERT] Threat from {src_ip} | confidence={confidence:.3f}")
                self.response_handler.handle_threat(packet, confidence)

        except Exception as exc:
            print(f"[TrafficMonitor] Error processing packet: {exc}")

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------

    def start(self):
        """Start sniffing network traffic (blocking call)."""
        self._running = True

        # Graceful shutdown on Ctrl-C / SIGTERM
        def _shutdown(sig, frame):
            print("\n[TrafficMonitor] Shutting down...")
            self._running = False
            sys.exit(0)

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        iface_msg = self.interface or "all interfaces"
        print(f"[TrafficMonitor] Monitoring {iface_msg} | filter: '{self.capture_filter}'")

        sniff(
            iface=self.interface,
            filter=self.capture_filter,
            prn=self.packet_callback,
            store=False,
        )
