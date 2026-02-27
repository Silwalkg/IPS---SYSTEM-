"""
AI-Based Intrusion Prevention System
Main entry point for the IPS
"""
from traffic_monitor import TrafficMonitor
from ml_detector import MLDetector
from response_handler import ResponseHandler

def main():
    print("Starting AI-Based IPS System...")
    
    # Initialize components
    detector = MLDetector()
    response_handler = ResponseHandler()
    monitor = TrafficMonitor(detector, response_handler)
    
    # Start monitoring
    monitor.start()

if __name__ == "__main__":
    main()
