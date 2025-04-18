# Main Entry Point
from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem
import time

def main():
    capture = PacketCapture(interface="eth0")
    analyzer = TrafficAnalyzer()
    detector = DetectionEngine()
    alert = AlertSystem()
    
    capture.start()
    
    try:
        while True:
            packet = capture.packet_queue.get(timeout=1)
            features = analyzer.analyze_packet(packet)
            if features:
                threats = detector.detect_threats(features)
                for threat in threats:
                    alert.generate_alert(threat, features)
    except KeyboardInterrupt:
        capture.stop()

if __name__ == "__main__":
    main()