# Feature extraction and analysis
from collections import defaultdict

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            flow_key = (src_ip, dst_ip, proto)
            stats = self.flow_stats[flow_key]
            
            # Update stats
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            
            # Return features
            return {
                'packet_size': len(packet),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto
            }
        return None