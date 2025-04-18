# Alert generation and logging
import logging
import requests
import json
from datetime import datetime

class AlertSystem:
    def __init__(self):
        logging.basicConfig(
            filename='ids_alerts.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
        
    def generate_alert(self, threat, packet_info):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'threat': threat,
            'source_ip': packet_info.get('src_ip'),
            'destination_ip': packet_info.get('dst_ip')
        }
        logging.warning(json.dumps(log_entry))
        
        # Optional: Enrich with AbuseIPDB
        self._enrich_with_abuseipdb(packet_info['src_ip'])
    
    def _enrich_with_abuseipdb(self, ip):
        try:
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                headers={"Key": "YOUR_API_KEY"}
            )
            if response.json()['data']['abuseConfidenceScore'] > 50:
                logging.critical(f"Malicious IP: {ip}")
        except Exception as e:
            pass