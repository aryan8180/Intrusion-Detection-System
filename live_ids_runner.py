import time
import socket
import struct
import requests
import numpy as np
from scapy.all import sniff
from detection_engine.isolation_forest_model import load_model
from detection_engine.signature_matcher import match_signature
from detection_engine.decision_engine import hybrid_detection
import datetime

# Constants
API_URL = "http://127.0.0.1:8000/alert/"  # FastAPI backend endpoint
ANOMALY_THRESHOLD = -0.2  # Threshold for anomaly detection

# Load the pre-trained Isolation Forest model
model = load_model()

# Function to send an alert to the backend
def send_alert(source_ip, destination_ip, description):
    alert_data = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "description": description,
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    try:
        response = requests.post(API_URL, json=alert_data)
        print(f"Alert sent: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending alert: {e}")

# Callback for packet processing
def process_packet(packet):
    if packet.haslayer('IP'):
        source_ip = packet['IP'].src
        destination_ip = packet['IP'].dst
        payload = str(packet['Raw'].load) if packet.haslayer('Raw') else ""
        
        # Extract packet features (example: length, payload size)
        packet_features = [len(packet), len(payload)]
        
        # Run hybrid detection: anomaly + signature
        detection_result = hybrid_detection(packet_features, payload)
        
        if detection_result["final_decision"]:
            alert_description = "Anomaly Detected" if detection_result["anomaly_detected"] else "Signature Detected"
            print(f"🚨 Threat detected from {source_ip} to {destination_ip}: {alert_description}")
            send_alert(source_ip, destination_ip, alert_description)

# Start sniffing packets (you can filter by IP or protocol if needed)
print("Starting packet capture...")
sniff(prn=process_packet, store=0, filter="ip", iface="eth0", timeout=60)
