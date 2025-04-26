from scapy.all import sniff
import pandas as pd
import datetime

# List to hold captured packet data
captured_data = []

# Define the packet handler
def packet_callback(packet):
    try:
        # Extract basic packet features
        packet_info = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': packet[0][1].src if hasattr(packet[0][1], 'src') else None,
            'dst_ip': packet[0][1].dst if hasattr(packet[0][1], 'dst') else None,
            'protocol': packet.proto if hasattr(packet, 'proto') else None,
            'length': len(packet),
            'payload_size': len(bytes(packet.payload)) if packet.payload else 0
        }
        
        captured_data.append(packet_info)

        # Optional: Print for debug
        print(packet_info)

    except Exception as e:
        print(f"Error processing packet: {e}")

# Capture live packets
def start_capture(interface="eth0", packet_count=100):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=packet_callback, count=packet_count)

# Save captured data to CSV
def save_to_csv(filename="captured_packets.csv"):
    df = pd.DataFrame(captured_data)
    df.to_csv(filename, index=False)
    print(f"Captured packets saved to {filename}")

if __name__ == "__main__":
    start_capture(interface="eth0", packet_count=100)
    save_to_csv()
