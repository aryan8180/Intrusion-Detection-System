#!/usr/bin/env python3
"""
capture_live.py
- Sniffs live packets using Scapy
- Aggregates packets into flows (5-tuple)
- Emits flow records (every X seconds or when flow is inactive) to CSV (data/captured_flows.csv)
Run with sudo/root.
"""

import csv
import os
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP, UDP, Raw

DATA_FILE = os.path.join("data", "captured_flows.csv")
FLOW_TIMEOUT = 5.0  # seconds of inactivity to flush a flow
FLUSH_INTERVAL = 2.0  # how often to check for timed-out flows

# Ensure data dir and CSV header
os.makedirs("data", exist_ok=True)
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ts_start","ts_end","src_ip","src_port","dst_ip","dst_port","proto",
            "pkt_count","byte_count","duration","avg_pkt_size","pkt_iat_mean",
            "syn_count","ack_count","rst_count"
        ])

class Flow:
    def __init__(self, src, sport, dst, dport, proto, ts):
        self.src_ip = src
        self.src_port = sport
        self.dst_ip = dst
        self.dst_port = dport
        self.proto = proto
        self.ts_start = ts
        self.ts_end = ts
        self.pkt_count = 0
        self.byte_count = 0
        self.pkt_times = []
        self.flags = {"SYN":0,"ACK":0,"RST":0}

    def add_packet(self, pkt_len, ts, tcpflags=None):
        self.pkt_count += 1
        self.byte_count += pkt_len
        if self.pkt_times:
            self.pkt_times.append(ts - self.pkt_times[-1] + self.pkt_times[-1])  # store absolute times
        else:
            self.pkt_times.append(ts)
        self.ts_end = ts
        if tcpflags:
            if "S" in tcpflags:
                self.flags["SYN"] += 1
            if "A" in tcpflags:
                self.flags["ACK"] += 1
            if "R" in tcpflags:
                self.flags["RST"] += 1

    def features(self):
        duration = max(0.000001, self.ts_end - self.ts_start)
        avg_pkt_size = self.byte_count / self.pkt_count if self.pkt_count else 0
        # compute inter-arrival times
        iats = []
        if len(self.pkt_times) >= 2:
            for i in range(1, len(self.pkt_times)):
                iats.append(self.pkt_times[i] - self.pkt_times[i-1])
        pkt_iat_mean = sum(iats)/len(iats) if iats else 0
        return {
            "ts_start": datetime.fromtimestamp(self.ts_start).isoformat(),
            "ts_end": datetime.fromtimestamp(self.ts_end).isoformat(),
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "pkt_count": self.pkt_count,
            "byte_count": self.byte_count,
            "duration": round(duration,6),
            "avg_pkt_size": round(avg_pkt_size,2),
            "pkt_iat_mean": round(pkt_iat_mean,6),
            "syn_count": self.flags["SYN"],
            "ack_count": self.flags["ACK"],
            "rst_count": self.flags["RST"]
        }

# flows keyed by tuple (src,dport,dst,dport,proto) and reversed direction combined into single key
flows = {}
flows_lock = threading.Lock()

def flow_key(pkt):
    ip = pkt[IP]
    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        proto = str(ip.proto)
        sport = 0
        dport = 0
    return (ip.src, sport, ip.dst, dport, proto)

def packet_handler(pkt):
    if IP not in pkt:
        return
    ts = pkt.time
    ip = pkt[IP]
    key = flow_key(pkt)
    # normalize key so that client/server ordering doesn't create duplicate flows
    rev_key = (key[2], key[3], key[0], key[1], key[4])
    with flows_lock:
        if key in flows:
            f = flows[key]
        elif rev_key in flows:
            f = flows[rev_key]
        else:
            f = Flow(key[0], key[1], key[2], key[3], key[4], ts)
            flows[key] = f
        pkt_len = len(pkt)
        tcpflags = None
        if TCP in pkt:
            tcpflags = pkt[TCP].flags
        f.add_packet(pkt_len, ts, tcpflags)

def flush_expired():
    while True:
        now = time.time()
        to_flush = []
        with flows_lock:
            for k, f in list(flows.items()):
                if now - f.ts_end > FLOW_TIMEOUT:
                    to_flush.append((k,f))
            for k,_ in to_flush:
                flows.pop(k, None)
        if to_flush:
            file_exists = os.path.exists(DATA_FILE) and os.path.getsize(DATA_FILE) > 0
            with open(DATA_FILE, "a", newline="") as fcsv:
                writer = csv.writer(fcsv)
                # write header if file is empty
                if not file_exists:
                    writer.writerow([
                        "ts_start","ts_end","src_ip","src_port","dst_ip","dst_port","proto",
                        "pkt_count","byte_count","duration","avg_pkt_size","pkt_iat_mean",
                        "syn_count","ack_count","rst_count"
                    ])
                for k, f in to_flush:
                    feat = f.features()
                    writer.writerow([
                        feat["ts_start"],feat["ts_end"],feat["src_ip"],feat["src_port"],
                        feat["dst_ip"],feat["dst_port"],feat["proto"],feat["pkt_count"],
                        feat["byte_count"],feat["duration"],feat["avg_pkt_size"],
                        feat["pkt_iat_mean"],feat["syn_count"],feat["ack_count"],feat["rst_count"]
                    ])
                    print(f"[FLUSH] {feat['src_ip']}->{feat['dst_ip']} pkts={feat['pkt_count']} bytes={feat['byte_count']} dur={feat['duration']}")
        time.sleep(FLUSH_INTERVAL)


def main(interface=None):
    t = threading.Thread(target=flush_expired, daemon=True)
    t.start()
    print("Starting live capture. Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--iface", help="network interface to sniff (e.g., eth0,wlan0)", default=None)
    args = parser.parse_args()
    try:
        main(args.iface)
    except KeyboardInterrupt:
        print("Stopping capture.")
