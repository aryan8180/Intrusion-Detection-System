#!/usr/bin/env python3
"""
realtime_detector.py
- Loads models/best_model.joblib
- Tails data/captured_flows.csv for new flow records
- Scores flows and inserts alerts into SQLite database
"""

import os
import time
import sqlite3
import pandas as pd
import joblib
from datetime import datetime

DATA_FILE = os.path.join("data", "captured_flows.csv")
MODEL_FILE = os.path.join("models", "best_model.joblib")
DB_FILE = "alerts.db"

if not os.path.exists(MODEL_FILE):
    print("Model not found. Run train_models.py first.")
    exit(1)

model_bundle = joblib.load(MODEL_FILE)
model = model_bundle["model"]
scaler = model_bundle["scaler"]
mtype = model_bundle.get("type","isolation")

conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    proto TEXT,
    pkt_count INTEGER,
    byte_count INTEGER,
    duration REAL,
    score REAL,
    severity TEXT,
    extra TEXT
)
""")
conn.commit()

def score_row(row):
    feats = ["pkt_count","byte_count","duration","avg_pkt_size","pkt_iat_mean","syn_count","ack_count","rst_count"]
    X = row[feats].astype(float).values.reshape(1,-1)
    Xs = scaler.transform(X)
    if mtype == "isolation":
        # IsolationForest: lower score = more anomalous (decision_function)
        score = model.decision_function(Xs)[0]
        # choose threshold heuristically (user should tune)
        severity = "HIGH" if score < -0.1 else ("MEDIUM" if score < -0.05 else "LOW")
    else:
        # supervised: predict prob of malicious (if classifier supports predict_proba)
        if hasattr(model, "predict_proba"):
            prob = model.predict_proba(Xs)[0][1]
            score = float(prob)
            severity = "HIGH" if prob > 0.7 else ("MEDIUM" if prob > 0.4 else "LOW")
        else:
            pred = model.predict(Xs)[0]
            score = float(pred)
            severity = "HIGH" if pred == 1 else "LOW"
    return score, severity

# Tail the CSV file: remember file pos and read new lines
def tail_and_score():
    # header offset: skip header line
    if not os.path.exists(DATA_FILE):
        print("No data file found:", DATA_FILE)
        return
    with open(DATA_FILE, "r") as f:
        # move to end
        f.seek(0,2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1.0)
                continue
            # parse CSV line
            # header: ts_start,ts_end,src_ip,src_port,dst_ip,dst_port,proto,pkt_count,byte_count,duration,avg_pkt_size,pkt_iat_mean,syn_count,ack_count,rst_count
            parts = line.strip().split(",")
            if len(parts) < 14:
                continue
            try:
                row = {
                    "ts_start": parts[0],
                    "ts_end": parts[1],
                    "src_ip": parts[2],
                    "src_port": int(parts[3]),
                    "dst_ip": parts[4],
                    "dst_port": int(parts[5]),
                    "proto": parts[6],
                    "pkt_count": int(parts[7]),
                    "byte_count": int(parts[8]),
                    "duration": float(parts[9]),
                    "avg_pkt_size": float(parts[10]),
                    "pkt_iat_mean": float(parts[11]),
                    "syn_count": int(parts[12]),
                    "ack_count": int(parts[13]),
                    "rst_count": int(parts[14]) if len(parts) > 14 else 0
                }
            except Exception as e:
                print("Parse error:", e)
                continue
            # score
            score, severity = score_row(pd.Series(row))
            ts = datetime.now().isoformat()
            cur.execute("""
            INSERT INTO alerts (ts,src_ip,dst_ip,proto,pkt_count,byte_count,duration,score,severity,extra)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (ts,row["src_ip"],row["dst_ip"],row["proto"],row["pkt_count"],row["byte_count"],row["duration"],score,severity,""))
            conn.commit()
            print(f"[ALERT] {row['src_ip']} -> {row['dst_ip']} severity={severity} score={score:.4f}")

if __name__ == "__main__":
    tail_and_score()
