#!/usr/bin/env python3
"""
train_models.py
- Train simple ML models on captured flow CSV (expects a CSV with features)
- If label column present ('label'), train supervised RandomForest
- Otherwise, demonstrate unsupervised IsolationForest
- Saves model to models/best_model.joblib
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler

DATA_FILE = os.path.join("data", "captured_flows.csv")
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

def load_data():
    df = pd.read_csv(DATA_FILE)
    # The capture writer doesn't add labels. If you have a labeled dataset, include 'label'
    # For now, we'll demonstrate unsupervised training. If 'label' in df.columns, use supervised.
    return df

def prepare_features(df):
    # select numeric features we created
    feats = ["pkt_count","byte_count","duration","avg_pkt_size","pkt_iat_mean","syn_count","ack_count","rst_count"]
    df = df.dropna(subset=feats)
    X = df[feats].astype(float)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    return Xs, scaler

def train_unsupervised(X):
    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    model.fit(X)
    return model

def train_supervised(X, y):
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X, y)
    return clf

def main():
    df = load_data()
    if df.shape[0] < 10:
        print("Not enough flow samples. Run capture_live.py to collect data first.")
        return
    X, scaler = prepare_features(df)
    if 'label' in df.columns:
        y = df['label'].values
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
        clf = train_supervised(X_train, y_train)
        y_pred = clf.predict(X_test)
        print(classification_report(y_test, y_pred))
        joblib.dump({"model":clf, "scaler":scaler, "type":"supervised"}, os.path.join(MODEL_DIR,"best_model.joblib"))
        print("Saved supervised model.")
    else:
        print("No labels found. Training IsolationForest (unsupervised).")
        iso = train_unsupervised(X)
        joblib.dump({"model":iso, "scaler":scaler, "type":"isolation"}, os.path.join(MODEL_DIR,"best_model.joblib"))
        print("Saved unsupervised model.")

if __name__ == "__main__":
    main()
