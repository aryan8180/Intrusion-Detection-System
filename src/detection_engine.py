# Rule + ML threat detection
import yaml
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

class DetectionEngine:
    def __init__(self):
        self.rules = self._load_rules()
        self.model = joblib.load("models/isolation_forest.pkl")

    def _load_rules(self):
        with open("config/signature_rules.yaml") as f:
            return yaml.safe_load(f)['signature_rules']

    def detect_threats(self, features):
        threats = []
        
        # Signature-based detection
        for rule in self.rules:
            if eval(rule['condition'], {}, features):
                threats.append(f"Signature match: {rule['name']}")
        
        # Anomaly detection
        feature_vector = [[features['packet_size']]]
        anomaly_score = self.model.score_samples(feature_vector)[0]
        if anomaly_score < -0.5:
            threats.append(f"Anomaly detected (score: {anomaly_score:.2f})")
        
        return threats