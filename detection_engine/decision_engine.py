from joblib import load
from detection_engine.signature_matcher import match_signature
import numpy as np

# Load the pre-trained Isolation Forest model
model = load('detection_engine/isolation_forest_model.pkl')

# Anomaly detection threshold
ANOMALY_THRESHOLD = -0.2  # Adjust based on testing

# Hybrid detection function
def hybrid_detection(features, payload):
    """
    features: [length, payload_size] -> list of features
    payload: string (packet payload)
    """
    result = {
        "anomaly_detected": False,
        "signature_detected": [],
        "final_decision": False
    }

    # Predict anomaly
    features_array = np.array(features).reshape(1, -1)
    anomaly_score = model.decision_function(features_array)[0]
    anomaly_prediction = model.predict(features_array)[0]  # 1 (normal), -1 (anomaly)

    # Debug output
    print(f"[DEBUG] Anomaly Score: {anomaly_score}, Prediction: {anomaly_prediction}")

    if anomaly_score < ANOMALY_THRESHOLD or anomaly_prediction == -1:
        result["anomaly_detected"] = True

    # Check for signature matches
    signatures = match_signature(payload)
    if signatures:
        result["signature_detected"] = signatures

    # Final decision: if either anomaly or signature is positive
    if result["anomaly_detected"] or result["signature_detected"]:
        result["final_decision"] = True

    return result

# Example usage
if __name__ == "__main__":
    # Example packet
    packet_features = [200, 50]  # Example: [length, payload_size]
    packet_payload = "SELECT * FROM users WHERE username='admin';"

    detection_result = hybrid_detection(packet_features, packet_payload)

    if detection_result["final_decision"]:
        print("🚨 Threat detected!")
        print(detection_result)
    else:
        print("✅ No threat detected.")
