import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Load captured data
def load_data(csv_file="captured_packets.csv"):
    df = pd.read_csv(csv_file)

    # Features we will use for training
    features = ['length', 'payload_size']

    # Fill NaN values if any
    df[features] = df[features].fillna(0)

    return df[features]

# Train Isolation Forest model
def train_model(X):
    model = IsolationForest(
        n_estimators=100, 
        contamination=0.01,  # Expected % of anomalies
        random_state=42
    )
    model.fit(X)
    return model

# Save the trained model
def save_model(model, filename="isolation_forest_model.pkl"):
    joblib.dump(model, filename)
    print(f"Model saved to {filename}")

if __name__ == "__main__":
    X = load_data("../data_collector/captured_packets.csv")
    model = train_model(X)
    save_model(model)
