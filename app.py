from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import joblib
from datetime import datetime
import uvicorn
import random

# For live packet capture
from scapy.all import sniff

app = FastAPI(title="AI-Based Multiclass NIDS 🚀")

# =========================
# LOAD MODEL
# =========================
model = joblib.load("xgboost_multiclass_realistic.pkl")

# =========================
# INPUT SCHEMA
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class InputData(BaseModel):
    features: list

# =========================
# TEMP LOG STORAGE
# =========================
logs = []

# =========================
# ATTACK LABELS
# =========================
attack_labels = {
    0: "BENIGN",
    1: "BOT",
    2: "BruteForce",
    3: "DoS",
    4: "PortScan",
    5: "WebAttack"
}

# =========================
# RISK LOGIC
# =========================
def get_risk_level(attack_type):
    if attack_type == "BENIGN":
        return "LOW"
    elif attack_type == "PortScan":
        return "MEDIUM"
    else:
        return "HIGH"

# =========================
# FEATURE EXTRACTION (LIVE)
# =========================
def extract_features_from_packet(packet):
    features = []

    try:
        # Basic real features
        features.append(len(packet))  # packet size
        features.append(packet.time % 100)  # pseudo timestamp

        features.append(1 if packet.haslayer("TCP") else 0)
        features.append(1 if packet.haslayer("UDP") else 0)
        features.append(1 if packet.haslayer("ICMP") else 0)

    except:
        pass

    # Fill remaining to 78 features
    while len(features) < 78:
        features.append(random.random())

    return features

# =========================
# ROOT
# =========================
@app.get("/")
def home():
    return {"message": "NIDS API Running 🚀"}

# =========================
# NORMAL PREDICT
# =========================
@app.post("/predict")
def predict(data: InputData):
    try:
        features = np.array(data.features).reshape(1, -1)

        prediction = model.predict(features)

        if len(prediction.shape) > 1:
            predicted_class = int(np.argmax(prediction))
        else:
            predicted_class = int(prediction[0])

        attack_type = attack_labels.get(predicted_class, "Unknown")
        risk_level = get_risk_level(attack_type)
        timestamp = datetime.now().isoformat()

        log_entry = {
            "attack_type": attack_type,
            "risk_level": risk_level,
            "timestamp": timestamp
        }

        logs.append(log_entry)

        return log_entry

    except Exception as e:
        return {"error": str(e)}

# =========================
# LIVE PACKET PREDICT
# =========================
@app.get("/live-predict")
def live_predict():
    try:
        packets = sniff(count=1)
        packet = packets[0]

        features = extract_features_from_packet(packet)
        features = np.array(features).reshape(1, -1)

        prediction = model.predict(features)

        if len(prediction.shape) > 1:
            predicted_class = int(np.argmax(prediction))
        else:
            predicted_class = int(prediction[0])

        attack_type = attack_labels.get(predicted_class, "Unknown")
        risk_level = get_risk_level(attack_type)
        timestamp = datetime.now().isoformat()

        log_entry = {
            "attack_type": attack_type,
            "risk_level": risk_level,
            "timestamp": timestamp
        }

        logs.append(log_entry)

        return log_entry

    except Exception as e:
        return {"error": str(e)}

# =========================
# GET LOGS
# =========================
@app.get("/logs")
def get_logs():
    return logs

# =========================
# GET STATS
# =========================
@app.get("/stats")
def get_stats():
    total = len(logs)
    attacks = len([l for l in logs if l["risk_level"] != "LOW"])
    normal = len([l for l in logs if l["risk_level"] == "LOW"])

    return {
        "total_packets": total,
        "attack_count": attacks,
        "normal_count": normal
    }

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)