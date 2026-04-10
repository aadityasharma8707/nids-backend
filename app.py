from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import joblib
from datetime import datetime
import uvicorn
import random
import speedtest
import threading
import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model_path = os.path.join(BASE_DIR, "xgboost_multiclass_realistic.pkl")

model = joblib.load(model_path)

# For live packet capture
from scapy.all import sniff

app = FastAPI(title="AI-Based Multiclass NIDS 🚀")

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
def start_sniffing():
    print("🚀 Sniffing started...")

    def packet_handler(packet):
        try:
            features = extract_features_from_packet(packet)
            features_np = np.array(features).reshape(1, -1)

            prediction = model.predict(features_np)

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

            print("🔥 LIVE:", log_entry)

        except Exception as e:
            print("Error:", e)

    sniff(prn=packet_handler, store=False)

@app.on_event("startup")
def startup_event():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

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

    # 🔥 attack distribution
    attack_distribution = {}
    for log in logs:
        attack = log["attack_type"]
        attack_distribution[attack] = attack_distribution.get(attack, 0) + 1

    # 🔥 attacks over time (simple grouping)
    attacks_over_time = []
    time_map = {}

    for log in logs:
        time = log["timestamp"][:19]  # yyyy-mm-ddTHH:MM:SS
        time_map[time] = time_map.get(time, 0) + 1

    for t, count in time_map.items():
        attacks_over_time.append({
            "time": t,
            "count": count
        })

    return {
        "total_packets": total,
        "attack_count": attacks,
        "normal_count": normal,
        "attack_distribution": attack_distribution,
        "attacks_over_time": attacks_over_time
    }
@app.get("/network")
def get_network_stats():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()

        download = st.download() / 1_000_000
        upload = st.upload() / 1_000_000
        ping = st.results.ping

        return {
            "download": round(download, 2),
            "upload": round(upload, 2),
            "ping": round(ping, 2)
        }

    except Exception as e:
        # fallback (IMPORTANT for Render)
        return {
            "download": 0,
            "upload": 0,
            "ping": 0,
            "error": "Speedtest failed on server"
        }

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)