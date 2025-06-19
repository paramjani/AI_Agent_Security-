from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import pandas as pd
import pyttsx3
import os
import joblib
from sklearn.ensemble import IsolationForest

LOG_FILE = 'logs.csv'

# === Init ===
if not os.path.exists(LOG_FILE):
    pd.DataFrame(columns=["time", "src", "dst", "protocol", "alert"]).to_csv(LOG_FILE, index=False)

# === Speak Alerts ===
def speak_alert(message):
    engine = pyttsx3.init()
    engine.setProperty('rate', 160)
    engine.say(message)
    engine.runAndWait()

# === ML Anomaly Detection ===
def load_or_train_model():
    if os.path.exists('ml_model.pkl'):
        return joblib.load('ml_model.pkl')
    else:
        # Train on dummy normal traffic
        df = pd.DataFrame({
            'port': [80, 443, 53, 22, 8080, 3306],
            'proto': [6, 6, 17, 6, 6, 6]
        })
        model = IsolationForest(contamination=0.2)
        model.fit(df)
        joblib.dump(model, 'ml_model.pkl')
        return model

model = load_or_train_model()

# === Rules + ML ===
def detect_threat(packet):
    reasons = []

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Rule-based
        if ip_src == "192.168.1.100":
            reasons.append("Blacklisted IP")

        if TCP in packet or UDP in packet:
            port = packet.dport
            if port in [23, 2323, 4444]:
                reasons.append(f"Suspicious Port: {port}")

            # ML model predict
            pred = model.predict([[port, protocol]])[0]
            if pred == -1:
                reasons.append("⚠️ ML Flagged as Anomaly")

        return reasons

    return []

# === Packet Handler ===
def process_packet(packet):
    if IP in packet:
        time = datetime.now().strftime('%H:%M:%S')
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        alert_reasons = detect_threat(packet)
        alert_text = "; ".join(alert_reasons)

        row = {
            "time": time,
            "src": ip_src,
            "dst": ip_dst,
            "protocol": proto,
            "alert": alert_text
        }

        # Append to CSV
        df = pd.DataFrame([row])
        df.to_csv(LOG_FILE, mode='a', index=False, header=False)

        if alert_reasons:
            speak_alert(f"Security Alert: {alert_text} from {ip_src} to {ip_dst}")

# === Start Sniffing ===
def start_monitoring():
    print("🔒 AI Security Agent running...")
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    start_monitoring()
