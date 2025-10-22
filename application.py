import pandas as pd
import logging
import requests
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from datetime import datetime
from pathlib import Path
import threading
import math

# ============================================================
# Flask App Setup
# ============================================================
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# ============================================================
# Logging Configuration
# ============================================================
logging.basicConfig(
    filename='ids.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# ============================================================
# Configuration
# ============================================================
MODEL_API_URL = "http://52.73.129.151/predict"  # FastAPI/ML model endpoint
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = OUTPUT_DIR / "predictions.csv"

# In-memory flow cache
flow_results = []
flow_results_lock = threading.Lock()

# ============================================================
# Helper: Safe numeric conversion
# ============================================================
def safe(val):
    try:
        if val is None:
            return 0
        if isinstance(val, bool):
            return int(val)
        if isinstance(val, (int, float)):
            return float(val)
        return float(val)
    except Exception:
        return 0

# ============================================================
# Feature columns (77)
# ============================================================
FEATURE_COLUMNS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# ============================================================
# Prediction via external model API
# ============================================================
def predict_features_api(features_dict):
    """Send features to external model API for prediction."""
    try:
        response = requests.post(MODEL_API_URL, json={"features": features_dict}, timeout=8)
        response.raise_for_status()
        data = response.json()
        label = data.get("prediction") or data.get("label", "UNKNOWN")
        confidence = data.get("confidence") or data.get("probability", None)
        return label, confidence
    except Exception as e:
        logging.error(f"Predict API error: {e}")
        return "ERROR", None

# ============================================================
# Process a single incoming flow (from CSV or live)
# ============================================================
def process_incoming_flow(payload):
    """Process one flow or feature set received from /ingest_flow."""
    # Extract 77 features only (ignore metadata)
    features = {c: safe(payload.get(c, 0)) for c in FEATURE_COLUMNS}

    # Predict using external API
    label, conf = predict_features_api(features)

    # Extract metadata (for dashboard only)
    meta = {
        "flow_id": payload.get("Flow ID", ""),
        "src_ip": payload.get("Source IP", ""),
        "dst_ip": payload.get("Destination IP", ""),
        "src_port": payload.get("Source Port", ""),
        "dst_port": payload.get("Destination Port", ""),
        "protocol": payload.get("Protocol", ""),
        "timestamp": payload.get("Timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Combine result for realtime dashboard
    result = {
        **meta,
        "binary_prediction": label,
        "binary_confidence": conf,
        "features": features
    }

    # Store and emit
    with flow_results_lock:
        flow_results.append(result)
        if len(flow_results) > 1000:
            flow_results.pop(0)
    try:
        socketio.emit("new_flow", result)
    except Exception:
        logging.exception("SocketIO emit failed")

    # Write CSV (only 77 features + Label)
    row = features.copy()
    row["Label"] = label
    pd.DataFrame([row]).to_csv(OUTPUT_CSV, mode='a', index=False, header=not OUTPUT_CSV.exists())

    return result

# ============================================================
# Endpoint: /ingest_flow
# ============================================================
@app.route("/ingest_flow", methods=["POST"])
def ingest_flow():
    """Receive single flow or batch from machine A."""
    try:
        payload = request.get_json(force=True)
        if payload is None:
            return jsonify({"error": "No JSON body"}), 400

        if "batch" in payload:
            results = [process_incoming_flow(p) for p in payload["batch"]]
            return jsonify({"results": results}), 200
        else:
            result = process_incoming_flow(payload)
            return jsonify(result), 200
    except Exception as e:
        logging.exception("Ingest flow error")
        return jsonify({"error": str(e)}), 500

# ============================================================
# Root route → render dashboard
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")

# ============================================================
# Main entry point
# ============================================================
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001, debug=True)

