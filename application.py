#!/usr/bin/env python3
import eventlet
eventlet.monkey_patch(socket=True, select=True, time=True, os=True, thread=False)

import logging
import json
import threading
import math
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix
import boto3
import httpx
import os

# ============================================================
# Flask
# ============================================================
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
socketio = SocketIO(app, cors_allowed_origins="*")

# ============================================================
# Logging
# ============================================================
logging.basicConfig(
    filename='ids.log',
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# ============================================================
# Config
# ============================================================
MODEL_API_URL = "http://api.qmuit.id.vn/predict"
FEEDBACK_API_URL = "http://api.qmuit.id.vn/feedback"
AWS_REGION = "us-east-1"

logging.info(f"Using MODEL_API_URL={MODEL_API_URL}")
logging.info(f"Using FEEDBACK_API_URL={FEEDBACK_API_URL}")

# ============================================================
# DynamoDB
# ============================================================
try:
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = dynamodb.Table("ids_log_system")
    logging.info("Connected to DynamoDB")
except:
    table = None

# ============================================================
# Helper
# ============================================================
def safe(val):
    try:
        if val is None: return 0.0
        if isinstance(val, bool): return float(int(val))
        f = float(val)
        if math.isnan(f) or math.isinf(f): return 0.0
        return f
    except:
        return 0.0

def to_timestamp_ms(dt_str):
    try:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
    except:
        try:
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except:
            dt = datetime.now()
    return int(dt.timestamp() * 1000)

def normalize_label(label):
    if not isinstance(label, str):
        return "unknown"
    return label.strip().lower()

# ============================================================
# Features
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
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# ============================================================
# Predict → Model API
# ============================================================
def predict_features_api(flow_id, features):
    try:
        with httpx.Client(timeout=8) as client:
            response = client.post(MODEL_API_URL, json={
                "flow_id": flow_id,
                "features": features
            })
        data = response.json()
        return normalize_label(data.get("prediction")), data.get("confidence", 0.0)
    except Exception as e:
        logging.error(f"Predict error: {e}")
        return "error", 0.0

# ============================================================
# Process Flow
# ============================================================
def process_incoming_flow(payload):
    features = {c: safe(payload.get(c, 0)) for c in FEATURE_COLUMNS}

    flow_id = payload.get("Flow ID", "")
    label, conf = predict_features_api(flow_id, features)

    result = {
        "flow_id": flow_id,
        "src_ip": payload.get("Source IP", ""),
        "dst_ip": payload.get("Destination IP", ""),
        "src_port": payload.get("Source Port", ""),
        "dst_port": payload.get("Destination Port", ""),
        "protocol": payload.get("Protocol", ""),
        "timestamp": payload.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "timestamp_ms": to_timestamp_ms(payload.get("Timestamp", "")),
        "binary_prediction": label,
        "binary_confidence": conf,
        "features": features,
    }

    socketio.emit("new_flow", result)
    eventlet.sleep(0)

    return result

# ============================================================
# Endpoints
# ============================================================
@app.route("/ingest_flow", methods=["POST"])
def ingest_flow():
    payload = request.get_json(force=True)
    if not payload:
        return jsonify({"error": "No JSON"}), 400

    if "batch" in payload:
        return jsonify({"results": [process_incoming_flow(p)
                                    for p in payload["batch"]]}), 200
    return jsonify(process_incoming_flow(payload)), 200


# ============================================================
# Feedback → Forward full JSON
# ============================================================
@app.route("/feedback_flow", methods=["POST"])
def feedback_flow():
    try:
        payload = request.get_json(force=True)

        with httpx.Client(timeout=8.0) as client:
            response = client.post(FEEDBACK_API_URL, json=payload)

        data = response.json()  # FULL FEEDBACK INFO

        # emit full data
        socketio.emit("feedback_event", data)
        eventlet.sleep(0)

        logging.info(f"[FEEDBACK] Forwarded: {data}")

        return jsonify({"status": "forwarded", "model_response": data}), 200

    except Exception as e:
        logging.error(e, exc_info=True)
        return jsonify({"error": str(e)}), 500


# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001)
