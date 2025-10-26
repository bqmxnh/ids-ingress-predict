import pandas as pd
import logging
import requests
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from datetime import datetime
from pathlib import Path
import threading
import math
import boto3
import json
import eventlet
eventlet.monkey_patch()

# ============================================================
# Flask App Setup
# ============================================================
app = Flask(__name__)

# ✅ Cho phép Flask hiểu header từ ALB (X-Forwarded-For, X-Proto)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# ✅ SocketIO (hỗ trợ WebSocket qua ALB)
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

# ============================================================
# DynamoDB Setup
# ============================================================
try:
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.Table("ids_log_system")
except Exception as e:
    logging.error(f"DynamoDB initialization failed: {e}")
    table = None

# ============================================================
# In-memory flow cache
# ============================================================
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
# Helper: Convert datetime string → timestamp (milliseconds)
# ============================================================
def to_timestamp_ms(dt_str):
    try:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
        return int(dt.timestamp() * 1000)
    except Exception:
        try:
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
            return int(dt.timestamp() * 1000)
        except Exception:
            return int(datetime.now().timestamp() * 1000)

# ============================================================
# Helper: Normalize label
# ============================================================
def normalize_label(label):
    if not isinstance(label, str):
        return "unknown"
    return label.strip().lower()

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
# DynamoDB Logging (Async)
# ============================================================
def log_to_dynamodb_async(result):
    if not table:
        logging.warning("⚠️ DynamoDB table not initialized, skip log.")
        return

    def _worker():
        try:
            features = result.get("features", {})
            content = (
                f"Src: {result.get('src_ip')}:{result.get('src_port')} → "
                f"Dst: {result.get('dst_ip')}:{result.get('dst_port')} ({result.get('protocol')}), "
                f"Confidence: {result.get('binary_confidence', 0):.3f}, "
                f"Flow ID: {result.get('flow_id')}"
            )
            item = {
                "flow_id": str(result.get("flow_id", "")),
                "timestamp": int(result.get("timestamp_ms", datetime.now().timestamp() * 1000)),
                "content": content,
                "label": normalize_label(result.get("binary_prediction", "UNKNOWN")),
                "features_json": json.dumps(features)
            }
            table.put_item(Item=item)
        except Exception as e:
            logging.error(f"DynamoDB insert failed: {e}")

    threading.Thread(target=_worker, daemon=True).start()

# ============================================================
# Prediction via external model API
# ============================================================
def predict_features_api(features_dict):
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
# Process a single incoming flow
# ============================================================
def process_incoming_flow(payload):
    features = {c: safe(payload.get(c, 0)) for c in FEATURE_COLUMNS}
    label, conf = predict_features_api(features)
    meta = {
        "flow_id": payload.get("Flow ID", ""),
        "src_ip": payload.get("Source IP", ""),
        "dst_ip": payload.get("Destination IP", ""),
        "src_port": payload.get("Source Port", ""),
        "dst_port": payload.get("Destination Port", ""),
        "protocol": payload.get("Protocol", ""),
        "timestamp": payload.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "timestamp_ms": to_timestamp_ms(payload.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))),
    }

    result = {**meta, "binary_prediction": normalize_label(label), "binary_confidence": conf, "features": features}

    with flow_results_lock:
        flow_results.append(result)
        if len(flow_results) > 1000:
            flow_results.pop(0)

    try:
        socketio.emit("new_flow", result, broadcast=True, namespace="/")
        eventlet.sleep(0.001)
    except Exception:
        logging.exception("SocketIO emit failed")

    log_to_dynamodb_async(result)
    return result

# ============================================================
# Endpoint: /ingest_flow
# ============================================================
@app.route("/ingest_flow", methods=["POST"])
def ingest_flow():
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
# Main entry point (Eventlet server)
# ============================================================
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001, debug=False)
