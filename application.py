#!/usr/bin/env python3
import logging
import json
import math
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix
import boto3
import httpx
import eventlet

# ============================================================
# Eventlet patch (safe)
# ============================================================
# ⚠️ Không patch threading để tránh ảnh hưởng boto3 / httpx
eventlet.monkey_patch(socket=True, select=True, time=True, os=True, thread=False)

# ============================================================
# Flask + SocketIO Setup
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
MODEL_API_URL = "http://34.203.76.187/predict"
AWS_REGION = "us-east-1"

# ============================================================
# DynamoDB Setup
# ============================================================
try:
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = dynamodb.Table("ids_log_system")
    logging.info("Connected to DynamoDB")
except Exception as e:
    table = None
    logging.error(f"DynamoDB init failed: {e}")

# ============================================================
# Thread-safe cache
# ============================================================
flow_results = []
flow_results_lock = threading.Lock()

# ============================================================
# Helper functions
# ============================================================
def safe(val):
    try:
        if val is None:
            return 0.0
        if isinstance(val, bool):
            return float(int(val))
        return float(val)
    except Exception:
        return 0.0


def to_timestamp_ms(dt_str):
    try:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        try:
            dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = datetime.now()
    return int(dt.timestamp() * 1000)


def normalize_label(label):
    if not isinstance(label, str):
        return "unknown"
    return label.strip().lower()


# ============================================================
# Feature columns
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
# Prediction via external model (httpx)
# ============================================================
def predict_features_api(features_dict):
    try:
        # Log features được gửi đi
        logging.info(f"[API SEND] Sending features to model: {json.dumps(features_dict, ensure_ascii=False)[:2000]}")

        with httpx.Client(timeout=8.0) as client:
            response = client.post(MODEL_API_URL, json={"features": features_dict})

        # Log response trả về
        data = response.json()
        logging.info(f"[API RECV] Model response: {data}")

        label = data.get("prediction") or data.get("label", "unknown")
        conf = data.get("confidence") or data.get("probability", 0.0)
        return normalize_label(label), conf

    except Exception as e:
        logging.error(f"Predict API error: {e}")
        return "error", 0.0


# ============================================================
# Log to DynamoDB (async)
# ============================================================
def log_to_dynamodb_async(result):
    if not table:
        return

    def _worker():
        try:
            item = {
                "flow_id": str(result.get("flow_id", "")),
                "timestamp": int(result.get("timestamp_ms", datetime.now().timestamp() * 1000)),
                "label": normalize_label(result.get("binary_prediction", "unknown")),
                "content": (
                    f"Src: {result.get('src_ip')}:{result.get('src_port')} → "
                    f"Dst: {result.get('dst_ip')}:{result.get('dst_port')} ({result.get('protocol')}), "
                    f"Conf: {result.get('binary_confidence', 0):.3f}"
                ),
                "features_json": json.dumps(result.get("features", {}))
            }
            table.put_item(Item=item)
        except Exception as e:
            logging.error(f"DynamoDB log failed: {e}")

    threading.Thread(target=_worker, daemon=True).start()

# ============================================================
# Process flow
# ============================================================
def process_incoming_flow(payload):
    features = {c: safe(payload.get(c, 0)) for c in FEATURE_COLUMNS}
    label, conf = predict_features_api(features)

    result = {
        "flow_id": payload.get("Flow ID", ""),
        "src_ip": payload.get("Source IP", ""),
        "dst_ip": payload.get("Destination IP", ""),
        "src_port": payload.get("Source Port", ""),
        "dst_port": payload.get("Destination Port", ""),
        "protocol": payload.get("Protocol", ""),
        "timestamp": payload.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "timestamp_ms": to_timestamp_ms(payload.get("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))),
        "binary_prediction": label,
        "binary_confidence": conf,
        "features": features,
    }

    with flow_results_lock:
        flow_results.append(result)
        if len(flow_results) > 1000:
            flow_results.pop(0)

    try:
        socketio.emit("new_flow", result)
        eventlet.sleep(0)
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
        return jsonify(process_incoming_flow(payload)), 200
    except Exception as e:
        logging.exception("Ingest error")
        return jsonify({"error": str(e)}), 500

# ============================================================
# Root route
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")

# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    logging.info("IDS Ingress Server starting on port 5001 ...")
    socketio.run(app, host="0.0.0.0", port=5001)
