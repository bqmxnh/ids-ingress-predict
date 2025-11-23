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

############
# QuanTC add: 
import requests
from collections import deque
import time
##############

# Flask Setup
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(filename='ids.log', level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s] %(message)s')

MODEL_API_URL = "http://api.qmuit.id.vn/predict"
FEEDBACK_API_URL = "http://api.qmuit.id.vn/feedback"
AWS_REGION = "us-east-1"


#############
# QuanTC add: 
# ==========================================
# CONFIG
# ==========================================
HONEYPOT_URL = "http://honeypot.qmuit.id.vn/receive_attack"
EMAIL_LAMBDA_URL=""
ATTACK_BUFFER = deque() 
BATCH_TIMEOUT = 60
LOCK = threading.Lock()
last_attack_time = None

# ==========================================
# REDIRECT ATTACK TO HONEYPOT
# ==========================================
def redirect_to_honeypot(flow_data, label):
    global last_attack_time
    
    if label.upper() != "ATTACK":
        return
    
    with LOCK:
        # Add to buffer
        ATTACK_BUFFER.append({
            "flow_id": flow_data.get("Flow ID"),
            "timestamp": datetime.now().isoformat(),
            "src_ip": flow_data.get("Source IP"),
            "src_port": flow_data.get("Source Port"),
            "dst_ip": flow_data.get("Destination IP"),
            "dst_port": flow_data.get("Destination Port"),
            "protocol": flow_data.get("Protocol"),
            "features": flow_data,
            "label": label
        })
        last_attack_time = time.time()
    
    # Send to honeypot (non-blocking)
    try:
        requests.post(
            HONEYPOT_URL,
            json=flow_data,
            timeout=2
        )
        print(f"[→ HONEYPOT] Redirected flow {flow_data.get('Flow ID')}")
    except Exception as e:
        print(f"[!] Honeypot error: {e}")

# ==========================================
# BATCH ALERT THREAD
# ==========================================
def batch_alert_worker():
    global last_attack_time
    
    while True:
        time.sleep(1)
        
        with LOCK:
            if not ATTACK_BUFFER:
                continue
            
            # Check timeout
            if last_attack_time and (time.time() - last_attack_time) >= BATCH_TIMEOUT:
                batch_size = len(ATTACK_BUFFER)
                batch_data = list(ATTACK_BUFFER)
                ATTACK_BUFFER.clear()
                last_attack_time = None
                
                # Send email alert
                threading.Thread(
                    target=send_email_alert,
                    args=(batch_size, batch_data),
                    daemon=True
                ).start()

def send_email_alert(count, batch_data):
    try:
        alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        email_body = f"""
        <h2>IDS Attack Detection Alert</h2>
        <p><strong>Time:</strong> {alert_time}</p>
        <p><strong>Total Attack Traffic:</strong> {count} flows</p>
        <h3>Attack Summary:</h3>
        <ul>
        """
        
        for flow in batch_data[:15]: 
            email_body += f"""
            <li>Flow ID: {flow['flow_id']} | 
                Src: {flow['src_ip']}:{flow['src_port']} → 
                Dst: {flow['dst_ip']}:{flow['dst_port']}</li>
            """
        
        if count > 15:
            email_body += f"<li>... and {count - 15} more flows</li>"
        
        email_body += """
        </ul>
        <p>All attack traffic has been redirected to Honeypot system.</p>
        """
        
        # Call Lambda to send email
        response = requests.post(
            EMAIL_LAMBDA_URL,
            json={
                "subject": f"[IDS Alert] {count} Attack Traffic Detected",
                "body": email_body,
                "count": count,
                "timestamp": alert_time
            },
            timeout=5
        )
        
        if response.status_code == 200:
            print(f"[✓] Email alert sent for {count} attacks")
        else:
            print(f"[!] Email send failed: {response.text}")
            
    except Exception as e:
        print(f"[!] Email error: {e}")

# Start batch worker thread
threading.Thread(target=batch_alert_worker, daemon=True).start()
#############

try:
    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = dynamodb.Table("ids_log_system")
except:
    table = None

flow_results = []
flow_lock = threading.Lock()

def safe(v):
    try:
        f = float(v)
        if math.isnan(f) or math.isinf(f):
            return 0.0
        return f
    except:
        return 0.0

def normalize_label(l):
    if not isinstance(l, str): return "unknown"
    return l.lower().strip()

def to_ms(ts):
    try:
        return int(datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timestamp()*1000)
    except:
        return int(datetime.now().timestamp()*1000)

# ============================== FEATURE LIST =========================
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

# ============================== PREDICT ===============================
def predict_api(flow_id, features):
    try:
        payload = {"flow_id": flow_id, "features": features}
        with httpx.Client(timeout=8.0) as c:
            r = c.post(MODEL_API_URL, json=payload)
        data = r.json()
        label = normalize_label(data.get("prediction", "unknown"))
        conf = data.get("confidence", 0.0)
        return label, conf
    except Exception as e:
        logging.error(f"Predict API error: {e}")
        return "error", 0.0

# ============================== LOG TO DYNAMODB ========================
def log_async(result):
    if not table:
        return
    def worker():
        try:
            table.put_item(Item={
                "flow_id": str(result["flow_id"]),
                "timestamp": result["timestamp_ms"],
                "label": normalize_label(result["binary_prediction"]),
                "content": f"{result['src_ip']}:{result['src_port']} → {result['dst_ip']}:{result['dst_port']} ({result['protocol']}) - {result['binary_confidence']}",
                "features_json": json.dumps(result["features"])
            })
        except Exception as e:
            logging.error(f"DynamoDB error: {e}")
    threading.Thread(target=worker, daemon=True).start()

# ============================== PROCESS FLOW ===========================
def process_flow(p):
    features = {f: safe(p.get(f, 0)) for f in FEATURE_COLUMNS}

    flow_id = p.get("Flow ID") or p.get("flow_id") or ""
    label, conf = predict_api(flow_id, features)

    result = {
        "flow_id": flow_id,
        "src_ip": p.get("Source IP", ""),
        "dst_ip": p.get("Destination IP", ""),
        "src_port": p.get("Source Port", ""),
        "dst_port": p.get("Destination Port", ""),
        "protocol": p.get("Protocol", ""),
        "timestamp": p.get("Timestamp"),
        "timestamp_ms": to_ms(p.get("Timestamp")),
        "binary_prediction": label,
        "binary_confidence": conf,
        "features": features,
        "feedback_report": None
    }

    #QuanTC add:
    redirect_to_honeypot(p, label)
    ####

    with flow_lock:
        flow_results.append(result)
        if len(flow_results) > 1000:
            flow_results.pop(0)

    socketio.emit("new_flow", result)
    log_async(result)
    return result

# ============================== INGEST =================================
@app.route("/ingest_flow", methods=["POST"])
def ingest_flow():
    try:
        p = request.get_json(force=True)
        if "batch" in p:
            return jsonify({"results": [process_flow(x) for x in p["batch"]]}), 200
        return jsonify(process_flow(p)), 200
    except Exception as e:
        logging.error(f"Ingest error: {e}")
        return jsonify({"error": str(e)}), 500

# ============================== FEEDBACK + UPDATE UI ====================
@app.route("/feedback_flow", methods=["POST"])
def feedback_flow():
    try:
        p = request.get_json(force=True)

        # ---- Lấy flow_id từ cả 2 kiểu ----
        flow_id = p.get("Flow ID") or p.get("flow_id")

        # ---- Payload gửi tới API học ----
        payload = {
            "flow_id": flow_id,
            "true_label": p.get("true_label"),
            "features": p.get("features", {})
        }

        # ---- Gửi feedback tới model API ----
        with httpx.Client(timeout=8.0) as c:
            r = c.post(FEEDBACK_API_URL, json=payload)

        report = r.json()

        # ---- Gửi event lên UI ----
        socketio.emit("feedback_event", {
            "flow_id": flow_id,
            "true_label": p.get("true_label"),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        # ---- Gắn report vào flow trong bộ nhớ ----
        with flow_lock:
            idx = next((i for i, f in enumerate(flow_results)
                        if f["flow_id"] == flow_id), None)

            if idx is not None:
                flow_results[idx]["feedback_report"] = report
                socketio.emit("update_flow", flow_results[idx])

        # ---- Nếu model học thì highlight ----
        if report.get("learned") is True:
            socketio.emit("learn_event", report)

        return jsonify({"status": "ok", "model_response": report}), 200

    except Exception as e:
        logging.error(f"Feedback error: {e}")
        return jsonify({"error": str(e)}), 500



@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001)
