#!/usr/bin/env python3
import logging
import json
import threading
import math
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix
import boto3
import httpx
import os
from boto3.dynamodb.conditions import Key


############
# QuanTC add: 
import requests
from collections import deque
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),  # Console output
        logging.FileHandler('/home/ubuntu/logs/ids_agent.log')  # File output
    ]
)
logger = logging.getLogger(__name__)

from metrics_collector import metrics as redirection_metrics
##############

# Flask Setup
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(filename='ids.log', level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s] %(message)s')

MODEL_API_URL = "http://api.qmuit.id.vn/predict"
FEEDBACK_API_URL = "http://api.qmuit.id.vn/feedback"
EVALUATE_API_URL = "http://api.qmuit.id.vn/evaluate"
AWS_REGION = "us-east-1"
HTTPX_CLIENT = httpx.Client(timeout=10.0)


#############
# QuanTC add: 
# ==========================================
# CONFIG
# ==========================================
mail_url=os.getenv("EMAIL_LAMBDA_URL", "") 
HONEYPOT_URL = "http://honeypot.qmuit.id.vn/receive_attack"
EMAIL_LAMBDA_URL=mail_url
ATTACK_BUFFER = deque() 
BATCH_TIMEOUT = 60
LOCK = threading.Lock()
last_attack_time = None

logger.info("=" * 60)
logger.info("IDS AGENT CONFIGURATION")
logger.info("=" * 60)
logger.info(f"HONEYPOT_URL     : {HONEYPOT_URL}")
logger.info(f"EMAIL_LAMBDA_URL : {EMAIL_LAMBDA_URL if EMAIL_LAMBDA_URL else '⚠️  NOT SET'}")
logger.info(f"BATCH_TIMEOUT    : {BATCH_TIMEOUT}s")
logger.info("=" * 60)

if not EMAIL_LAMBDA_URL:
    logger.warning("⚠️  EMAIL_LAMBDA_URL is empty! Email alerts are DISABLED.")
else:
    logger.info("✅ Email alerts are ENABLED")
# ==========================================
# REDIRECT ATTACK TO HONEYPOT
# ==========================================
def redirect_to_honeypot(flow_data, label, confidence):
    """
    Redirect attack traffic to honeypot system with performance tracking
    
    Implementation based on:  
      Beltran Lopez, P., et al. (2024). Cyber Deception Reactive:  
      TCP Stealth Redirection to On-Demand Honeypots. arXiv:2402.09191v2
      
    Args:
        flow_data: Dictionary containing flow features and metadata (5-tuple + features)
        label: Predicted label from IDS (BENIGN/ATTACK)
        confidence: Model confidence score (0.0 - 1.0)
    
    Process:
      1. Validate attack classification
      2. Prepare enriched redirection metadata
      3. Measure redirection latency (for stealth evaluation)
      4. Send to honeypot via HTTP POST
      5. Record metrics for performance analysis
      6. Buffer for batch email alerts
    
    Stealth Requirement (from paper):
      - Latency must be < 10ms for 95% of redirections
      - This ensures attackers cannot detect the redirection
    """
    global last_attack_time
    
    if label.upper() != "ATTACK":
        return
    
    # ============================================
    # STEP 1: Extract flow metadata (5-tuple)
    # ============================================
    flow_id = flow_data.get("Flow ID")
    if not flow_id or flow_id == "unknown": 
        # Generate unique flow_id with timestamp
        import uuid
        flow_id = f"flow_{datetime.now().timestamp()}_{uuid.uuid4().hex[:8]}"
    src_ip = flow_data.get("Source IP", "")
    src_port = flow_data.get("Source Port", "")
    dst_ip = flow_data. get("Destination IP", "")
    dst_port = flow_data.get("Destination Port", "")
    protocol = flow_data.get("Protocol", "")
    
    # ============================================
    # STEP 2: Prepare enriched redirection metadata
    # ============================================
    # Per Beltran Lopez et al. (2024), redirection metadata should include:
    # - Original flow identification (5-tuple)
    # - IDS detection decision (label + confidence)
    # - Session state information
    # - Timestamp for correlation
    
    redirection_metadata = {
        # === Flow Identification ===
        "flow_id": flow_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        
        # === 5-tuple (Network Flow Identity) ===
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip":  dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        
        # === IDS Detection Decision ===
        "ids_label": label,
        "ids_confidence": round(confidence, 4),
        "detection_timestamp": datetime.now(timezone.utc).isoformat(),
        
        # === Redirection Information ===
        "redirection_decision": "REDIRECT_TO_HONEYPOT",
        "redirection_method": "HTTP_JSON_SIMULATION",  # Honest about simulation approach
        "honeypot_target":  HONEYPOT_URL,
        "redirection_reason": f"IDS classified as {label} with {confidence*100:.1f}% confidence",
        
        # === Flow Features (for honeypot deep analysis) ===
        "flow_features": flow_data,
        
        # === Session Metadata (simulated TCP state) ===
        "session_metadata": {
            "total_packets": int(flow_data.get("Total Fwd Packets", 0)) + int(flow_data.get("Total Backward Packets", 0)),
            "total_bytes": int(flow_data.get("Total Length of Fwd Packets", 0)) + int(flow_data.get("Total Length of Bwd Packets", 0)),
            "flow_duration_ms": float(flow_data.get("Flow Duration", 0)),
            "tcp_flags": {
                "SYN": int(flow_data.get("SYN Flag Count", 0)),
                "FIN": int(flow_data. get("FIN Flag Count", 0)),
                "RST":  int(flow_data.get("RST Flag Count", 0)),
                "PSH": int(flow_data.get("PSH Flag Count", 0)),
                "ACK": int(flow_data.get("ACK Flag Count", 0))
            }
        }
    }
    
    # ============================================
    # STEP 3: Buffer for batch email alert
    # ============================================
    with LOCK:
        ATTACK_BUFFER.append({
            "flow_id": flow_id,
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "features": flow_data,
            "label": label,
            "confidence":  confidence
        })
        last_attack_time = time.time()
    
    # ============================================
    # STEP 4: Send to honeypot with latency measurement
    # ============================================
    # Per Beltran Lopez et al.  (2024):
    # - Mean latency: 2.3ms
    # - Max latency: 8.7ms
    # - Stealth requirement:  < 10ms (undetectable by humans)
    
    start_time = time.time()
    success = False
    error_msg = None
    
    try:
        response = requests.post(
            HONEYPOT_URL,
            json=redirection_metadata,
            headers={
                "X-IDS-Agent": "ARF-IDS-v1.0",
                "X-Flow-ID": flow_id,
                "X-IDS-Confidence": str(confidence),
                "Content-Type": "application/json"
            },
            timeout=3  # 3 second timeout
        )
        
        # Calculate latency in milliseconds
        latency_ms = (time.time() - start_time) * 1000
        
        if response.status_code == 200:
            success = True
            logger.info(
                f"[→ HONEYPOT] Flow {flow_id[:16]}...  | "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"Proto: {protocol} | "
                f"Conf: {confidence*100:.2f}% | "
                f"Latency: {latency_ms:.2f}ms"
            )
        else:
            error_msg = f"HTTP {response.status_code}"
            logger.warning(
                f"[!  HONEYPOT] Flow {flow_id[:16]}... | "
                f"Failed with HTTP {response.status_code} | "
                f"Latency: {latency_ms:.2f}ms"
            )
        
        # ✅ RECORD METRICS for performance evaluation
        redirection_metrics.record_redirection(flow_id, latency_ms, success, error_msg)
        
    except requests.exceptions.Timeout:
        latency_ms = (time.time() - start_time) * 1000
        error_msg = "Timeout (>3s)"
        logger.error(f"[✗ HONEYPOT] Flow {flow_id[:16]}...  | Timeout after {latency_ms:.2f}ms")
        redirection_metrics.record_redirection(flow_id, latency_ms, False, error_msg)
        
    except requests.exceptions.ConnectionError as e:
        latency_ms = (time.time() - start_time) * 1000
        error_msg = f"Connection Error: {str(e)[:50]}"
        logger.error(f"[✗ HONEYPOT] Flow {flow_id[:16]}... | Connection failed:  {e}")
        redirection_metrics. record_redirection(flow_id, latency_ms, False, error_msg)
        
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        error_msg = f"Error: {str(e)[:50]}"
        logger.error(f"[✗ HONEYPOT] Flow {flow_id[:16]}... | Unexpected error: {e}")
        redirection_metrics.record_redirection(flow_id, latency_ms, False, error_msg)
# ==========================================
# BATCH ALERT THREAD
# ==========================================
def batch_alert_worker():
    global last_attack_time
    
    while True:
        time.sleep(1)
        batch_data = None
        with LOCK:
            if not ATTACK_BUFFER:
                continue
            
            # Check timeout
            if last_attack_time and (time.time() - last_attack_time) >= BATCH_TIMEOUT:
                batch_size = len(ATTACK_BUFFER)
                batch_data = list(ATTACK_BUFFER)
                ATTACK_BUFFER.clear()
                last_attack_time = None
                
        if batch_data:
            threading.Thread(
                target=send_email_alert,
                args=(batch_data,),
                daemon=True
            ).start()

def send_email_alert(batch_data):  # ✅ NHẬN batch_data từ args
    """Send batch email alert after timeout"""
    
    if not batch_data:
        return
    
    try:
        batch_count = len(batch_data)
        
        # Generate email HTML
        dt_now = datetime.now(timezone(timedelta(hours=7)))
        timestamp_display = dt_now.strftime('%Y-%m-%d %H:%M:%S')  # 2025-11-26 22:48:46
        timestamp_iso = dt_now.isoformat()
        subject = f"🚨 ARF IDS Alert - {batch_count} attacks detected in last batch"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2 style="color: #d9534f;">IDS Attack Detection Alert</h2>
            <p><strong>Time:</strong> {timestamp_display}</p>
            <p><strong>Total Attack Traffic:</strong> {batch_count} flows</p>
            
            <h3>Attack Summary:</h3>
            <ul>
        """
        
        # ✅ DÙNG batch_data thay vì ATTACK_BUFFER
        for i, flow in enumerate(batch_data[:15], 1):
            flow_id = flow.get("flow_id", "unknown")
            src_ip = flow.get("src_ip", "")
            src_port = flow.get("src_port", "")
            dst_ip = flow.get("dst_ip", "")
            dst_port = flow.get("dst_port", "")
            
            html_body += f"""
            <li>
                Flow ID: {flow_id} | 
                Src: <a href="http://ip-api.com/json/{src_ip}">{src_ip}:{src_port}</a> → 
                Dst: <a href="http://ip-api.com/json/{dst_ip}">{dst_ip}:{dst_port}</a>
            </li>
            """
        
        if batch_count > 15:
            html_body += f"<li>... and {batch_count - 15} more flows</li>"
        
        html_body += """
            </ul>
            <p style="color: #5bc0de;">
                All attack traffic has been redirected to Honeypot system.
            </p>
            <p style="color: #5bc0de;">
                Check: http://honeypot.qmuit.id.vn/stats
            </p>
        </body>
        </html>
        """
        
        # Send email via Lambda
        if EMAIL_LAMBDA_URL:
            payload = {
                "subject": subject,
                "body": html_body,
                "count": batch_count,
                "timestamp": timestamp_iso
            }
            
            response = requests.post(EMAIL_LAMBDA_URL, json=payload, timeout=5)
            
            if response.status_code == 200:
                logger.info(f"[EMAIL] ✅ Sent alert for {batch_count} attacks")
            else:
                logger.error(f"[EMAIL] ❌ Failed: {response.status_code} - {response.text}")
        
    except Exception as e:
        logger.error(f"[EMAIL ERROR] {str(e)}")

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
        r = HTTPX_CLIENT.post(MODEL_API_URL, json=payload)
        data = r.json()
        label = normalize_label(data.get("prediction", "unknown"))
        conf = data.get("confidence", 0.0)
        return label, conf
    except Exception as e:
        logging.error(f"Predict API error: {e}")
        return "error", 0.0

# ============================== LOG TO DYNAMODB ========================#
def log_ingest(result):
    if not table:
        return

    def worker():
        try:
            table.put_item(Item={
                "flow_id": str(result["flow_id"]),
                "timestamp": result["timestamp_ms"],
                "label": normalize_label(result["binary_prediction"]),
                "true_label": "unknown",   # luôn unknown khi ingest
                "content": f"{result['src_ip']}:{result['src_port']} → {result['dst_ip']}:{result['dst_port']} ({result['protocol']}) - {result['binary_confidence']}",
                "features_json": json.dumps(result["features"])
            },
            ConditionExpression="attribute_not_exists(flow_id)"
            )
        except Exception as e:
            logging.error(f"DynamoDB ingest error: {e}")

    threading.Thread(target=worker, daemon=True).start()



def log_feedback(result):
    if not table:
        return

    def worker():
        try:
            # 1) Query tất cả bản ghi của flow_id
            resp = table.query(
                KeyConditionExpression=Key("flow_id").eq(result["flow_id"])
            )

            items = resp.get("Items", [])
            if not items:
                logging.error(f"[DDB] No record found for flow_id={result['flow_id']}")
                return

            # 2) Update ALL items trùng flow_id
            for item in items:
                ts = item["timestamp"]

                table.update_item(
                    Key={
                        "flow_id": result["flow_id"],
                        "timestamp": ts
                    },
                    UpdateExpression="SET true_label = :label",
                    ExpressionAttributeValues={
                        ":label": normalize_label(result.get("true_label"))
                    }
                )
                logging.info(f"[DDB] Updated true_label for {result['flow_id']} at timestamp {ts}")

        except Exception as e:
            logging.error(f"DynamoDB update error: {e}")

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
    threading.Thread(
        target=redirect_to_honeypot,
        args=(p, label, conf),
        daemon=True
    ).start()
    #MinhBQ add: chạy hàm redirect_to_honeypot trong thread riêng để không làm chậm quá trình ingest
    ####

    with flow_lock:
        flow_results.append(result)
        if len(flow_results) > 1000:
            flow_results.pop(0)

    socketio.emit("new_flow", result)
    log_ingest(result)
    return result

# ============================== INGEST =================================
@app.route("/ingest_flow", methods=["POST"])
def ingest_flow():
    try:
        p = request.get_json(force=True)
        if "batch" in p:
            for x in p["batch"]:
                threading.Thread(
                    target=process_flow,
                    args=(x,),
                    daemon=True
                ).start()
            return jsonify({"status": "accepted", "count": len(p["batch"])}), 202

        threading.Thread(target=process_flow, args=(p,), daemon=True).start()
        return jsonify({"status": "accepted"}), 202
    except Exception as e:
        logging.error(f"Ingest error: {e}")
        return jsonify({"error": str(e)}), 500

# ============================== FEEDBACK + UPDATE UI ====================
@app.route("/feedback_flow", methods=["POST"])
def feedback_flow():
    try:
        p = request.get_json(force=True)

        flow_id = p.get("Flow ID") or p.get("flow_id")
        true_label = normalize_label(p.get("true_label"))

        if not flow_id or not true_label:
            return jsonify({"error": "missing flow_id or true_label"}), 400

        # Update DB (KHÔNG GỌI API)
        resp = table.query(
            KeyConditionExpression=Key("flow_id").eq(flow_id),
            ScanIndexForward=False,
            Limit=1
        )

        items = resp.get("Items", [])
        if not items:
            return jsonify({"error": "flow not found"}), 404

        item = items[0]

        table.update_item(
            Key={
                "flow_id": flow_id,
                "timestamp": item["timestamp"]
            },
            UpdateExpression="SET true_label = :v",
            ExpressionAttributeValues={
                ":v": true_label
            }
        )

        # Update UI memory (optional)
        with flow_lock:
            idx = next((i for i, f in enumerate(flow_results)
                        if f["flow_id"] == flow_id), None)
            if idx is not None:
                flow_results[idx]["true_label"] = true_label
                socketio.emit("update_flow", flow_results[idx])

        return jsonify({
            "status": "ok",
            "flow_id": flow_id,
            "true_label": true_label
        }), 200

    except Exception as e:
        logger.error(f"Feedback error: {e}")
        return jsonify({"error": str(e)}), 500
    

    
@app.route("/feedback_csv", methods=["POST"])
def feedback_csv():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    try:
        import pandas as pd

        df = pd.read_csv(file)

        # =======================
        # VALIDATION
        # =======================
        if "Flow ID" not in df.columns or "Label" not in df.columns:
            return jsonify({
                "error": "CSV must contain 'Flow ID' and 'Label' columns"
            }), 400

        updated = 0
        skipped = 0

        for _, row in df.iterrows():
            flow_id = str(row["Flow ID"]).strip()
            true_label = normalize_label(row["Label"])

            if not flow_id or flow_id.lower() == "nan":
                skipped += 1
                continue

            # lấy record mới nhất của flow
            resp = table.query(
                KeyConditionExpression=Key("flow_id").eq(flow_id),
                ScanIndexForward=False,
                Limit=1
            )

            items = resp.get("Items", [])
            if not items:
                skipped += 1
                continue

            item = items[0]

            table.update_item(
                Key={
                    "flow_id": flow_id,
                    "timestamp": item["timestamp"]
                },
                UpdateExpression="SET true_label = :v",
                ExpressionAttributeValues={
                    ":v": true_label
                }
            )

            updated += 1

        return jsonify({
            "status": "ok",
            "updated": updated,
            "skipped": skipped,
            "total_rows": len(df)
        }), 200

    except Exception as e:
        logger.error(f"[FEEDBACK CSV] {e}")
        return jsonify({"error": str(e)}), 500

    
# ============================== EVALUATE ================================

@app.route("/evaluate_csv", methods=["POST"])
def evaluate_csv():
    """
    Upload CSV → call IDS API /evaluate → return metrics
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    try:
        files = {
            "file": (file.filename, file.stream, file.mimetype)
        }

        resp = requests.post(
            EVALUATE_API_URL,
            files=files,
            timeout=120
        )

        if resp.status_code != 200:
            return jsonify({
                "error": "Evaluate API failed",
                "detail": resp.text
            }), 500

        return jsonify(resp.json()), 200

    except Exception as e:
        logger.error(f"[EVALUATE] {e}")
        return jsonify({"error": str(e)}), 500



@app.route("/history", methods=["GET"])
def get_history():
    with flow_lock:
        return jsonify(flow_results[-500:]), 200


@app.route("/")
def index():
    return render_template("index.html")

######Quantc ADD#####
# ============================== METRICS API ================================
@app.route("/redirection/stats", methods=["GET"])
def get_redirection_metrics():
    """
    Get traffic redirection performance metrics
    
    Endpoint to retrieve detailed metrics about traffic redirection to honeypot. 
    Compares performance with baseline from Beltran Lopez et al.  (2024).
    
    Metrics include:
      - Latency statistics (mean, median, p95, p99, max)
      - Throughput (redirections per second)
      - Success/failure rate
      - Stealth analysis (% below 10ms threshold)
      - Baseline comparison with paper results
    
    Returns: 
        JSON with comprehensive redirection performance data
    
    Example: 
        curl http://ids. qmuit.id. vn/metrics/redirection | jq
    
    Reference:
        Beltran Lopez et al. (2024) - arXiv:2402.09191v2
        Baseline:  mean=2.3ms, max=8.7ms, detection_rate=0%
    """
    try:
        stats = redirection_metrics.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        logging.error(f"Metrics API error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/redirection/summary", methods=["GET"])
def get_redirection_summary():
    try:
        summary = redirection_metrics.get_summary_text()
        return summary, 200, {'Content-Type':  'text/plain; charset=utf-8'}
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        logger.error(f"[METRICS SUMMARY ERROR] {error_detail}")
        return f"Error: {str(e)}\n\n{error_detail}", 500

@app.route("/redirection/export", methods=["POST"])
def export_redirection_metrics():
    """
    Export metrics to JSON file for offline analysis
    
    POST to trigger export of current metrics to file.
    Useful for archiving metrics before restart or for batch analysis.
    
    Returns:
        JSON with export status, filepath, and current stats
    
    Example:
        curl -X POST http://ids.qmuit.id.vn/metrics/redirection/export
    """
    try:
        filepath = "/home/ubuntu/logs/redirection_metrics.json"
        success = redirection_metrics.export_json(filepath)
        
        if success:
            return jsonify({
                "status": "exported",
                "filepath": filepath,
                "stats": redirection_metrics.get_stats()
            }), 200
        else:
            return jsonify({"status": "failed", "filepath": filepath}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/health", methods=["GET"])
def health():
    return "ok", 200

#####################
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001)