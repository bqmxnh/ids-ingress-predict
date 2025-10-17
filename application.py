import nfstream
import pandas as pd
import numpy as np
import joblib
import time
import logging
import subprocess
import requests
from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
from datetime import datetime
from pathlib import Path
import os
import math

# ============================================================
# Flask App Setup
# ============================================================
app = Flask(__name__)
socketio = SocketIO(app)

# Logging
logging.basicConfig(filename='ids.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Configuration
INTERFACE = "eth0"
URL = "http://52.73.129.151/predict"

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = OUTPUT_DIR / "predictions.csv"

# In-memory results
flow_results = []
flow_results_lock = threading.Lock()
active_timeout = 60
idle_timeout = 10
packet_thread = None
stop_processing = False

# ============================================================
# Helper: safe numeric conversion
# ============================================================
def safe(val):
    try:
        if val is None:
            return 0
        if isinstance(val, bool):
            return int(val)
        if isinstance(val, int):
            return val
        if isinstance(val, float):
            if math.isfinite(val):
                return float(val)
            return 0
        return float(val)
    except Exception:
        return 0


# ============================================================
# Feature Extraction (Min-Zero version)
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
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]


def extract_flow_features_minzero(flow):
    f = {}
    dur_ms = safe(getattr(flow, "bidirectional_duration_ms", 0))
    dur_s = dur_ms / 1000 if dur_ms > 0 else 0

    f["Flow Duration"] = dur_ms
    f["Total Fwd Packets"] = safe(getattr(flow, "src2dst_packets", 0))
    f["Total Backward Packets"] = safe(getattr(flow, "dst2src_packets", 0))
    f["Total Length of Fwd Packets"] = safe(getattr(flow, "src2dst_bytes", 0))
    f["Total Length of Bwd Packets"] = safe(getattr(flow, "dst2src_bytes", 0))

    f["Fwd Packet Length Max"] = safe(getattr(flow, "src2dst_max_ps", 0))
    f["Fwd Packet Length Min"] = safe(getattr(flow, "src2dst_min_ps", 0))
    f["Fwd Packet Length Mean"] = safe(getattr(flow, "src2dst_mean_ps", 0))
    f["Fwd Packet Length Std"] = safe(getattr(flow, "src2dst_stddev_ps", 0))
    f["Bwd Packet Length Max"] = safe(getattr(flow, "dst2src_max_ps", 0))
    f["Bwd Packet Length Min"] = safe(getattr(flow, "dst2src_min_ps", 0))
    f["Bwd Packet Length Mean"] = safe(getattr(flow, "dst2src_mean_ps", 0))
    f["Bwd Packet Length Std"] = safe(getattr(flow, "dst2src_stddev_ps", 0))

    total_bytes = safe(getattr(flow, "bidirectional_bytes", 0))
    total_pkts = safe(getattr(flow, "bidirectional_packets", 0))
    f["Flow Bytes/s"] = safe(total_bytes / dur_s) if dur_s > 0 else 0
    f["Flow Packets/s"] = safe(total_pkts / dur_s) if dur_s > 0 else 0

    # IATs
    f["Flow IAT Mean"] = safe(getattr(flow, "bidirectional_mean_piat_ms", 0))
    f["Flow IAT Std"] = safe(getattr(flow, "bidirectional_stddev_piat_ms", 0))
    f["Flow IAT Max"] = safe(getattr(flow, "bidirectional_max_piat_ms", 0))
    f["Flow IAT Min"] = safe(getattr(flow, "bidirectional_min_piat_ms", 0))

    f["Fwd IAT Total"] = safe(getattr(flow, "src2dst_duration_ms", 0))
    f["Fwd IAT Mean"] = safe(getattr(flow, "src2dst_mean_piat_ms", 0))
    f["Fwd IAT Std"] = safe(getattr(flow, "src2dst_stddev_piat_ms", 0))
    f["Fwd IAT Max"] = safe(getattr(flow, "src2dst_max_piat_ms", 0))
    f["Fwd IAT Min"] = safe(getattr(flow, "src2dst_min_piat_ms", 0))
    f["Bwd IAT Total"] = safe(getattr(flow, "dst2src_duration_ms", 0))
    f["Bwd IAT Mean"] = safe(getattr(flow, "dst2src_mean_piat_ms", 0))
    f["Bwd IAT Std"] = safe(getattr(flow, "dst2src_stddev_piat_ms", 0))
    f["Bwd IAT Max"] = safe(getattr(flow, "dst2src_max_piat_ms", 0))
    f["Bwd IAT Min"] = safe(getattr(flow, "dst2src_min_piat_ms", 0))

    f["Fwd PSH Flags"] = safe(getattr(flow, "src2dst_psh_packets", 0))
    f["Bwd PSH Flags"] = safe(getattr(flow, "dst2src_psh_packets", 0))
    f["Fwd URG Flags"] = safe(getattr(flow, "src2dst_urg_packets", 0))
    f["Bwd URG Flags"] = safe(getattr(flow, "dst2src_urg_packets", 0))
    f["Fwd Header Length"] = 40 if f["Total Fwd Packets"] > 0 else 0
    f["Bwd Header Length"] = 40 if f["Total Backward Packets"] > 0 else 0
    f["Fwd Packets/s"] = safe(f["Total Fwd Packets"] / dur_s) if dur_s > 0 else 0
    f["Bwd Packets/s"] = safe(f["Total Backward Packets"] / dur_s) if dur_s > 0 else 0

    f["Min Packet Length"] = safe(getattr(flow, "bidirectional_min_ps", 0))
    f["Max Packet Length"] = safe(getattr(flow, "bidirectional_max_ps", 0))
    f["Packet Length Mean"] = safe(getattr(flow, "bidirectional_mean_ps", 0))
    f["Packet Length Std"] = safe(getattr(flow, "bidirectional_stddev_ps", 0))
    f["Packet Length Variance"] = safe((getattr(flow, "bidirectional_stddev_ps", 0)) ** 2)

    f["FIN Flag Count"] = safe(getattr(flow, "bidirectional_fin_packets", 0))
    f["SYN Flag Count"] = safe(getattr(flow, "bidirectional_syn_packets", 0))
    f["RST Flag Count"] = safe(getattr(flow, "bidirectional_rst_packets", 0))
    f["PSH Flag Count"] = safe(getattr(flow, "bidirectional_psh_packets", 0))
    f["ACK Flag Count"] = safe(getattr(flow, "bidirectional_ack_packets", 0))
    f["URG Flag Count"] = safe(getattr(flow, "bidirectional_urg_packets", 0))
    f["CWE Flag Count"] = safe(getattr(flow, "bidirectional_cwr_packets", 0))
    f["ECE Flag Count"] = safe(getattr(flow, "bidirectional_ece_packets", 0))

    src_bytes = safe(getattr(flow, "src2dst_bytes", 0))
    dst_bytes = safe(getattr(flow, "dst2src_bytes", 0))
    f["Down/Up Ratio"] = safe((dst_bytes / src_bytes) if src_bytes > 0 else 0)
    f["Average Packet Size"] = safe((total_bytes / total_pkts) if total_pkts > 0 else 0)
    f["Avg Fwd Segment Size"] = safe(getattr(flow, "src2dst_mean_ps", 0))
    f["Avg Bwd Segment Size"] = safe(getattr(flow, "dst2src_mean_ps", 0))

    for c in FEATURE_COLUMNS:
        if c not in f:
            f[c] = 0
    return f


# ============================================================
# Predict using API instead of local model
# ============================================================
def predict_features_api(features_dict):
    try:
        r = requests.post(URL, json={"features": features_dict}, timeout=8)
        r.raise_for_status()
        data = r.json()
        label = data.get("prediction") or data.get("label", "UNKNOWN")
        conf = data.get("confidence") or data.get("probability", None)
        return label, conf
    except Exception as e:
        logging.error(f"Predict API error: {e}")
        return "ERROR", None


# ============================================================
# Stream + Predict Loop
# ============================================================
def check_interface(interface):
    try:
        result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def process_real_time_packets():
    global stop_processing
    while not stop_processing:
        try:
            if not check_interface(INTERFACE):
                logging.error(f"Interface {INTERFACE} invalid")
                print(f"Interface {INTERFACE} invalid")
                return
            streamer = nfstream.NFStreamer(
                source=INTERFACE,
                statistical_analysis=True,
                accounting_mode=1,
                active_timeout=active_timeout,
                idle_timeout=idle_timeout,
                snapshot_length=65535
            )
            for flow in streamer:
                if stop_processing:
                    break
                features = extract_flow_features_minzero(flow)
                label, conf = predict_features_api(features)
                result = {
                    "src_ip": flow.src_ip,
                    "src_port": flow.src_port,
                    "dst_ip": flow.dst_ip,
                    "dst_port": flow.dst_port,
                    "binary_prediction": label,
                    "binary_confidence": conf,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "features": features
                }
                with flow_results_lock:
                    flow_results.append(result)
                    if len(flow_results) > 1000:
                        flow_results.pop(0)
                socketio.emit("new_flow", result)

                # CSV
                row = features.copy()
                row["Label"] = label
                pd.DataFrame([row]).to_csv(OUTPUT_CSV, mode='a', index=False, header=not OUTPUT_CSV.exists())

        except Exception as e:
            logging.error(f"Error in packet loop: {e}")
            print("Error in packet loop:", e)
            time.sleep(1)


# ============================================================
# Flask Routes & SocketIO Handlers
# ============================================================
@app.route('/')
def index():
    return render_template('index.html')


def start_packet_processing():
    process_real_time_packets()


@socketio.on('update_timeout')
def handle_timeout_update(data):
    global active_timeout, idle_timeout, packet_thread, stop_processing
    try:
        active_timeout = int(data['active_timeout'])
        idle_timeout = int(data['idle_timeout'])

        if packet_thread and packet_thread.is_alive():
            stop_processing = True
            packet_thread.join(timeout=2)
            with flow_results_lock:
                flow_results.clear()
            stop_processing = False

        packet_thread = threading.Thread(target=start_packet_processing, daemon=True)
        packet_thread.start()
        socketio.emit('timeout_updated', {'active_timeout': active_timeout, 'idle_timeout': idle_timeout})
    except Exception as e:
        logging.error(f"Timeout update error: {e}")


# ============================================================
# Main Entry
# ============================================================
if __name__ == "__main__":
    packet_thread = threading.Thread(target=start_packet_processing, daemon=True)
    packet_thread.start()
    socketio.run(app, debug=True, host="0.0.0.0", port=5001)
