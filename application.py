import nfstream
import pandas as pd
import numpy as np
import joblib
import time
from sklearn.preprocessing import StandardScaler
from flask import Flask, render_template, jsonify
import threading
from datetime import datetime

# Flask app setup
app = Flask(__name__)

# Configuration
INTERFACE = "ens33"  # Replace with your network interface
WINDOW_DURATION = 2  # Window duration (seconds)
MODEL_BINARY_FILE = "/home/bqmxnh/Desktop/IDS/models/best_binary_model.pkl"
SCALER_FILE = "/home/bqmxnh/Desktop/IDS/models/scaler.pkl"
LE_BINARY_FILE = "/home/bqmxnh/Desktop/IDS/models/label_encoder_binary.pkl"
OUTPUT_CSV = "predictions.csv"

# In-memory storage for flow results
flow_results = []

# Load models and components
try:
    model_binary = joblib.load(MODEL_BINARY_FILE)
    scaler = joblib.load(SCALER_FILE)
    le_binary = joblib.load(LE_BINARY_FILE)
    print("Loaded scikit-learn binary model and components")
except Exception as e:
    print(f"Error loading model or components: {e}")
    exit(1)

# Feature extraction function
def extract_cicids2017_features(flow):
    """
    Extract features from an NFlow object corresponding to the provided column names.
    Returns a list of features aligned with the column names.
    """
    features = [
        flow.dst_port,
        flow.bidirectional_duration_ms / 1000,
        flow.src2dst_packets,
        flow.dst2src_packets,
        flow.src2dst_bytes,
        flow.dst2src_bytes,
        flow.src2dst_max_ps,
        flow.src2dst_min_ps,
        flow.src2dst_mean_ps,
        flow.src2dst_stddev_ps,
        flow.dst2src_max_ps,
        flow.dst2src_min_ps,
        flow.dst2src_mean_ps,
        flow.dst2src_stddev_ps,
        (flow.bidirectional_bytes / (flow.bidirectional_duration_ms / 1000)) if flow.bidirectional_duration_ms > 0 else 0,
        (flow.bidirectional_packets / (flow.bidirectional_duration_ms / 1000)) if flow.bidirectional_duration_ms > 0 else 0,
        flow.bidirectional_mean_piat_ms,
        flow.bidirectional_stddev_piat_ms,
        flow.bidirectional_max_piat_ms,
        flow.bidirectional_min_piat_ms,
        flow.src2dst_duration_ms,
        flow.src2dst_mean_piat_ms,
        flow.src2dst_stddev_piat_ms,
        flow.src2dst_max_piat_ms,
        flow.src2dst_min_piat_ms,
        flow.dst2src_duration_ms,
        flow.dst2src_mean_piat_ms,
        flow.dst2src_stddev_piat_ms,
        flow.dst2src_max_piat_ms,
        flow.dst2src_min_piat_ms,
        flow.src2dst_psh_packets,
        flow.dst2src_psh_packets,
        flow.src2dst_urg_packets,
        flow.dst2src_urg_packets,
        flow.src2dst_packets * 40,
        flow.dst2src_packets * 40,
        (flow.src2dst_packets / (flow.bidirectional_duration_ms / 1000)) if flow.bidirectional_duration_ms > 0 else 0,
        (flow.dst2src_packets / (flow.bidirectional_duration_ms / 1000)) if flow.bidirectional_duration_ms > 0 else 0,
        flow.bidirectional_min_ps,
        flow.bidirectional_max_ps,
        flow.bidirectional_mean_ps,
        flow.bidirectional_stddev_ps,
        flow.bidirectional_stddev_ps ** 2,
        flow.bidirectional_fin_packets,
        flow.bidirectional_syn_packets,
        flow.bidirectional_rst_packets,
        flow.bidirectional_psh_packets,
        flow.bidirectional_ack_packets,
        flow.bidirectional_urg_packets,
        flow.bidirectional_cwr_packets,
        flow.bidirectional_ece_packets,
        (flow.dst2src_bytes / flow.src2dst_bytes) if flow.src2dst_bytes > 0 else 0,
        (flow.bidirectional_bytes / flow.bidirectional_packets) if flow.bidirectional_packets > 0 else 0,
        flow.src2dst_mean_ps,
        flow.dst2src_mean_ps,
        0, 0, 0, 0, 0, 0,
        flow.src2dst_packets,
        flow.src2dst_bytes,
        flow.dst2src_packets,
        flow.dst2src_bytes,
        getattr(flow, 'init_win_bytes_forward', 0),
        getattr(flow, 'init_win_bytes_backward', 0),
        getattr(flow, 'act_data_pkt_fwd', 0),
        40,
        0, 0, 0, 0, 0, 0, 0, 0
    ]
    return features

CICIDS2017_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

def predict_features(features):
    numeric_features = [f if isinstance(f, (int, float)) else 0 for f in features]
    numeric_features = np.nan_to_num(numeric_features, nan=0, posinf=0, neginf=0)
    features_df = pd.DataFrame([numeric_features], columns=CICIDS2017_COLUMNS)
    features_scaled = scaler.transform(features_df)
    binary_pred = model_binary.predict(features_scaled)[0]
    binary_conf = model_binary.predict_proba(features_scaled)[0] if hasattr(model_binary, "predict_proba") else None
    binary_label = le_binary.inverse_transform([binary_pred])[0]
    return binary_label, binary_conf

def process_real_time_packets():
    streamer = nfstream.NFStreamer(
        source=INTERFACE,
        statistical_analysis=True,
        accounting_mode=0,
        idle_timeout=WINDOW_DURATION,
        active_timeout=WINDOW_DURATION
    )
    for flow in streamer:
        all_features = extract_cicids2017_features(flow)
        binary_label, binary_conf = predict_features(all_features)
        result = {
            'src_ip': flow.src_ip,
            'src_port': flow.src_port,
            'dst_ip': flow.dst_ip,
            'dst_port': flow.dst_port,
            'binary_prediction': binary_label,
            'binary_confidence': max(binary_conf) if binary_conf is not None else None,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        flow_results.append(result)
        if len(flow_results) > 100:
            flow_results.pop(0)
        result_df = pd.DataFrame([result])
        result_df.to_csv(OUTPUT_CSV, mode='a', index=False, header=not pd.io.common.file_exists(OUTPUT_CSV))

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_flows')
def get_flows():
    return jsonify(flow_results)

def start_packet_processing():
    try:
        print("Starting real-time attack detection...")
        process_real_time_packets()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    packet_thread = threading.Thread(target=start_packet_processing, daemon=True)
    packet_thread.start()
    app.run(debug=True, host='0.0.0.0', port=5001)
