# Network Traffic Analysis & Honeypot Redirection

A lightweight Flask + Socket.IO service that ingests network flow records, performs real-time intrusion detection via an external model API, redirects malicious flows to a honeypot (HTTP JSON simulation), tracks redirection performance against published baselines, and provides a live web dashboard with feedback and offline evaluation tools. Optional persistence is provided via AWS DynamoDB.

Authors: MinhBQ · QuanTC (Graduation Thesis – 2025)

---

## Key Features
- Real-time web dashboard (Socket.IO + Tailwind + Chart.js) for flow monitoring
- Prediction via external IDS model API with confidence scoring
- Stealth honeypot redirection (HTTP JSON simulation) with detailed metrics
- Batch email alerting (via `EMAIL_LAMBDA_URL`) for detected attacks
- AWS DynamoDB logging for flows and label feedback
- Offline CSV evaluation and bulk feedback tools
- Metrics API with latency percentiles and baseline comparison

## Repository Layout
- `application.py` — Flask app, Socket.IO, REST APIs, honeypot redirection, DynamoDB, metrics endpoints
- `metrics_collector.py` — Redirection performance metrics collector
- `templates/index.html` — Real‑time dashboard UI

## Architecture Overview
- Ingestion: `/ingest_flow` accepts single or batch flow JSON
- Inference: Calls external model API (`MODEL_API_URL`) using `httpx`
- Redirection: Suspicious flows are forwarded to `HONEYPOT_URL` with enriched metadata
- Metrics: Latency/throughput tracked by `metrics_collector.RedirectionMetrics`
- Storage: Flow logs and feedback saved to DynamoDB table `ids_log_system`
- UI: Socket.IO broadcasts to the browser for live charts and tables

## Prerequisites
- Python 3.9+ recommended
- AWS account and credentials configured (needed for DynamoDB-backed features)
- Network access to:
  - Model API: `MODEL_API_URL`
  - Evaluate API: `EVALUATE_API_URL`
  - Honeypot endpoint: `HONEYPOT_URL`
  - Optional email lambda: `EMAIL_LAMBDA_URL`

### Python dependencies
Install with pip (example minimal set):

```bash
pip install flask flask-socketio httpx requests boto3 pandas werkzeug
```

Notes:
- `flask-socketio` is used with `async_mode="threading"`, so no extra async server is required.
- `pandas` is required for CSV feedback/evaluation endpoints only.

## Configuration
Most settings are in `application.py`:

- `MODEL_API_URL` — Prediction API endpoint
- `FEEDBACK_API_URL` — Not currently used for feedback persistence (feedback writes to DynamoDB directly)
- `EVALUATE_API_URL` — Remote evaluation service used by `/evaluate_csv`
- `AWS_REGION` — AWS region for DynamoDB (default `us-east-1`)
- `HONEYPOT_URL` — Target endpoint to receive redirected attack metadata
- `BATCH_TIMEOUT` — Seconds to buffer attacks before sending batch email alert (default `60`)

Environment variables:

- `EMAIL_LAMBDA_URL` — If set, batch email alerts are sent after `BATCH_TIMEOUT`

Logging:
- The application configures logging to console and to `/home/ubuntu/logs/ids_agent.log`. On Windows or other environments, ensure the directory exists or change the file path in `application.py`.

## DynamoDB Setup (Required for Feedback flows)
Some endpoints (`/feedback_flow`, `/feedback_csv`) require DynamoDB. Create table:

- Table name: `ids_log_system`
- Partition key: `flow_id` (String)
- Sort key: `timestamp` (Number)
- Billing mode: On‑demand or provisioned (your choice)

Ensure your environment has AWS credentials (e.g., via `~/.aws/credentials`, environment variables, or an instance role). The app initializes the table on startup.

## Running the App

### 1) Clone and install
```bash
python -m venv .venv
. .venv/Scripts/Activate.ps1   # Windows PowerShell
pip install -U pip
pip install flask flask-socketio httpx requests boto3 pandas werkzeug
```

### 2) Configure (optional)
```powershell
# Optional email alerting
$env:EMAIL_LAMBDA_URL = "https://your-lambda-or-webhook-url"
```
If you plan to use feedback/evaluation endpoints, set up DynamoDB as above and ensure AWS credentials are available.

### 3) Run
```bash
python application.py
```
The server listens on `http://0.0.0.0:5001`.

Open the dashboard at:
- `http://localhost:5001/`

## REST API

### Health
- `GET /health` → `"ok"` if server is alive

### Ingest Flow
- `POST /ingest_flow`
- Body: either a single flow object or `{ "batch": [ ...flows... ] }`
- Returns: `202 Accepted`

Single example:
```json
{
  "Flow ID": "flow_123",
  "Source IP": "10.0.0.5",
  "Source Port": 44321,
  "Destination IP": "10.0.0.10",
  "Destination Port": 443,
  "Protocol": "TCP",
  "Timestamp": "2025-12-28 12:34:56",
  "Flow Duration": 120.0,
  "Total Fwd Packets": 10,
  "Total Backward Packets": 8
  // ... see Feature Columns below
}
```

Batch example:
```json
{
  "batch": [ { /* flow */ }, { /* flow */ } ]
}
```

Behavior:
- Performs prediction via `MODEL_API_URL`
- Emits `new_flow` event over Socket.IO
- Persists to DynamoDB (if configured)
- If prediction is ATTACK → sends enriched metadata to `HONEYPOT_URL` and records metrics

### Label Feedback
- `POST /feedback_flow`
- Body:
```json
{ "flow_id": "flow_123", "true_label": "attack" }
```
- Updates the latest DynamoDB item for the `flow_id` with the provided `true_label`.

### Bulk Feedback (CSV)
- `POST /feedback_csv`
- Multipart form with file field `file`. CSV must contain `Flow ID` and `Label` columns.
- Updates latest item for each `Flow ID` in DynamoDB.

### Offline Evaluation (CSV)
- `POST /evaluate_csv`
- Multipart form with file field `file`.
- Proxies to `EVALUATE_API_URL` and returns its JSON (accuracy, precision, recall, f1, kappa, rows, confusion_matrix).

### History (UI support)
- `GET /history` → Returns recent flows (up to 2000) kept in memory for UI restore.

### Metrics
- `GET /redirection/stats` → JSON stats: counts, latency percentiles (`p90`, `p95`, `p99`), stealth analysis (<10ms), baseline comparison
- `GET /redirection/summary` → Plain-text summary of current redirection performance
- `POST /redirection/export` → Exports current metrics JSON to `/home/ubuntu/logs/redirection_metrics.json`

## Web Dashboard
- Route: `GET /`
- Live flow table and line chart of ATTACK/BENIGN counts
- Upload panels for Offline Evaluation and CSV Feedback
- Click a row to view/copy detailed flow data (including features)

## Feature Columns (Model Input)
`application.py` defines the required numeric feature set in `FEATURE_COLUMNS`:

```
Flow Duration, Total Fwd Packets, Total Backward Packets,
Total Length of Fwd Packets, Total Length of Bwd Packets,
Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,
Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,
Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,
Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,
Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,
Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags,
Fwd Header Length, Bwd Header Length,
Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length,
Packet Length Mean, Packet Length Std, Packet Length Variance,
FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count,
ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count,
Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size,
Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate,
Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate,
Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,
Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,
Active Mean, Active Std, Active Max, Active Min,
Idle Mean, Idle Std, Idle Max, Idle Min
```

Additional metadata commonly present per flow:
- `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol`, `Timestamp`

## Redirection Performance & Baseline
The app measures redirection latency and throughput and compares with results from:

> Beltran Lopez, P., et al. (2024). Cyber Deception Reactive: TCP Stealth Redirection to On-Demand Honeypots. arXiv:2402.09191v2

Baseline targets from the paper:
- Mean latency: 2.3 ms
- Max latency: 8.7 ms
- Stealth requirement: < 10 ms for 95% of redirections

The `/redirection/stats` endpoint exposes whether the stealth requirement is currently met.

Note: This implementation redirects via HTTP JSON (a simulation), not TCP-level stealth redirection.

## Troubleshooting
- Windows log path: Update or remove the file handler path `/home/ubuntu/logs/ids_agent.log` in `application.py`, or create the directory.
- DynamoDB required: `/feedback_flow` and `/feedback_csv` require the DynamoDB table to exist and valid AWS credentials.
- External endpoints: Ensure `MODEL_API_URL`, `EVALUATE_API_URL`, `HONEYPOT_URL` are reachable from the host running the app.
- Timeouts: Honeypot redirection uses a 3s timeout; stats will record failures and slow calls.

## Development Notes
- Hot reload is not enabled by default. Edit code and restart the process.
- Socket.IO is configured with `cors_allowed_origins="*"` and `async_mode="threading"`.
- `ProxyFix` is enabled for reverse proxy headers: `x_for=1`, `x_proto=1`.

