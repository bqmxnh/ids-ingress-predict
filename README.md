# Real-time Intrusion Detection System (IDS)
## Introduction
This system implements a real-time Intrusion Detection System (IDS) using the nfstream library to analyze network traffic, extract features, and predict anomalous behaviors (attack or normal) using a machine learning model. Results are saved to a CSV file and displayed via a web interface built with Flask.
### Key Features
- Capture and analyze network traffic in real-time using nfstream.
- Extract features from network flows in CICIDS2017 format.
- Predict network behavior (normal or attack) using a machine learning model.
- Save results to a CSV file (predictions.csv) and display them on a Flask web interface.
- Support remote monitoring through the Flask web interface.
## Directory Structure
- **models/**: Directory containing pre-trained machine learning model files (customizable).
  - **best_binary_model.pkl**: Binary classification model.
  - **scaler.pkl**: Feature scaler (StandardScaler).
  - **label_encoder_binary.pkl**: Label encoder for binary classification (LabelEncoder). 
- **templates/**: Directory for web interface files. 
  - **index.html**: HTML file for displaying prediction results.
- **application.py**: Main source code for packet processing, prediction, and result display.
- **predictions.csv**: File storing prediction results (source IP, destination IP, label, probability, timestamp).
## System Requirements
- Operating System: Ubuntu (or other Linux-based systems).
- Python 3.6 or higher.
- Required Python libraries:
  - nfstream
  - pandas
  - numpy
  - joblib
  - scikit-learn
  - flask
## Installation Guide

### 1. Install Python and pip
- Ensure Python 3 and pip are installed. If not, run the following commands on Ubuntu:
```bash
sudo apt update
sudo apt install python3 python3-pip
```
### 2. Install Required Libraries
- Install the necessary Python libraries using:
```bash
pip3 install nfstream pandas numpy joblib scikit-learn flask
```
### 3. Configure Network Interface
- Open application.py and update the INTERFACE variable with your network interface (e.g., eth0, wlan0).
```bash
INTERFACE = "ens33"  # Thay "ens33" bằng giao diện của bạn
```
- To check available network interfaces, use:
```bash
ifconfig
```
### 4. Ensure Model Files are Available
- Place the best_binary_model.pkl, scaler.pkl, and label_encoder_binary.pkl files in the models/ directory.
- If these files are not available, train a model on a dataset (e.g., CICIDS2017) and save it using joblib.
### 5. Update Model File Paths
- Open application.py and update the paths for the model files:
```bash
MODEL_BINARY_FILE = "/path/to/your/IDS/models/best_binary_model.pkl"
SCALER_FILE = "/path/to/your/IDS/models/scaler.pkl"
LE_BINARY_FILE = "/path/to/your/IDS/models/label_encoder_binary.pkl"
```
## Running the System
### 1. Start the Program
- In the directory containing application.py, run:
```bash
python3 application.py
```
- The program will:
  - Capture packets from the configured network interface.
  - Extract features, make predictions, and save results to predictions.csv.
  - Launch the Flask web interface at http://localhost:5001.
### 2. Access the Web Interface
- Open a browser and navigate to:
```bash
http://localhost:5001
```
- The interface displays processed network flows, including source IP, destination IP, port, predicted label, and probability.
## Usage
- **Real-time Monitoring:** The system continuously captures packets and predicts network behavior. Results are updated on the web interface.
- **Post-analysis:** Review the predictions.csv file for a history of processed network flows.
- **Customization:**
  - Adjust the flow processing duration by modifying WINDOW_DURATION in application.py.
  - Update the machine learning model in the models/ directory to improve accuracy.
## Notes
- Ensure you have sufficient permissions to access the network interface (may require sudo):
```bash
sudo python3 application.py
```
- For high network traffic, the system may consume significant CPU/memory. Consider adjusting WINDOW_DURATION or limiting traffic.
- The predictions.csv file is appended to, so its size will grow over time. Periodically archive or delete it as needed.
## Authors
- **Công Quân**  
  Email: 22521190@gm.uit.edu.vn  
- **Quốc Minh**  
  Email: 22520855@gm.uit.edu.vn
  ## License
This project was developed as part of the research topic **Applying Machine Learning Techniques to Detect Malicious Network Traffic in Cloud Computing.** The source code is provided for educational and research purposes.


