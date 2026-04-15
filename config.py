"""
NIDS Configuration Settings
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Server Settings
HOST = '0.0.0.0'
PORT = 14094
DEBUG = False

# Threat Level Definitions
THREAT_LEVELS = {
    'NORMAL': {'label': 'Normal', 'color': '#34d399', 'icon': '✅'},
    'CRITICAL': {'label': 'Critical', 'color': '#fbbf24', 'icon': '⚠️'},
    'EMERGENCY': {'label': 'Emergency', 'color': '#f87171', 'icon': '🚨'}
}

# Action Recommendations (DEPRECATED - Now dynamic via LLM)
# RECOMMENDATIONS = {
#     'BENIGN': "System operating normally. No immediate action required. Continue routine monitoring.",
#     'DoS': "Denial of Service detected. Immediate priority: Isolate source IP, implement rate limiting, and check server resource availability.",
#     'DDoS': "Distributed Denial of Service in progress. Immediate priority: Activate DDoS protection services (e.g., Cloudflare, AWS Shield), scale infrastructure, and notify ISP."
# }

# Attack Pattern Relevance (DEPRECATED - Now dynamic via LLM)
# ATTACK_PATTERNS = {
#     'DoS': [
#         "High frequency of requests from a single source disrupting service.",
#         "Resource exhaustion through rapid SYN packets or malformed requests.",
#         "Specific feature patterns observed in Packet Length and Flow Duration."
#     ],
#     'DDoS': [
#         "Distributed traffic surge from multiple disparate sources.",
#         "Volume-based saturation of network bandwidth and processing capacity.",
#         "Coordinated botnet activity identified through multivariate feature analysis."
#     ]
# }

# Model Settings
MODEL_DIR = 'models'
BEST_MODEL_PATH = os.path.join(MODEL_DIR, 'xgboost_model.pkl')
RF_MODEL_PATH = os.path.join(MODEL_DIR, 'random_forest_model.pkl')
XGB_MODEL_PATH = os.path.join(MODEL_DIR, 'xgboost_model.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
PCA_PATH = os.path.join(MODEL_DIR, 'ipca.pkl')

# Multiclass Settings
IS_MULTICLASS = True
LABELS = {
    0: 'BENIGN',
    1: 'DDoS',
    2: 'DoS'
}

# PCA Settings
PCA_COMPONENTS = 35

# Data Settings
DATA_DIR = 'data'
TRAIN_DATA = os.path.join(DATA_DIR, 'CICIDS2017_merged.csv') 
CICIDS_BASE_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"

# Detection Settings
INTERFACE = 'Wi-Fi' 
FLOW_TIMEOUT = 60 # seconds
ALERT_THRESHOLD = 0.5 # Lowered for multiclass confidence
LOG_FILE = 'logs/threat_sentry.log'

# Amazon Bedrock (AWS) LLM Settings
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "YOUR_AWS_ACCESS_KEY")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "YOUR_AWS_SECRET_ACCESS_KEY")
AWS_REGION_NAME = os.getenv("AWS_REGION_NAME", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")

# Baseline Performance Metrics (from Training Notebook)
BASELINE_METRICS = {
    "Random Forest": {"Accuracy": 0.989185, "Precision": 0.989202, "Recall": 0.989185, "F1": 0.989182, "AUC": 0.999134},
    "XGBoost": {"Accuracy": 0.996444, "Precision": 0.996445, "Recall": 0.996444, "F1": 0.996444, "AUC": 0.999919},
    "CNN": {"Accuracy": 0.986074, "Precision": 0.986192, "Recall": 0.986074, "F1": 0.986062, "AUC": 0.999200},
    "BiLSTM": {"Accuracy": 0.985630, "Precision": 0.985752, "Recall": 0.985630, "F1": 0.985600, "AUC": 0.999419},
    "Best Model": {"Accuracy": 0.996444, "Precision": 0.996445, "Recall": 0.996444, "F1": 0.996444, "AUC": 0.999919}
}
