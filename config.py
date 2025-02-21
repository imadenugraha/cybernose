#!/usr/bin/env python3
"""
Modul konfigurasi global untuk Network Traffic Analyzer
"""
from os import getenv
from dotenv import load_dotenv

load_dotenv()

# Database Configuration
DB_CONFIG = {
    'provider': getenv("DB_PROVIDER"),
    'user': getenv("DB_USERNAME"),
    'password': getenv("DB_PASSWORD"),
    'host': getenv("DB_HOST"),
    'port': getenv("DB_PORT"),
    'database': getenv("DB_NAME")
}

# Machine Learning Configuration
ML_CONFIG = {
    'internal': {
        'n_clusters': getenv("N_CLUSTERS"),
        'buffer_size': getenv("BUFFER_SIZE"),
        'suspicious_threshold': getenv("SUSPICIOUS_THRESHOLD"),
    },
    'external': {
        'api_endpoint': getenv("API_ENDPOINT"),
        'api_key': getenv("API_KEY"),
        'batch_size': getenv("BATCH_SIZE"),
        'timeout_seconds': getenv("TIMEOUT_SECONDS")
    }
}

# Common service ports to exclude
SAFE_PORTS = [getenv("SAFE_PORTS")]

SERVICE_FILTER = ' and '.join([
    f'not (src port {port} or dst port {port})' 
    for port in SAFE_PORTS
])

# Packet Capture Configuration
CAPTURE_CONFIG = {
    'interface': None,  # None for default interface
    'filter': f'ip and {SERVICE_FILTER}',    # BPF filter string
    'packet_count': 0   # 0 for infinite capture
}

# Logging Configuration
LOG_CONFIG = {
    'log_level': getenv("LOG_LEVEL"),
    'log_file': getenv("LOG_FILE"),
    'rotate_logs': getenv("ROTATE_LOGS"),
    'max_log_size_mb': getenv("MAX_LOG_IN_MB"),
}
