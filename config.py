#!/usr/bin/env python3
"""
Modul konfigurasi global untuk Network Traffic Analyzer
"""
from os import getenv
from dotenv import load_dotenv

load_dotenv()

# Database Configuration
DB_CONFIG = {
    'provider': getenv("DB_PROVIDER", "postgresql"),
    'user': getenv("DB_USER", "postgres"),
    'password': getenv("DB_PASSWORD", "postgres"),
    'host': getenv("DB_HOST", "localhost"),
    'port': getenv("DB_PORT", "5432"),
    'database': getenv("DB_DATABASE", "network_analyzer")
}

# Machine Learning Configuration
ML_CONFIG = {
    'internal': {
        'n_clusters': getenv("N_CLUSTERS", 5),
        'buffer_size': getenv("BUFFER_SIZE", 1000),
        'suspicious_threshold': getenv("SUSPICIOUS_THRESHOLD", 1.5),
    },
    'external': {
        'api_endpoint': getenv("API_ENDPOINT", "http://localhost:5000/api/v1/analyze"),
        'api_key': getenv("API_KEY", "secret"),
        'batch_size': getenv("BATCH_SIZE", 100),
        'timeout_seconds': getenv("TIMEOUT_SECONDS", 10)
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
    'filter': f'ip and ({SERVICE_FILTER})',    # BPF filter string
    'packet_count': 0   # 0 for infinite capture
}

# Logging Configuration
LOG_CONFIG = {
    'log_level': getenv("LOG_LEVEL", "INFO"),
    'log_file': getenv("LOG_FILE", "network_analyzer.log"),
    'rotate_logs': getenv("ROTATE_LOGS", True),
    'max_log_size_mb': getenv("MAX_LOG_IN_MB", 10),
}
