#!/usr/bin/env python3
"""
Modul konfigurasi global untuk Network Traffic Analyzer
"""

# Database Configuration
DB_CONFIG = {
    'provider': 'postgres',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': 5435,
    'database': 'network_traffic'
}

# Machine Learning Configuration
ML_CONFIG = {
    'internal': {
        'n_clusters': 5,
        'buffer_size': 1000,
        'suspicious_threshold': 1.5
    },
    'external': {
        'api_endpoint': 'http://ml-service:5000/predict',
        'api_key': 'your_api_key_here',
        'batch_size': 100,
        'timeout_seconds': 10
    }
}

# Packet Capture Configuration
CAPTURE_CONFIG = {
    'interface': None,  # None for default interface
    'filter': 'ip',     # BPF filter string
    'packet_count': 0   # 0 for infinite capture
}

# Logging Configuration
LOG_CONFIG = {
    'log_level': 'INFO',
    'log_file': 'network_analyzer.log',
    'rotate_logs': True,
    'max_log_size_mb': 10
}
