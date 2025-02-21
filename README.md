# CyberNose - Network Traffic Analyzer

A Python-based network traffic analyzer that uses machine learning to detect suspicious network patterns and anomalies in real-time.

## Features

- Real-time packet capture and analysis
- Machine learning-based anomaly detection
- Support for both internal and external ML analysis
- PostgreSQL database integration for packet storage
- Configurable logging and monitoring
- Command-line interface for easy operation

## Requirements

- Python 3.12+
- Poetry for dependency management
- PostgreSQL database
- Network interface with packet capture capabilities

## Installation

1. Clone the repository:
```bash
git clone https://github.com/imadenugraha/cybernose.git
cd cybernose
```

2. Install dependencies using Poetry:
```bash
poetry install
```

3. Configure your PostgreSQL database settings in `config.py`

## Usage
Start the analyzer with default settings:
```bash
poetry run python main.py
```

Available command line options:
- `--interface`: Network interface to capture packets from
- `--ml-type`: Choose ML analysis type (internal/external/hybrid)
- `--filter`: Set custom BPF filter for packet capture

Example:
```bash
poetry run python main.py --interface eth0 --ml-type internal --filter "tcp port 80"
```

## Configuration
Edit `config.py` to customize:
- Database connection settings
- ML parameters and thresholds
- Packet capture settings
- Logging configuration

## Project Structure
```tree
cybernose/
├── config.py                 # Global configuration
├── main.py                  # Application entry point
├── database/               # Database models and management
├── ml/                    # Machine learning components
├── packet_processing/     # Packet capture and feature extraction
└── utils/  
```
