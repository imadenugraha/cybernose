import argparse
import time
from database.models import initialize_database
from ml.analyzer import NetworkTrafficAnalyzer
from ml.external_integration import ExternalMLIntegration
from packet_processing.capture import PacketCaptureManager
from utils.logging_utils import get_logger
from config import DB_CONFIG, ML_CONFIG, CAPTURE_CONFIG, LOG_CONFIG

logger = get_logger(__name__, log_file=LOG_CONFIG['log_file'], level=LOG_CONFIG['log_level'])

def parse_arguments():
    """Parse argumen command line"""
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer with ML')
    
    parser.add_argument('--interface', type=str, help='Network interface to capture from')
    parser.add_argument('--ml-type', choices=['internal', 'external', 'hybrid'],
                        default='internal', help='Type of ML analysis to use')
    parser.add_argument('--filter', type=str, help='BPF filter for packet capture')
    
    return parser.parse_args()

def main():
    """Fungsi utama aplikasi"""
    args = parse_arguments()
    
    # Update konfigurasi dengan argumen command line
    if args.interface:
        CAPTURE_CONFIG['interface'] = args.interface
    if args.filter:
        CAPTURE_CONFIG['filter'] = args.filter
    
    # Inisialisasi database
    logger.info("Initializing database connection...")
    db = initialize_database(DB_CONFIG)
    
    # Inisialisasi ML analyzer berdasarkan pilihan
    logger.info(f"Initializing ML analyzer (type: {args.ml_type})...")
    
    if args.ml_type == 'internal':
        analyzer = NetworkTrafficAnalyzer(ML_CONFIG['internal'])
    elif args.ml_type == 'external':
        analyzer = ExternalMLIntegration(ML_CONFIG['external'])
    else:  # hybrid - implementasi untuk mengombinasikan hasil internal dan eksternal
        # Implementasi hybrid bisa dibuat sebagai wrapper kedua analyzer
        pass
    
    # Inisialisasi packet capture manager
    capture_manager = PacketCaptureManager(analyzer, CAPTURE_CONFIG)
    
    # Mulai proses penangkapan
    try:
        logger.info("Starting Network Traffic Analysis...")
        capture_manager.start_capture()
    except KeyboardInterrupt:
        logger.info("Application terminated by user")
    except Exception as e:
        logger.error(f"Error in main application: {e}")
    finally:
        logger.info("Application shutdown complete")

if __name__ == "__main__":
    main()