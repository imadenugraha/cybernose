import time
from scapy.all import sniff

from packet_processing.feature_extraction import extract_features
from database.db_manager import store_packet_analysis
from utils.logging_utils import get_logger

logger = get_logger(__name__)

class PacketCaptureManager:
    """Manager untuk penangkapan dan pemrosesan paket"""
    
    def __init__(self, ml_analyzer, capture_config):
        """
        Initialize packet capture manager
        
        Args:
            ml_analyzer: Objek analyzer ML (internal atau wrapper untuk eksternal)
            capture_config (dict): Konfigurasi untuk penangkapan paket
        """
        self.ml_analyzer = ml_analyzer
        self.config = capture_config
        self.is_running = False
        self.packets_processed = 0
        self.suspicious_packets = 0
    
    def packet_callback(self, packet):
        """
        Callback yang dipanggil untuk setiap paket yang ditangkap
        
        Args:
            packet: Paket Scapy yang ditangkap
        """
        # Ekstrak fitur
        features = extract_features(packet)
        if not features:
            return
        
        # Mulai timer untuk menghitung durasi analisis
        start_time = time.time()
        
        # Analisis dengan model ML
        ml_results = self.ml_analyzer.analyze(features)
        
        # Hitung durasi analisis
        analysis_duration_ms = (time.time() - start_time) * 1000
        ml_results['analysis_duration_ms'] = analysis_duration_ms
        
        # Simpan di database
        store_packet_analysis(features, ml_results)
        
        # Update statistik
        self.packets_processed += 1
        if ml_results['is_suspicious']:
            self.suspicious_packets += 1
            logger.warning(
                f"SUSPICIOUS PACKET: {features['src_ip']}:{features.get('src_port', 0)} -> "
                f"{features['dst_ip']}:{features.get('dst_port', 0)} "
                f"(Score: {ml_results['anomaly_score']:.2f})"
            )
        
        # Log progres
        if self.packets_processed % 1000 == 0:
            logger.info(f"Processed {self.packets_processed} packets "
                       f"({self.suspicious_packets} suspicious)")
    
    def start_capture(self):
        """Mulai penangkapan paket"""
        self.is_running = True
        logger.info("Starting packet capture...")
        
        try:
            # Mulai penangkapan paket
            sniff(
                prn=self.packet_callback,
                iface=self.config['interface'],
                filter=self.config['filter'],
                count=self.config['packet_count'],
                store=0
            )
        except KeyboardInterrupt:
            logger.info("\nStopping capture...")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            self.is_running = False
            logger.info(f"Capture stopped. Total processed: {self.packets_processed} packets.")