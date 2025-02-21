import time
import json
import requests
from collections import deque

from packet_processing.feature_extraction import prepare_ml_features_for_external
from utils.logging_utils import get_logger

logger = get_logger(__name__)

class ExternalMLIntegration:
    """
    Kelas untuk integrasi dengan layanan ML eksternal melalui API
    """
    
    def __init__(self, config):
        """
        Inisialisasi integrator ML eksternal
        
        Args:
            config (dict): Konfigurasi untuk integrasi ML eksternal
        """
        self.config = config
        self.api_endpoint = config['api_endpoint']
        self.api_key = config['api_key']
        self.timeout = config['timeout_seconds']
        
        # Buffer untuk batch processing
        self.buffer = deque(maxlen=config['batch_size'])
        self.batch_size = config['batch_size']
        
        # Fallback untuk kasus API tidak tersedia
        self.use_fallback = False
    
    def analyze(self, features_dict):
        """
        Mengirim fitur paket ke API ML eksternal untuk analisis
        
        Args:
            features_dict (dict): Fitur-fitur paket
            
        Returns:
            dict: Hasil analisis dari ML eksternal atau fallback
        """
        # Siapkan fitur untuk API eksternal
        api_features = prepare_ml_features_for_external(features_dict)
        
        # Jika fallback mode aktif, gunakan analisis sederhana
        if self.use_fallback:
            return self._fallback_analysis(api_features)
        
        # Coba kirim ke API eksternal
        try:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            payload = {
                'features': api_features,
                'metadata': {
                    'client_version': '1.0',
                    'timestamp': time.time()
                }
            }
            
            # Kirim request ke API
            response = requests.post(
                self.api_endpoint,
                headers=headers,
                data=json.dumps(payload),
                timeout=self.timeout
            )
            
            # Periksa status response
            if response.status_code == 200:
                result = response.json()
                
                # Format hasil untuk integrasi dengan sistem
                return {
                    'analyzer_type': 'external',
                    'anomaly_score': result.get('anomaly_score', 0.0),
                    'cluster': result.get('cluster', -1),
                    'is_suspicious': result.get('is_suspicious', False),
                    'model_version': result.get('model_version', 'external-1.0')
                }
            else:
                logger.warning(f"External ML API returned status {response.status_code}")
                self.use_fallback = True
                return self._fallback_analysis(api_features)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling external ML API: {e}")
            self.use_fallback = True
            return self._fallback_analysis(api_features)
    
    def _fallback_analysis(self, features):
        """
        Analisis fallback sederhana ketika API eksternal tidak tersedia
        
        Args:
            features (dict): Fitur paket yang disiapkan untuk API
            
        Returns:
            dict: Hasil analisis fallback sederhana
        """
        # Implementasi sederhana berbasis aturan
        is_suspicious = False
        anomaly_score = 0.0
        
        # Periksa pola mencurigakan dalam fitur
        if features['flags_syn'] and not features['flags_ack']:
            # Kemungkinan SYN scan
            is_suspicious = True
            anomaly_score = 0.8
        elif features['packet_size'] < 40:
            # Paket yang terlalu kecil mungkin mencurigakan
            is_suspicious = True
            anomaly_score = 0.6
        
        return {
            'analyzer_type': 'external-fallback',
            'anomaly_score': anomaly_score,
            'cluster': 0,
            'is_suspicious': is_suspicious,
            'model_version': 'fallback-1.0'
        }
    
    def batch_analyze(self, features_list):
        """
        Analisis batch untuk beberapa paket sekaligus
        
        Args:
            features_list (list): Daftar fitur-fitur paket
            
        Returns:
            list: Hasil analisis untuk setiap paket
        """
        # Implementasi batch processing untuk API eksternal
        # Berguna untuk efisiensi jika API mendukung batch processing
        pass