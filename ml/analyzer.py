import time
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from packet_processing.feature_extraction import prepare_ml_features
from utils.logging_utils import get_logger

logger = get_logger(__name__)

class NetworkTrafficAnalyzer:
    """Analyzer jaringan menggunakan clustering K-means"""
    
    def __init__(self, config):
        """
        Initialize network traffic analyzer
        
        Args:
            config (dict): Konfigurasi untuk analyzer
        """
        self.config = config
        self.scaler = StandardScaler()
        self.model = KMeans(n_clusters=config['n_clusters'], random_state=42)
        self.trained = False
        self.buffer = []
        self.buffer_size = config['buffer_size']
        self.suspicious_threshold = config['suspicious_threshold']
    
    def train_if_needed(self):
        """Train model jika buffer mencapai threshold"""
        if len(self.buffer) >= self.buffer_size:
            logger.info(f"Training model on {len(self.buffer)} packets...")
            X = np.array(self.buffer)
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            self.model.fit(X_scaled)
            self.trained = True
            self.buffer = []  # Clear buffer after training
            logger.info("Model training complete.")
    
    def analyze(self, features_dict):
        """
        Menganalisis paket dan mengembalikan skor anomali dan cluster
        
        Args:
            features_dict (dict): Fitur-fitur paket
            
        Returns:
            dict: Hasil analisis ML
        """
        ml_features = prepare_ml_features(features_dict)
        
        # If not trained yet, add to buffer and return default values
        if not self.trained:
            self.buffer.append(ml_features)
            self.train_if_needed()
            return {
                'analyzer_type': 'internal',
                'anomaly_score': 0.0,
                'cluster': -1,
                'is_suspicious': False,
                'model_version': 'training'
            }
        
        # Preprocess input for prediction
        X = np.array([ml_features])
        X_scaled = self.scaler.transform(X)
        
        # Get cluster assignment
        cluster = self.model.predict(X_scaled)[0]
        
        # Calculate anomaly score (distance to cluster center)
        center = self.model.cluster_centers_[cluster]
        distance = np.linalg.norm(X_scaled[0] - center)
        
        # Determine if suspicious based on distance threshold
        is_suspicious = distance > self.suspicious_threshold
        
        return {
            'analyzer_type': 'internal',
            'anomaly_score': float(distance),
            'cluster': int(cluster),
            'is_suspicious': bool(is_suspicious),
            'model_version': '1.0'
        }
