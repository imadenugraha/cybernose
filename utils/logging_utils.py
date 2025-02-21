import os
import logging
from logging.handlers import RotatingFileHandler

def get_logger(name, log_file='network_analyzer.log', level=logging.INFO):
    """
    Mendapatkan logger yang dikonfigurasi
    
    Args:
        name (str): Nama logger
        log_file (str): Path file log
        level: Level logging
        
    Returns:
        logging.Logger: Objek logger yang dikonfigurasi
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Periksa jika handler sudah ada
    if not logger.handlers:
        # File handler dengan rotasi
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_format)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_format = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_format)
        
        # Tambahkan handlers ke logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger