from scapy.all import IP, TCP, UDP

def extract_features(packet):
    """
    Ekstrak fitur-fitur relevan dari paket jaringan untuk analisis ML
    
    Args:
        packet: Paket Scapy yang diambil dari jaringan
        
    Returns:
        dict: Dictionary berisi fitur-fitur yang diekstrak, atau None jika bukan paket IP
    """
    features = {}
    
    # Basic IP features
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['packet_size'] = len(packet)
        features['ttl'] = packet[IP].ttl
        features['protocol'] = packet[IP].proto
    else:
        return None  # Skip non-IP packets
    
    # TCP specific features
    if TCP in packet:
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
        features['flags'] = str(packet[TCP].flags)
        features['window_size'] = packet[TCP].window
    # UDP specific features
    elif UDP in packet:
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport
        features['flags'] = ''
        features['window_size'] = 0
    else:
        features['src_port'] = 0
        features['dst_port'] = 0
        features['flags'] = ''
        features['window_size'] = 0
    
    return features

def prepare_ml_features(features_dict):
    """
    Menyiapkan fitur dalam format yang siap untuk analisis ML
    
    Args:
        features_dict (dict): Fitur paket mentah
        
    Returns:
        list: Daftar fitur numerik yang siap untuk model ML
    """
    # Ekstrak fitur numerik untuk ML
    ml_features = [
        features_dict.get('packet_size', 0),
        features_dict.get('ttl', 0),
        features_dict.get('src_port', 0),
        features_dict.get('dst_port', 0),
        features_dict.get('window_size', 0)
    ]
    return ml_features

def prepare_ml_features_for_external(features_dict):
    """
    Menyiapkan fitur dalam format yang siap untuk API ML eksternal
    
    Args:
        features_dict (dict): Fitur paket mentah
        
    Returns:
        dict: Fitur dalam format JSON yang siap dikirim ke API eksternal
    """
    return {
        'packet_size': features_dict.get('packet_size', 0),
        'ttl': features_dict.get('ttl', 0),
        'src_port': features_dict.get('src_port', 0),
        'dst_port': features_dict.get('dst_port', 0),
        'window_size': features_dict.get('window_size', 0),
        'protocol': features_dict.get('protocol', 0),
        'flags_fin': '0' in str(features_dict.get('flags', '')),
        'flags_syn': '2' in str(features_dict.get('flags', '')),
        'flags_rst': '4' in str(features_dict.get('flags', '')),
        'flags_psh': '8' in str(features_dict.get('flags', '')),
        'flags_ack': '16' in str(features_dict.get('flags', '')),
        'flags_urg': '32' in str(features_dict.get('flags', ''))
    }