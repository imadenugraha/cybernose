import time

from datetime import datetime
from pony.orm import db_session, commit, select
from database.models import PacketData


@db_session
def store_packet_analysis(packet_features, ml_results):
    """
    Stores the analysis results of a network packet in the database.

    :param packet_features: A dictionary containing the packet features, including:
        - src_ip: The source IP address.
        - dst_ip: The destination IP address.
        - protocol: The protocol used by the packet.
        - src_port: The source port number.
        - dst_port: The destination port number.
        - packet_size: The size of the packet.
        - flags: (Optional) The flags associated with the packet.
        - ttl: (Optional) The time-to-live value of the packet.
        - window_size: (Optional) The window size of the packet.

    :param ml_results: A dictionary containing the machine learning analysis results, including:
        - analyzer_type: (Optional) The type of analyzer used (default 'internal').
        - anomaly_score: The anomaly score of the packet.
        - cluster: The cluster ID assigned to the packet.
        - is_suspicous: A boolean indicating if the packet is suspicious.
        - model_version: (Optional) The version of the machine learning model used (default '1.0').
        - analysis_duration_ms: (Optional) The duration of the analysis in milliseconds.

    :return: The created PacketData object if successful, None if an error occurs.
    """

    try:
        start_time = time.time()
        
        packet_record = PacketData(
            timestamp = datetime.now(),
            src_ip = packet_features['src_ip'],
            dst_ip = packet_features['dst_ip'],
            protocol = str(packet_features['protocol']),
            src_port = packet_features.get('src_port', 0),
            dst_port = packet_features.get('dst_port', 0),
            packet_size = packet_features['packet_size'],
            flags = packet_features.get('flags', ''),
            ttl = packet_features.get('ttl', 0),
            window_size = packet_features.get('window_size', 0),
            
            analyzer_type = ml_results.get('analyzer_type', 'internal'),
            anomaly_score = ml_results['anomaly_score'],
            cluster = ml_results['cluster'],
            is_suspicous = ml_results['is_suspicous'],
            ml_model_version = ml_results.get('model_version', '1.0'),
            analysis_duration_ms = ml_results.get('analysis_duration_ms', 0)
        )
        
        commit()
        return packet_record
    except Exception as e:
        print(f"Error storing packet analysis: {e}")
        return None

@db_session
def get_suspicious_packet(limit=100):
    """
    Return a list of recent suspicious packets.

    :param limit: The maximum number of packets to return.
    :return: A list of PacketData objects, ordered by timestamp.
    """
    return select(p for p in PacketData if p.is_suspicious).order_by(lambda p: p.timestamp)[:][:limit]

@db_session
def get_packet_stats():
    total_count = select(p for p in PacketData).count()
    suspicious_count = select(p for p in PacketData if p.is_suspicious).count()
    
    return {
        'total_packets': total_count,
        'suspicious_packets': suspicious_count,
        'suspicious_percentage': (suspicious_count / total_count * 100) if total_count > 0 else 0
    }
