from datetime import datetime
from pony.orm import Database, Required, Optional, PrimaryKey

db = Database()

class PacketData(db.Entity):
    id = PrimaryKey(int, auto=True)
    timestamp = Required(datetime)
    src_ip = Required(str)
    dst_ip = Required(str)
    protocol = Required(str)
    src_port = Required(int)
    dst_port = Required(int)
    packet_size = Required(int)
    flags = Optional(str)
    ttl = Optional(int)
    window_size = Optional(int)
    
    analyzer_type = Required(str)
    anomaly_score = Required(float)
    cluster = Required(int)
    is_suspicous = Required(bool)
    
    ml_model_version = Required(str)
    analysis_duration_ms = Optional(float)
    
def initialize_database(db_config):
    """
    Initialize the database connection and create tables.

    :param db_config: A dictionary of settings used to connect to the
        database. The dictionary should have the following keys:

        - provider: The type of database (e.g. "postgres", "mysql")
        - user: The username to use to connect to the database
        - password: The password to use to connect to the database
        - host: The hostname or IP address of the database server
        - database: The name of the database to connect to

    :return: The initialized Database object
    """
    db.bind(**db_config)
    db.generate_mapping(create_tables=True)
    return db
