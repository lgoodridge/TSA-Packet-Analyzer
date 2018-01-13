"""
This module serves as a proxy for geoip database reader.

This module should be initialized via the init_module
method before its other methods are used.
"""

from settings import get_setting

import geoip2.database
import geoip2.errors

# GEOIP Reader object for country lookup requests
geoip_db_reader = None

def init_module():
    """
    Initializes the geoip database reader.
    """
    global geoip_db_reader
    if geoip_db_reader:
        raise RuntimeError("Attempted to double initialize geoip module")

    database_path = get_setting('geoip', 'DatabaseFilePath')
    geoip_db_reader = geoip2.database.Reader(database_path)

    # Ensure the reader is properly initialized
    try:
        geoip_db_reader.country('127.0.0.1')
    except geoip2.errors.AddressNotFoundError:
        pass

def cleanup():
    global geoip_db_reader
    if geoip_db_reader:
        geoip_db_reader = None

def get_country(ip_addr):
    """
    Takes in an ip address (string) and returns the
    country name (string) it maps to in the geoip db.
    """
    global geoip_db_reader
    try:
        name = geoip_db_reader.country(ip_addr).country.name
        return name
    except geoip2.errors.AddressNotFoundError:
        return None
