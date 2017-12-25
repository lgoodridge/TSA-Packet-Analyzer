import geoip2.database
import geoip2.errors

from settings import get_setting

# Create a GEOIP reader object for future country lookup requests.
GEOIP_DB_READER = geoip2.database.Reader(get_setting('geoip2', 'DatabaseFilePath'))

# Query database with localhost to check if database is valid.
try:
    GEOIP_DB_READER.country('127.0.0.1')
except geoip2.errors.AddressNotFoundError:
    pass