"""
This module serves as a proxy for the p0f capturer / database.

This module should be initialized via either of the init methods
before its other methods are used.
"""

from p0f import P0f, P0fException

# p0f database containing current
# security data for all seen hosts
p0f_db = None


def init_from_file(cap_filename):
    """
    Initializes the p0f proxy using the provided .cap file.
    """
    raise NotImplementedError()

def init_live_capture():
    """
    Initializes the p0f proxy and begins a p0f live capture
    as a background process.
    """
    raise NotImplementedError()


def get_security_info(host_ip):
    """
    Returns the stored security information for the provided
    IP address as a dictionary, or None if this host has not
    been seen yet.
    """
    raw_info = p0f_db.get_info(host_ip)
    # TODO: parse this into a cleaner dictionary
    raise NotImplementedError()
