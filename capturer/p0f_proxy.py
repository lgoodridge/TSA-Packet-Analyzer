"""
This module serves as a proxy for the p0f capturer / database.

This module should be initialized via either of the init methods
before its other methods are used.
"""

from p0f import P0f, P0fException
from settings import get_setting

import os
import subprocess

# p0f database containing current
# security data for all seen hosts
p0f_db = None

# Background process where p0f will run
background_proc = None

def _init_p0f(flag, value):
    """
    Helper function for the init methods: performs most
    of the work for setting up background process and
    API socket database hook.
    """
    global p0f_db, background_proc
    if p0f_db:
        raise RuntimeError("Attempted to double initialize p0f proxy.")

    database_path = get_setting('p0f', 'DatabaseFilePath')
    socket_path = get_setting('p0f', 'APISocketFilePath')

    background_proc = subprocess.Popen(["p0f", "-f", database_path,
        "-s", socket_path, flag, value], stdout=open(os.devnull, 'w'),
        stderr=subprocess.STDOUT, close_fds=True)
    p0f_db = P0f(socket_path)

def init_from_file(cap_filename):
    """
    Initializes the p0f proxy using the provided .cap file.
    """
    # p0f doesn't support API mode when using static files!
    # It would be: _init_p0f("-r", cap_filename)
    pass

def init_live_capture(cap_interface):
    """
    Initializes the p0f proxy and begins a p0f live capture
    as a background process.
    """
    _init_p0f("-i", cap_interface)

def cleanup():
    """
    Stops any background processes / threads and
    returns the module to its uninitialized state.
    """
    global p0f_db, background_proc
    if p0f_db:
        p0f_db = None
    if background_proc:
        background_proc.kill()
        background_proc = None

def get_security_info(host_ip):
    """
    Returns the stored security information for the provided
    IP address as a dictionary, or None if this host has not
    been seen yet.
    """
    if not p0f_db:
        return None
    try:
        raw_info = p0f_db.get_info(host_ip)
        # TODO: parse this into a cleaner dictionary
        return raw_info
    except KeyError:
        return None
