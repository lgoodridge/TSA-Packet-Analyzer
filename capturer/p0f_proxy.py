"""
This module serves as a proxy for the p0f capturer / database.

This module should be initialized via either of the init methods
before its other methods are used.
"""

from p0f import P0f, P0fException
from settings import get_setting

import os
import subprocess
import sys

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

    sys.stdout.flush()
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

    The dictionary returned will have the following fields,
    with missing or undetermined fields having a value of None:
        os_name:  name of the OS host is using
        os_full_name:  name and version of the OS host is using
        app_name:  name of the HTTP application host is using
        app_full_name: name and version of the application host is using
        language:  system language
        link_type:  network link type (e.g. 'Ethernet', 'DSL', ...)
        num_hops:  network distance in packet hops
        uptime:  estimated uptime of the system (in minutes)
    """
    global p0f_db
    if not p0f_db:
        return None

    try:
        raw_info = p0f_db.get_info(host_ip)
        results = {}

        # Perform some processing on the string fields
        os_name_raw = raw_info['os_name'].decode('utf8')
        os_flavor_raw = raw_info['os_flavor'].decode('utf8')
        if os_name_raw[0] != "\0":
            os_name = os_name_raw.rstrip(" \0")
            os_full_name = (os_name + " " + os_flavor_raw).rstrip(" \0")
        else:
            os_name = None
            os_full_name = None

        http_name_raw = raw_info['http_name'].decode('utf8')
        http_flavor_raw = raw_info['http_name'].decode('utf8')
        if http_name_raw[0] != "\0":
            app_name = http_name_raw.rstrip(" \0")
            app_full_name = (app_name + " " + http_flavor_raw).rstrip(" \0")
        else:
            app_name = None
            app_full_name = None

        language_raw = raw_info['language'].decode('utf8')
        if language_raw[0] != "\0":
            language = language_raw.rstrip(" \0")
        else:
            language = None

        link_type_raw = raw_info['link_type'].decode('utf8')
        if link_type_raw[0] != "\0":
            link_type = str(link_type_raw).rstrip(" \0")
        else:
            link_type = language

        # Perform some processing on the integer fields
        if raw_info['distance'] and int(raw_info['distance']) != -1:
            num_hops = int(raw_info['distance'])
        else:
            num_hops = None

        if raw_info['uptime_min'] and int(raw_info['uptime_min']) != 0:
            uptime = int(raw_info['uptime_min'])
        else:
            uptime = None

        # Combine the processed results into a dict and return it
        processed_info = {
            'os_name': os_name,
            'os_full_name': os_full_name,
            'app_name': app_name,
            'app_full_name': app_full_name,
            'language': language,
            'link_type': link_type,
            'num_hops': num_hops,
            'uptime': uptime,
        }
        return processed_info

    except KeyError:
        return None
