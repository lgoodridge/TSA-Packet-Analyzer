"""
Reads and exposes the settings in the settings.ini file
"""

import configparser
import os

config = configparser.ConfigParser()
last_read_time = 0

SETTINGS_FILE = "settings.ini"

def check_settings_file():
    """
    See if settings file was updated since the last time
    it was read, and update the config parser if so.
    """
    global last_read_time
    last_modified_time = os.path.getmtime(SETTINGS_FILE)
    if last_modified_time > last_read_time:
        config.read(SETTINGS_FILE)
        last_read_time = last_modified_time

def get_setting(section, setting, type='string'):
    """
    Returns the value of the provided setting in the provided
    section. type can be 'string', 'int', or 'bool'.
    """
    check_settings_file()
    if type == "string":
        return config.get(section, setting)
    elif type == "int":
        return config.getint(section, setting)
    elif type == "bool":
        return config.getboolean(section, setting)
