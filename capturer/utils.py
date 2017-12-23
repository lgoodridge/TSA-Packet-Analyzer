"""
Defines utility functions for the capturer layer
"""

def split_cdl(cdl_string):
    """
    Accepts a comma delimited list of values as a string,
    and returns a list of the string elements.
    """
    return [x.strip() for x in cdl_string.split(',')]
