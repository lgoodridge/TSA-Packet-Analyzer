"""
This module serves as a proxy for the wireshark reader / capturer.

This module should be initialized via either of the init methods
before its other methods are used.
"""

from capturer.tsa_packet import TSA_Packet
from capturer.tsa_stream import TSA_Stream

import pyshark

# Pyshark Capture object containing the
# current captured Wireshark packets
pyshark_capture = None


def init_from_file(cap_filename):
    """
    Initializes the wireshark proxy using the provided .cap file.
    """
    raise NotImplementedError()

def init_live_capture():
    """
    Initializes the wireshark proxy and begins a wireshark
    live capture as a background process.
    """
    raise NotImplementedError()


def read_packets(num_packets=None):
    """
    Reads num_packets packets from the tail of the capture, and
    returns them as a TSA_Stream. Packets that fail to parse are
    silently dropped from the returned stream.
    If num_packets is None, attempts to read all captured packets.
    """
    raise NotImplementedError()
