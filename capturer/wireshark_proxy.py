"""
This module serves as a proxy for the wireshark reader / capturer.

This module should be initialized via either of the init methods
before its other methods are used.
"""

from capturer.tsa_packet import TSAPacket, TSAPacketParseException
from capturer.tsa_stream import TSAStream
from settings import get_setting

import pyshark

# Pyshark Capture object containing the
# current captured Wireshark packets
pyshark_capture = None

def init_from_file(cap_filename):
    """
    Initializes the wireshark proxy using the provided .pcap file.
    """
    global pyshark_capture
    pyshark_capture = pyshark.FileCapture(cap_filename)

    # Since the next_packet method for FileCaptures doesn't work
    # as expected, we have to manually access each index until
    # we find the end bound of the capture (sigh)
    index = 0
    while True:
        try:
            packet = pyshark_capture[index]
            index += 1
        except KeyError:
            break

def init_live_capture():
    """
    Initializes the wireshark proxy and begins a wireshark
    live capture as a background process.
    """
    global pyshark_capture
    raise NotImplementedError()

def read_packets(num_packets=None):
    """
    Reads num_packets packets from the tail of the capture, and
    returns them as a TSAStream. Packets that fail to parse are
    silently dropped from the returned stream.

    If num_packets is None, attempts to read all captured packets.
    """
    if pyshark_capture is None:
        raise RuntimeError("Wireshark Proxy has not been initialized")

    if not num_packets:
        start_index = 0
    else:
        start_index = max(0, len(pyshark_capture) - num_packets)

    tsa_packets = []
    for i in range(start_index, len(pyshark_capture)):
        try:
            tsa_packet = TSAPacket.parse_pyshark_packet(pyshark_capture[i])
            tsa_packets.append(tsa_packet)
        except TSAPacketParseException:
            continue

    return TSAStream(tsa_packets)
