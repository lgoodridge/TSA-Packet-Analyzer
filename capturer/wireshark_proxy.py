"""
This module serves as a proxy for the wireshark reader / capturer.

This module should be initialized via either of the init methods
before its other methods are used.
"""

from capturer.tsa_packet import TSAPacket, TSAPacketParseException
from capturer.tsa_stream import TSAStream

import collections
import pyshark
import threading

# Pyshark Capture object containing the
# current captured Wireshark packets
pyshark_capture = None

# Deque that acts as a ring buffer for
# the captured and parsed Wireshark packets
packet_deque = collections.deque(maxlen=20000)

# Background thread used to capture packets with
background_thread = None

def init_from_file(cap_filename):
    """
    Initializes the wireshark proxy using the provided .pcap file.
    """
    global pyshark_capture, packet_deque
    if pyshark_capture:
        raise RuntimeError("Attempted to double initialize wireshark proxy.")

    pyshark_capture = pyshark.FileCapture(cap_filename)

    # Attempt to parse each packet and drop the ones that fail
    # from the dequeue. Stop once we've run out of packets.
    index = 0
    while True:
        try:
            packet = pyshark_capture[index]
            tsa_packet = TSAPacket.parse_pyshark_packet(packet)
            packet_deque.append(tsa_packet)
        except TSAPacketParseException:
            continue
        except KeyError:
            break
        finally:
            index += 1

def init_live_capture(cap_interface):
    """
    Initializes the wireshark proxy and begins a wireshark
    live capture as a background thread.
    """
    global pyshark_capture, background_thread
    if pyshark_capture:
        raise RuntimeError("Attempted to double initialize wireshark proxy.")

    # Define method that continuously captures and
    # parses packets and places them into the deque
    def capture_packets():
        global pyshark_capture, packet_deque
        pyshark_capture = pyshark.LiveCapture(cap_interface)
        for packet in pyshark_capture.sniff_continuously():
            try:
                tsa_packet = TSAPacket.parse_pyshark_packet(packet)
                packet_deque.append(tsa_packet)
            except TSAPacketParseException:
                continue

    # Run this method in the background
    background_thread = threading.Thread(target=capture_packets)
    background_thread.start()

def cleanup():
    """
    Stops any background processes / threads and
    returns the module to its uninitialized state.
    """
    global pyshark_capture, packet_deque, background_thread
    if pyshark_capture:
        pyshark_capture = None
    if packet_deque:
        packet_deque.clear()
    if background_thread:
        background_thread = None

def read_packets(num_packets=None):
    """
    Reads num_packets packets from the tail of the capture, and
    returns them as a TSAStream. Packets that fail to parse are
    silently dropped from the returned stream, and not counted.

    If num_packets is None, attempts to read all captured packets.
    """
    global pyshark_capture, packet_deque
    if pyshark_capture is None:
        raise RuntimeError("Wireshark Proxy has not been initialized")

    if not num_packets:
        start_index = 0
    else:
        start_index = max(0, len(packet_deque) - num_packets)

    tsa_packets = list(packet_deque)[start_index:]
    return TSAStream(tsa_packets)
