"""
Defines utility functions for the analyzer layer
"""

def get_host_ip_addr(packets):
    """
    Guesses the host ip address from a list of packets. Host ip address appears in each packet at least once.
    """
    ip_counts = {}
    host_ip_addr = None
    for packet in packets:
        src = packet.src_addr
        dst = packet.dst_addr

        ip_counts[src] = ip_counts[src] + 1 if src in ip_counts else 1
        ip_counts[dst] = ip_counts[dst] + 1 if dst in ip_counts else 1

        if ip_counts[src] >= len(packets):
            host_ip_addr = src
        elif ip_counts[dst] >= len(packets):
            host_ip_addr = dst

    return host_ip_addr
