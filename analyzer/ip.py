"""
This module contains IP related analysis functions.
"""

def get_host_ip_addr(stream, ip_counts=None):
    """
    Returns the host IP address from a stream of packets,
    or None, if one cannot be guessed.

    If dictionary of ip addresses to packet counts is provided,
    that is used instead of recalculated for efficiency.

    Host IP address must appear in each packet at least once.
    """
    if not ip_counts:
        ip_counts = get_ip_to_packet_count(stream)
    for addr, count in ip_counts.items():
        if count >= len(ip_counts):
            return addr
    return None

def get_ip_to_packet_count(stream):
    """
    Returns a dictionary relating IP addresses to the
    number of times they are used as a source or
    destination address in the provided stream.
    """
    ip_counts = {}
    for packet in stream:
        src = packet.src_addr
        dst = packet.dst_addr
        ip_counts[src] = ip_counts[src] + 1 if src in ip_counts else 1
        ip_counts[dst] = ip_counts[dst] + 1 if dst in ip_counts else 1
    return ip_counts

def get_ip_to_fqdns(stream):
    """
    Returns a dictionary relating IP addresses to a list
    of all fully qualified domain names that use them in
    the provided stream.

    IP addresses contained in ignore_addrs are dropped
    from the returned dictionary.
    """
    ip_fqdns = {}
    for packet in stream:
        if packet.dns_resp_ip:
            resp_ip = packet.dns_resp_ip
            if resp_ip in ip_fqdns:
                ip_fqdns[resp_ip].update(packet.dns_query_names)
            else:
                ip_fqdns[resp_ip] = set(packet.dns_query_names)
    return ip_fqdns

