"""
This module contains dns / hostname related analysis functions.
"""

from analyzer.ip import get_host_ip_addr, get_ip_to_packet_count, \
        get_ip_to_fqdns

def get_fqdn_to_packet_count(stream):
    """
    Counts the number of packets the host has sent to or received from each  Fully Qualified Domain Name (fqdns).

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are FQDNs and the values are the number of packets from / to that FQDN
        from / to that country.
    """
    UNKNOWN = 'Unknown'

    # Get dictionary of ip addrs to counts / fqdns, minus host IP address
    ip_counts = get_ip_to_packet_count(stream)
    ip_fqdns = get_ip_to_fqdns(stream)
    host_ip_addr = get_host_ip_addr(stream, ip_counts)
    ip_counts.pop(host_ip_addr, None)

    # Coalesce fqdn packet counts using ip count dict
    fqdn_counts = {}
    fqdn_counts[UNKNOWN] = 0
    for ip, count in ip_counts.items():
        fqdns = ip_fqdns.get(ip, None)

        if fqdns:
            fqdn_counts[", ".join(fqdns)] = count
        else:
            fqdn_counts[UNKNOWN] += 1

    return fqdn_counts
