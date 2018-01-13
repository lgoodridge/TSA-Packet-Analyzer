"""
This module contains dns / hostname related analysis functions.
"""

from analyzer.ip import get_host_ip_addr, get_ip_to_packet_count, \
        get_ip_to_fqdns, aggregate_on_dns

def get_fqdn_to_packet_count(stream):
    """
    Counts the number of packets the host has sent to or received from each
    Fully Qualified Domain Name (fqdns), aggregated.

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are tld domains and the values are the 
    number of packets from / to that tld domain.
    """

    # Get dictionary of ip addrs to counts / fqdns, minus host IP address
    ip_counts = get_ip_to_packet_count(stream)
    ip_fqdns = get_ip_to_fqdns(stream)
    host_ip_addr = get_host_ip_addr(stream, ip_counts)
    ip_counts.pop(host_ip_addr, None)

    fqdn_alias_count = aggregate_on_dns(ip_counts, ip_fqdns)

    return fqdn_alias_count
