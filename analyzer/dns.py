"""
This module contains dns / hostname related analysis functions.
"""

from analyzer.ip import get_host_ip_addr, get_ip_to_packet_count, \
        get_ip_to_fqdns, aggregate_on_dns, UNKNOWN, PACKET_COUNT, TRAFFIC_SIZE,\
        get_ip_to_total_traffic_size

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


def get_fqdn_to_traffic_size(stream):
    """
    Computes the size of traffic in bytes that  the host has sent to or
    received from each Fully Qualified Domain Name (fqdns), aggregated.

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are tld domains and the values are the
        size of traffic received from / to that tld domain.
    """
    ip_traffic_size = get_ip_to_total_traffic_size(stream)
    ip_fqdns = get_ip_to_fqdns(stream)
    host_ip_addr = get_host_ip_addr(stream)
    ip_traffic_size.pop(host_ip_addr, None)

    fqdn_alias_count = aggregate_on_dns(ip_traffic_size, ip_fqdns)

    return fqdn_alias_count

def consolidate_fqdn_data(stream):
    """
    Consolidates all known fqdn data

    Args:
        stream (TSAStream object): List of TSAPacket objects

    Returns:
        A dictionary mapping each domain to a dictionary of data,
        ex: {"google.com": {"Packet Count": 50, "Traffic Size": 1200}}
    """   
    fqdn_data = {}
    fqdn_traffic_size = get_fqdn_to_traffic_size(stream)
    fqdn_packet_count = get_fqdn_to_packet_count(stream)

    for fqdn in fqdn_traffic_size:
        data = {}
        data[PACKET_COUNT] = fqdn_packet_count[fqdn]
        data[TRAFFIC_SIZE] = fqdn_traffic_size[fqdn]
        fqdn_data[fqdn] = data

    return fqdn_data

