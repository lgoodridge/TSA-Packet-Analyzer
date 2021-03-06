"""
This module contains country related analysis functions
"""

from capturer.geoip_proxy import get_country_name
from analyzer.ip import get_host_ip_addr, get_ip_to_packet_count, get_ip_to_total_traffic_size, UNKNOWN, PACKET_COUNT, TRAFFIC_SIZE

def get_country_to_packet_count(stream):
    """
    Counts the number of packets the host has sent to or received
    from different countries. If an ip address cannot be mapped to
    a country it is mapped to unknown.

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are names of countries and the
        values are the number of packets from / to that country.
    """

    # Get dictionary of ip addresses to counts, minus host IP address
    ip_counts = get_ip_to_packet_count(stream)
    host_ip_addr = get_host_ip_addr(stream, ip_counts)
    ip_counts.pop(host_ip_addr, None)

    # Coalesce country packet counts using ip count dict
    country_counts = {UNKNOWN: 0}
    for ip, count in ip_counts.items():
        country_name = get_country_name(ip)
        if country_name:
            if country_name in country_counts:
                country_counts[country_name] += count
            else:
                country_counts[country_name] = count
        else:
            country_counts[UNKNOWN] += 1

    return country_counts


def get_country_to_traffic_size(stream):
    """
    Size of traffic in bytes that the host has sent to or received
    from different countries. If an ip address cannot be mapped to
    a country it is mapped to unknown.

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are names of countries and the
        values are the size of traffic (in bytes) received from / sent
        to that country.
    """

    # Get dictionary of ip addresses to counts, minus host IP address
    ip_traffic_size = get_ip_to_total_traffic_size(stream)
    host_ip_addr = get_host_ip_addr(stream)
    ip_traffic_size.pop(host_ip_addr, None)

    # Coalesce country packet counts using ip count dict
    country_traffic_sizes = {UNKNOWN: 0}
    for ip, traffic_size in ip_traffic_size.items():
        country_name = get_country_name(ip)
        if country_name:
            if country_name in country_traffic_sizes:
                country_traffic_sizes[country_name] += traffic_size
            else:
                country_traffic_sizes[country_name] = traffic_size
        else:
            country_traffic_sizes[UNKNOWN] += 1

    return country_traffic_sizes



def consolidate_country_data(stream):
    """
    Consolidates all known country data

    Args:
        stream (TSAStream object): List of TSAPacket objects

    Returns:
        A dictionary mapping each country to a dictionary of data,
        ex: {"USA": {"Packet Count": 50, "Traffic Size": 1200}}
    """   
    country_data = {}
    country_traffic_size = get_country_to_traffic_size(stream)
    country_packet_count = get_country_to_packet_count(stream)

    for country in country_traffic_size:
        data = {}
        data[PACKET_COUNT] = country_packet_count[country]
        data[TRAFFIC_SIZE] = country_traffic_size[country]
        country_data[country] = data

    return country_data
