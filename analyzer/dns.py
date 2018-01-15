"""
This module contains dns / hostname related analysis functions.
"""

from analyzer.ip import get_host_ip_addr, get_ip_to_packet_count, \
        get_ip_to_fqdns, get_ip_to_security_info, get_ip_to_total_traffic_size, \
        get_ip_to_country_name, aggregate_on_dns, \
        PACKET_COUNT, TRAFFIC_SIZE, SECURITY_INFO, COUNTRY_NAMES

def get_tldn_to_packet_count(stream):
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


def get_tldn_to_traffic_size(stream):
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

def get_tldn_to_security_info(stream):
    """
    Returns a dictionary relating Top Level Domain Names (tldn) to
    dictionaries containing security info gathered by p0f.

    Each dictionary containing security info will have the following fields,
    with missing or undetermined fields having a value of None:
        os_name:  name of the OS host is using
        os_full_name:  name and version of the OS host is using
        app_name:  name of the HTTP application host is using
        app_full_name: name and version of the application host is using
        language:  system language
        link_type:  network link type (e.g. 'Ethernet', 'DSL', ...)
        num_hops:  network distance in packet hops
        uptime:  estimated uptime of the system (in minutes)
    """
    ip_security_info = get_ip_to_security_info(stream)
    ip_fqdn = get_ip_to_fqdns(stream)
    host_ip_addr = get_host_ip_addr(stream)
    ip_security_info.pop(host_ip_addr, None)

    tldn_security_info = aggregate_on_dns(ip_security_info, ip_fqdn,
                                          is_numeric=False)

    return tldn_security_info

def get_tldn_to_country_names(stream):
    """
    Returns a dictionary relating Top Level Domain Names (tldn) to
    a list of country names its servers are believed to be in.

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are tld domains and the values are lists
        of country names

    """
    ip_country_names = get_ip_to_country_name(stream)
    ip_fqdns = get_ip_to_fqdns(stream)
    host_ip_addr = get_host_ip_addr(stream)
    ip_country_names.pop(host_ip_addr, None)

    tldn_country_names = aggregate_on_dns(ip_country_names, ip_fqdns,
                                         is_numeric=False)

    return tldn_country_names

def consolidate_fqdn_data(stream):
    """
    Consolidates all known tldn data

    Args:
        stream (TSAStream object): List of TSAPacket objects

    Returns:
        A dictionary mapping each domain to a dictionary of data,
        ex: {"google.com": {"Packet Count": 50, "Traffic Size": 1200,
             "Security Info": list of security_info_dicts}}

    Each security_info_dict will have the following fields,
    with missing or undetermined fields having a value of None:
        os_name:  name of the OS host is using
        os_full_name:  name and version of the OS host is using
        app_name:  name of the HTTP application host is using
        app_full_name: name and version of the application host is using
        language:  system language
        link_type:  network link type (e.g. 'Ethernet', 'DSL', ...)
        num_hops:  network distance in packet hops
        uptime:  estimated uptime of the system (in minutes)

    """   
    tldn_data = {}
    tldn_traffic_size = get_tldn_to_traffic_size(stream)
    tldn_packet_count = get_tldn_to_packet_count(stream)
    tldn_security_info = get_tldn_to_security_info(stream)
    tldn_country_names = get_tldn_to_country_names(stream)

    for tldn in tldn_traffic_size:
        data = {}
        data[PACKET_COUNT] = tldn_packet_count[tldn]
        data[TRAFFIC_SIZE] = tldn_traffic_size[tldn]
        data[SECURITY_INFO] = tldn_security_info.get(tldn, [])
        data[COUNTRY_NAMES] = tldn_country_names[tldn]

        tldn_data[tldn] = data

    return tldn_data

