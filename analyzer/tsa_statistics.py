"""
This module contains a library of functions that analyze a TSAStream to return different statistics

"""
from analyzer.utils import get_country_from_ip_geoipDB, get_host_ip_addr

def get_country_counts(packets):
    """
    Counts the number of packets the host has sent to or received from different countries. If an ip address cannot be
    mapped to a country it is mapped to unknown.

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are names of countries and the values are the number of packets
        from / to that country.
    """

    unknown = 'Unknown'

    #TODO: get_host_ip_addr might be inappropriate when analyzing a network's traffic instead of a host's traffic
    host_ip_addr = get_host_ip_addr(packets)

    ip_counts = {}
    for packet in packets:
        src = packet.src_addr
        dst = packet.dst_addr

        ip_counts[src] = ip_counts[src] + 1 if src in ip_counts else 1
        ip_counts[dst] = ip_counts[dst] + 1 if dst in ip_counts else 1

    ip_counts.pop(host_ip_addr, None)

    country_counts = {}
    country_counts[unknown] = 0
    for ip, count in ip_counts.items():
        country_name = get_country_from_ip_geoipDB(ip)

        if country_name:
            if country_name in country_counts:
                country_counts[country_name] += count
            else:
                country_counts[country_name] = count
        else:
            country_counts[unknown] += 1


    return country_counts

def get_fqdn_counts(packets):
    """
    Counts the number of packets the host has sent to or received from each  Fully Qualified Domain Name (fqdns).

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are FQDNs and the values are the number of packets from / to that FQDN
        from / to that country.
    """

    unkown = 'Unknown'

    host_ip_addr = get_host_ip_addr(packets)

    ip_counts = {}

    ip_to_fqdns = {}

    for packet in packets:
        src = packet.src_addr
        dst = packet.dst_addr

        ip_counts[src] = ip_counts[src] + 1 if src in ip_counts else 1
        ip_counts[dst] = ip_counts[dst] + 1 if dst in ip_counts else 1

        # if query response
        if packet.dns_query_resp_ip:
            resp_ip = packet.dns_query_resp_ip
            if resp_ip in ip_to_fqdns:
                ip_to_fqdns[resp_ip].update(packet.dns_query_names)
            else:
                ip_to_fqdns[resp_ip] = set(packet.dns_query_names)

    ip_counts.pop(host_ip_addr, None)

    fqdn_counts = {}
    fqdn_counts[unkown] = 0
    for ip, count in ip_counts.items():
        fqdns = ip_to_fqdns.get(ip, None)

        if fqdns:
            fqdn_counts[", ".join(fqdns)] = count
        else:
            fqdn_counts[unkown] += 1


    return fqdn_counts
