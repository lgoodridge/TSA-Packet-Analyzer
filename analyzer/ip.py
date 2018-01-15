"""
This module contains IP related analysis functions.
"""

from capturer.p0f_proxy import get_security_info
from capturer.geoip_proxy import get_country_name
from tld import get_tld

#Constants
UNKNOWN = "Unknown"

PACKET_COUNT = "Packet Count"
TRAFFIC_SIZE = "Traffic Size"
SECURITY_INFO = "Security Info"
COUNTRY_NAMES = "Country Names"

# cache of ip to fqdns
ip_fqdns_cache = {}

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
    Returns a dictionary relating IP addresses to a set
    of all fully qualified domain names that use them in
    the provided stream.

    """
    global ip_fqdns_cache

    ip_fqdns = {}
    for packet in stream:
        if packet.dns_resp_ip:
            resp_ip = packet.dns_resp_ip
            if resp_ip in ip_fqdns:
                ip_fqdns[resp_ip].update(packet.dns_query_names)
            else:
                ip_fqdns[resp_ip] = set(packet.dns_query_names)

    ips = []
    for packet in stream:
        src = packet.src_addr
        dst = packet.dst_addr
        ips.extend([src, dst])

    ips = set(ips)

    # update the cache with new info
    for ip, fqdns in ip_fqdns.items():
        ip_fqdns_cache[ip] = set(fqdns)

    # use cache to add missing info to result
    for ip in ips:
        if ip not in ip_fqdns and ip in ip_fqdns_cache:
            ip_fqdns[ip] = set(ip_fqdns_cache[ip])

    return ip_fqdns

def get_ip_to_security_info(stream):
    """
    Returns a dictionary relating IP addresses to
    dictionaries containing security info gathered by p0f.

    If an IP address doesn't have any security information it
    is not included in the dictionary

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
    ip_security = {}
    for packet in stream:
        src = packet.src_addr
        dst = packet.dst_addr
        ips = [src, dst]

        for ip in ips:
            if ip not in ip_security:
                security_info = get_security_info(ip)
                if security_info:
                    ip_security[ip] = security_info

    return ip_security

def get_ip_to_country_name(stream):
    """
    Returns a dictionary relating IP addresses to the country
    that the server of each IP address is believed to be located in.
    If an ip address cannot be associated with a country UNKNOWN
    is returned.
    """
    ip_country = {}
    for packet in stream:
        src = packet.src_addr
        dst = packet.dst_addr
        ips = [src, dst]

        for ip in ips:
            if ip not in ip_country:
                country_name = get_country_name(ip)
                if country_name:
                    ip_country[ip] = country_name
                else:
                    ip_country[ip] = UNKNOWN

    return ip_country


def get_ip_to_total_traffic_size(stream):
    """
    Returns a dictionary relating IP addresses to their total traffic size.
    Where total traffic size is the size of all the packets that the address
    is present in as a source or a destination in the provided stream.
    """
    ip_traffic_size = {}
    for packet in stream:
        src = packet.src_addr
        dst = packet.dst_addr
        length = packet.length
        ip_traffic_size[src] = ip_traffic_size[src] + length if src in ip_traffic_size else length
        ip_traffic_size[dst] = ip_traffic_size[dst] + length if dst in ip_traffic_size else length
    return ip_traffic_size

def aggregate_on_dns(ip_values, ip_fqdns, is_numeric=True):
    """
    Aggregates the values in ip_values based on domains accessed from
    ip_fqdns. Values from same ip_addresses same domain names are combines

    Args:
        ip_values (dictionary): maps ip address to some computed value
                                host has already been removed from ip_values
        ip_fqdns (dictionary): maps ip address to fqdns

        is_numeric (boolean): are the values numeric? If so, add the values,
                              else create a list of values.

    Returns:
        a dictionary mapping tld domains to the values in ip_values,
        aggregated as sums or as a list.
    """
    # Coalesce fqdn packet counts using ip values dict
    fqdn_domain_values = {}
    fqdn_domain_values[UNKNOWN] = 0 if is_numeric else []
    fqdn_domain_aliases = {}
    fqdn_domain_aliases[UNKNOWN] = {UNKNOWN}

    for ip, value in ip_values.items():
        fqdns = ip_fqdns.get(ip, None)

        if fqdns:
            domain_set = set()
            for fqdn in fqdns:
                res = get_tld(fqdn, as_object=True, fail_silently=True,
                              fix_protocol=True)
                domain_set.add(str(res))
            domain_set = list(domain_set)
            # Add domains to domain counts, only adding first entry if multiple
            domain = domain_set[0]
            if domain in fqdn_domain_values:
                if is_numeric:
                    fqdn_domain_values[domain] += value
                else:
                    fqdn_domain_values[domain].append(value)
            else:
                if is_numeric:
                    fqdn_domain_values[domain] = value
                else:
                    fqdn_domain_values[domain] = [value]

            # Add aliases for domains
            for domain1 in domain_set:
                if domain1 not in fqdn_domain_aliases:
                    fqdn_domain_aliases[domain1] = {domain1}
                for domain2 in domain_set:
                    if domain2 not in fqdn_domain_aliases[domain1]:
                        if (domain2 in fqdn_domain_aliases):
                            for domain in fqdn_domain_aliases[domain2]:
                                if domain != domain1:
                                    if (domain in fqdn_domain_aliases):
                                        fqdn_domain_aliases[domain] = fqdn_domain_aliases[domain].union(fqdn_domain_aliases[domain1])
                                        fqdn_domain_aliases[domain1] = fqdn_domain_aliases[domain].union(fqdn_domain_aliases[domain1])
                        fqdn_domain_aliases[domain1].add(domain2)

        else:
            if is_numeric:
                fqdn_domain_values[UNKNOWN] += value
            else:
                fqdn_domain_values[UNKNOWN].append(value)

    fqdn_alias_count = {}
    for domain in fqdn_domain_values:
        alias_list = list(fqdn_domain_aliases[domain])
        alias_list.sort()
        alias_name = ", ".join(alias_list)
        if alias_name in fqdn_alias_count:
            fqdn_alias_count[alias_name] += fqdn_domain_values[domain]
        else:
            fqdn_alias_count[alias_name] = fqdn_domain_values[domain]

    return fqdn_alias_count
