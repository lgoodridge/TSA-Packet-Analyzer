"""
This module contains IP related analysis functions.
"""

from capturer.p0f_proxy import get_security_info
from tld import get_tld

#Constants
UNKNOWN = "Unknown"

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

def get_ip_to_security_info(stream):
    """
    Returns a dictionary relating IP addresses to
    dictionaries containing security info gathered by p0f.
    """
    all_ip_addrs = stream.get_values_for_key('src_addr') +\
            stream.get_values_for_key('src_addr')
    unique_ip_addrs = set(all_ip_addrs)
    ip_security = {ip: get_security_info(ip) for ip in unique_ip_addrs}
    return ip_security

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
        length = int(packet.length)
        ip_traffic_size[src] = ip_traffic_size[src] + length if src in ip_traffic_size else length
        ip_traffic_size[dst] = ip_traffic_size[dst] + length if dst in ip_traffic_size else length
    return ip_traffic_size

def aggregate_on_dns(ip_values, ip_fqdns):
    """
    Aggregates the values in ip_values based on domains accessed from
    ip_fqdns. Values from same ip_addresses same domain names are combines

    Args:
        ip_values (dictionary): maps ip address to some computed value
                                host has already been removed from ip_values
        ip_fqdns (dictionary): maps ip address to fqdns

    Returns:
        a dictionary mapping tld domains to the values in ip_values, aggregated.
    """
    # Coalesce fqdn packet counts using ip count dict
    fqdn_domain_counts = {}
    fqdn_domain_counts[UNKNOWN] = 0
    fqdn_domain_aliases = {}
    fqdn_domain_aliases[UNKNOWN] = {UNKNOWN}

    for ip, count in ip_values.items():
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
            if domain in fqdn_domain_counts:
                fqdn_domain_counts[domain] += count
            else:
                fqdn_domain_counts[domain] = count

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
            fqdn_domain_counts[UNKNOWN] += 1

    fqdn_alias_count = {}
    for domain in fqdn_domain_counts:
        alias_list = list(fqdn_domain_aliases[domain])
        alias_list.sort()
        alias_name = ", ".join(alias_list)
        if alias_name in fqdn_alias_count:
            fqdn_alias_count[alias_name] += fqdn_domain_counts[domain]
        else:
            fqdn_alias_count[alias_name] = fqdn_domain_counts[domain]

    return fqdn_alias_count
