"""
This module contains dns / hostname related analysis functions.
"""

from analyzer.ip import get_host_ip_addr, get_ip_to_packet_count, \
        get_ip_to_fqdns
from tld import get_tld

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
    fqdn_domain_counts = {}
    fqdn_domain_counts[UNKNOWN] = 0
    fqdn_domain_aliases = {}
    fqdn_domain_aliases[UNKNOWN] = {UNKNOWN}

    for ip, count in ip_counts.items():
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
