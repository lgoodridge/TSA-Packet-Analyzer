"""
This module contains dns / hostname related analysis functions.
"""

from tld import get_tld
from analyzer.utils import get_host_ip_addr

def get_fqdn_to_packet_count(packets):
    """
    Counts the number of packets the host has sent to or received from each  Fully Qualified Domain Name (fqdns).

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary where the keys are FQDNs and the values are the number of packets from / to that FQDN
        from / to that country.
    """
    unknown = 'Unknown'
    host_ip_addr = get_host_ip_addr(packets)
    ip_counts = {}
    ip_to_fqdns = {}

    for packet in packets:
        src = packet.src_addr
        dst = packet.dst_addr

        ip_counts[src] = ip_counts[src] + 1 if src in ip_counts else 1
        ip_counts[dst] = ip_counts[dst] + 1 if dst in ip_counts else 1

        # if query response
        if packet.dns_resp_ip:
            resp_ip = packet.dns_resp_ip
            if resp_ip in ip_to_fqdns:
                ip_to_fqdns[resp_ip].update(packet.dns_query_names)
            else:
                ip_to_fqdns[resp_ip] = set(packet.dns_query_names)

    ip_counts.pop(host_ip_addr, None)

    # Keeps track of counts per domain
    fqdn_domain_counts = {}
    fqdn_domain_counts[unknown] = 0
    # Keeps track of aliases per domain
    fqdn_domain_aliases = {}
    fqdn_domain_aliases[unknown] = {unknown}

    for ip, count in ip_counts.items():
        fqdns = ip_to_fqdns.get(ip, None)

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
            fqdn_domain_counts[unknown] += 1

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
