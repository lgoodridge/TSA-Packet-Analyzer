"""
This module contains security related analysis functions
"""

ATTACK_BASE_THRESHOLD = 1000
ATTACK_MULT_THRESHOLD = 5

def get_syn_flood_attackers(stream):
    """
    Returns a list of tuples containing the IP addresses of
    suspected SYN flood perpretators, and the reason why
    they were suspected.
    """
    # Get a dictionary relating all seen source IP addresses
    # to the number of TCP SYN and ACK packets they've sent
    ip_to_syn_ack = {}
    for packet in stream:
        if packet.protocol == 'tcp':
            src_addr = packet.src_addr
            (syn, ack) = ip_to_syn_ack.get(src_addr, (0, 0))
            if packet.tcp_op == 'SYN':
                ip_to_syn_ack[src_addr] = (syn+1, ack)
            elif packet.tcp_op == 'ACK':
                ip_to_syn_ack[src_addr] = (syn, ack+1)

    # Find hosts that have sent much more SYNs than ACKs
    syn_flood_attackers = []
    for addr, (syn, ack) in ip_to_syn_ack.items():
        if syn > ATTACK_THRESHOLD and syn > ack * ATTACK_MULT_THRESHOLD:
            syn_flood_attackers.append((addr,
                "Host has sent much more SYNs than ACKs"))

    return syn_flood_attackers

def get_ddos_victims(stream):
    """
    Returns a list of tuples containing the IP addresses of
    suspected DDoS victims, and the reason why they were
    suspected.
    """
    # Get a dictionary relating all seen source IP addresses to
    # the number of TCP SYN-ACK and ACK packets they've sent
    ip_to_synack_ack = {}
    for packet in stream:
        if packet.protocol == 'tcp':
            src_addr = packet.src_addr
            (synack, ack) = ip_to_synack_ack.get(src_addr, (0, 0))
            if packet.tcp_op == 'SYN-ACK':
                ip_to_synack_ack[src_addr] = (synack+1, ack)
            elif packet.tcp_op == 'ACK':
                ip_to_synack_ack[src_addr] = (synack, ack+1)

    # Find hosts that have sent much more SYN-ACKs than ACKs
    ddos_victims = []
    for addr, (synack, ack) in ip_to_synack_ack.items():
        if synack > ATTACK_THRESHOLD and synack > ack * ATTACK_MULT_THRESHOLD:
            ddos_victims.append((addr,
                "Host has sent much more SYN-ACKs than ACKs"))

    return ddos_victims

def get_reflection_victims(stream):
    """
    Returns a list of tuples containing the IP addresses of
    suspected reflection attack victims, and the reason why
    they were suspected.
    """
    # Get a dictionary relating all seen IP addrresses to
    # the number of DNS queries they've sent and number of
    # DNS responses they've received
    ip_to_dns_query_resp = {}
    for packet in stream:
        if packet.application_type == 'dns':
            if packet.dns_query_resp == 'query':
                src_addr = packet.src_addr
                (query, resp) = ip_to_dns_query_resp.get(src_addr, (0, 0))
                ip_to_dns_query_resp[src_addr] = (query+1, resp)
            else:
                dst_addr = packet.dst_addr
                (query, resp) = ip_to_dns_query_resp.get(dst_addr, (0, 0))
                ip_to_dns_query_resp[dst_addr] = (query, resp+1)

    # Find hosts that received much DNS responses than sent DNS queries
    reflection_victims = []
    for addr, (query, resp) in ip_to_dns_query_resp.items():
        if resp > ATTACK_THRESHOLD and resp > query * ATTACK_MULT_THRESHOLD:
            reflection_victims.append((addr,
                "Host has received much DNS responses than queried for"))

    return reflection_victims
