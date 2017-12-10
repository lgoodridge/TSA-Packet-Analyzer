import pyshark

class TSA_Packet:
    """
    Condensed representation of a packet containing only the fields
    necessary for our analyzer.

    Packet fields are represented as attributes, and may be accessed
    directly (e.g. tsa_packet.src_addr). Some fields only appear
    in certain packets, and will have a value of None if it was not
    present.

    A TSA_Packet may either be initialized directly, with a dictionary
    containing the expected packet values, or via one of the defined
    parse methods.

    This class has the following attributes:
        timestamp:  time this packet was captured (required)
        ip_version:  'ipv4' | 'ipv6' (required)
        src_addr:  source IP address (required)
        dst_addr:  destination IP address (required)
        protocol:  'tcp' | 'udp' (required)
        src_port:  source TCP/UDP port (required)
        dst_port:  destination TCP/UDP port (required)
        tcp_op:  'SYN' | 'ACK' | 'SYN-ACK' (if TCP packet)
        application_type:  'arp' | 'dns' | 'http' | 'none' (required)
        arp_src_ip:  ARP source IP address (if ARP packet)
        arp_dst_ip:  ARP destination IP address (if ARP packet)
        dns_query_names:  List of URLs being queried (if DNS packet)
        http_req_resp:  'request' | 'response' (if HTTP packet)
        http_method:  'GET' | 'PUT' | 'POST' | ... (if HTTP request)
        http_status:  response status code (if HTTP response)
    """

    def __init__(self, init_data):
        raise NotImplementedError()

    def __repr__(self):
        raise NotImplementedError()

    @classmethod
    def parse_pyshark_packet(cls, pyshark_packet):
        """
        Accepts a pyshark Packet object, and returns a TSA_Packet
        created from it.
        Raises TSA_Packet_Parse_Exception if parsing fails.
        """
        raise NotImplementedError()


class TSA_Packet_Parse_Exception(Exception):
    def __init__(self, message, e):
        Exception.__init__(self, message, e)
