import pyshark

class TSAPacket(dict):
    """
    Condensed representation of a packet containing only the fields
    necessary for our analyzer.

    This class subclasses dict, and thus any operators on dictionaries
    will also work on a TSAPacket. Packet fields may be accessed
    through dictionary syntax (e.g. tsa_packet['src_addr']), or with
    dot syntax (e.g. tsa_packet.src_addr). Some fields only appear in
    certain packets, and will have a value of None if it was not present.

    A TSAPacket may either be initialized directly, with a dictionary
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

    FIELDS = ['timestamp', 'ip_version', 'src_addr', 'dst_addr', 'protocol',
              'src_port', 'dst_port', 'tcp_op', 'application_type',
              'arp_src_ip', 'arp_dst_ip', 'dns_query_names', 'http_req_resp',
              'http_method', 'http_status']

    REQUIRED_FIELDS = ['timestamp', 'ip_version', 'src_addr', 'dst_addr',
                       'protocol', 'src_port', 'dstport', 'application_type']

    def __init__(self, init_data):
        for field in TSAPacket.FIELDS:
            if field in init_data:
                self[field] = init_data[field]
            elif field in TSAPacket.REQUIRED_FIELDS:
                raise IncompleteInitDataException("Missing required" +
                        "field: %s." % field)
            else:
                self[field] = None

    def __repr__(self):
        field_list = []
        for field in TSAPacket.FIELDS:
            field_value = self[field]
            if field_value:
                field_list.append("\t%s: %s" % (field, self[field]))
        return "TSA Packet: {\n%s\n}" % "\n".join(field_list)

    ### METHODS TO ALLOW OBJECT DOT SYNTAX ###

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in TSAPacket.REQUIRED_FIELDS:
            raise AttributeError("Attempted to delete required field: " + name)
        elif name in TSAPacket.FIELDS:
            self[name] = None
        elif name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    ### PARSING METHODS ###

    @classmethod
    def parse_pyshark_packet(cls, pyshark_packet):
        """
        Accepts a pyshark Packet object, and returns a TSAPacket
        created from it.

        Raises TSAPacketParseException if parsing fails.
        """
        raise NotImplementedError()


class IncompleteInitDataException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class TSAPacketParseException(Exception):
    def __init__(self, message, e):
        Exception.__init__(self, message, e)
