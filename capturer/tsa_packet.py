from capturer.utils import split_cdl
from datetime import datetime

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
        application_type: 'dns' | 'http' | 'none' (required)
        dns_query_resp: 'query' | 'response' (if DNS packet)
        dns_query_names:  List of URLs being queried (if DNS packet)
        dns_resp_ip: response ip address (if DNS response with answer)
        http_req_resp:  'request' | 'response' (if HTTP packet)
        http_method:  'GET' | 'PUT' | 'POST' | ... (if HTTP request)
        http_status:  response status code (if HTTP response)
    """

    FIELDS = ['timestamp', 'ip_version', 'src_addr', 'dst_addr', 'protocol',
              'src_port', 'dst_port', 'tcp_op', 'application_type',
              'dns_query_resp', 'dns_query_names', 'dns_resp_ip',
              'http_req_resp', 'http_method', 'http_status']

    REQUIRED_FIELDS = ['timestamp', 'ip_version', 'src_addr', 'dst_addr',
                       'protocol', 'src_port', 'dst_port', 'application_type']

    def __init__(self, init_data):
        """
        Initializes a TSAPacket from a python dictionary.

        Raises IncompleteInitDataException if any required fields are
        missing in the provided dictionary.
        """
        for field in TSAPacket.FIELDS:
            if field in init_data:
                self[field] = init_data[field]
            elif field in TSAPacket.REQUIRED_FIELDS:
                raise IncompleteInitDataException("Missing required " +
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

    @staticmethod
    def parse_pyshark_packet(packet):
        """
        Accepts a pyshark Packet object, and returns a TSAPacket
        created from it.

        Raises TSAPacketParseException if parsing fails.
        """
        if not packet.__dict__.get('layers'):
            raise TSAPacketParseException("Provided packet is not in " +
                    "expected pyshark packet format")
        if packet.captured_length != packet.length:
            raise TSAPacketParseException("Failed to capture entire packet")

        init_data = {}
        sniff_time_float = float(packet.sniff_timestamp)
        init_data['timestamp'] = datetime.fromtimestamp(sniff_time_float)

        # Extract network layer data
        if 'ip' in packet:
            init_data['ip_version'] = "ipv" + str(packet.ip.version)
            init_data['src_addr'] = packet.ip.src
            init_data['dst_addr'] = packet.ip.dst
        else:
            raise TSAPacketParseException("Packet missing required IP layer")

        # Extract transport layer data
        if 'tcp' in packet:
            init_data['protocol'] = "tcp"
            init_data['src_port'] = int(packet.tcp.srcport)
            init_data['dst_port'] = int(packet.tcp.dstport)

            is_syn = bool(int(packet.tcp.flags_syn))
            is_ack = bool(int(packet.tcp.flags_ack))
            if is_syn and is_ack:
                init_data['tcp_op'] = "SYN-ACK"
            elif is_syn:
                init_data['tcp_op'] = "SYN"
            elif is_ack:
                init_data['tcp_op'] = "ACK"
            else:
                raise TSAPacketParseException("TCP Packet was neither a SYN, " +
                        "ACK, nor SYN-ACK operation")

        elif 'udp' in packet:
            init_data['protocol'] = "udp"
            init_data['src_port'] = int(packet.udp.srcport)
            init_data['dst_port'] = int(packet.udp.dstport)

        else:
            raise TSAPacketParseException("Packet missing transport layer " +
                    "(TCP or UDP)")

        # Extract application layer data (if any)
        if 'dns' in packet:
            init_data['application_type'] = "dns"
            if 'qry_name' in packet.dns.field_names:
                init_data['dns_query_names'] = split_cdl(packet.dns.qry_name)
            else:
                raise TSAPacketParseException("DNS Packet missing query " +
                        "names field")
            if 'resp_name' in packet.dns.field_names:
                init_data['dns_query_resp'] = "response"
                if 'a' in packet.dns.field_names:
                    init_data['dns_resp_ip'] = packet.dns.a
                if 'aaaa' in packet.dns.field_names:
                    init_data['dns_resp_ip'] = packet.dns.aaaa
            else:
                init_data['dns_query_resp'] = "query"

        elif 'http' in packet:
            init_data['application_type'] = "http"
            if 'request_method' in packet.http.field_names:
                init_data['http_req_resp'] = "request"
                init_data['http_method'] = packet.http.request_method
            elif 'response_code' in packet.http.field_names:
                init_data['http_req_resp'] = "response"
                init_data["http_status"] = int(packet.http.response_code)
            else:
                raise TSAPacketParseException("HTTP Packet contained neither " +
                        "request nor response data")

        else:
            init_data['application_type'] = "none"

        return TSAPacket(init_data)


class IncompleteInitDataException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class TSAPacketParseException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
