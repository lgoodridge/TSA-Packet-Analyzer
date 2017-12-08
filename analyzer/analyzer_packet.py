import json

# Packet Data class, container for different packet information. For now only contains ip and tcp/udp information.
# very open to changing implementation of class.
class PacketData:
    NETWORK_LAYER_PROTOCOLS = ["ipv4", "ipv6"]
    TRANSPORT_LAYER_PROTOCOLS = ["tcp", "udp"]
    APPLICATION_LAYER_PROTOCOLS = ["dns", "http"]

    def __init__(self, **kwargs):

        # keep list of protocols implemented. Can access attributes based on whether the protocol is implemented
        self.protocols = []

        if "ipv4" in kwargs and "ipv6" in kwargs:
            raise Exception("Ipv4 and Ipv6 used.")

        if "ipv4" in kwargs:
            try:
                self.IPv4_dst_addr = kwargs["ipv4"]["dst_address"]
            except KeyError:
                raise Exception("No IPv4 destination address specified.")
            try:
                self.IPv4_src_addr = kwargs["ipv4"]["src_address"]
            except KeyError:
                raise Exception("No IPv4 source address specified.")
            self.protocols.append("ipv4")

        elif "ipv6" in kwargs:
            try:
                self.IPv6_dst_addr = kwargs["ipv6"]["dst_address"]
            except KeyError:
                raise Exception("No IPv6 destination address specified.")
            try:
                self.IPv6_src_addr = kwargs["ipv6"]["src_address"]
            except KeyError:
                raise Exception("No IPv6 source address specified.")
            self.protocols.append("ipv6")

        transport_protocols_args = [arg_name for arg_name in kwargs if arg_name in PacketData.TRANSPORT_LAYER_PROTOCOLS]
        if len(transport_protocols_args) > 1:
            raise Exception("Multiple Transport Layer Protocols used: {}.".format(", ".join(transport_protocols_args)))

        if "tcp" in kwargs:
            try:
                self.TCP_dst_port = kwargs["tcp"]["dst_port"]
            except KeyError:
                raise Exception("No TCP destination port specified.")
            try:
                self.TCP_src_port = kwargs["tcp"]["dst_port"]
            except KeyError:
                raise Exception("No TCP source port specified.")
            self.protocols.append("tcp")

        elif "udp" in kwargs:
            try:
                self.UDP_dst_port = kwargs["udp"]["dst_port"]
            except KeyError:
                raise Exception("No UDP destination port specified.")
            try:
                self.UDP_src_port = kwargs["udp"]["src_port"]
            except KeyError:
                raise Exception("No UDP source port specified.")
            self.protocols.append("dns")

    def __repr__(self):
        return "Attributes:\t{}".format(json.dumps(self.__dict__))