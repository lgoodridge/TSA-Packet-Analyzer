"""
JSON implementation of the TSA Packet and wireshark parser
modules. Left here because some of this code can probably
be reused in the current implementation.
"""

import json

# Packet Data class, container for different packet information. For now only contains ip and tcp/udp information.
# very open to changing implementation of class.
class WiresharkPacket:
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

        transport_protocols_args = [arg_name for arg_name in kwargs if arg_name in WiresharkPacket.TRANSPORT_LAYER_PROTOCOLS]
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


# Extract packets wireshark json dump. Return an array of packet objects.
def packets_from_JSON(filename):
    try:
        packets_file = open(filename, "r")
    except IOError as e:
        raise e

    packet_dict_list = json.load(packets_file)

    # Extract data from json dump to construct packet objects. For now we only extract.
    packets = []
    for packet_dict in packet_dict_list:
        layers = packet_dict["_source"]["layers"]
        kwargs = {}
        if "ip" in layers:
            kwargs["ipv4"] = dict(dst_address=layers["ip"]["ip.dst_host"], src_address=layers["ip"]["ip.src_host"])
        elif "ipv6" in layers:
            kwargs["ipv6"] = dict(dst_address=layers["ipv6"]["ipv6.dst_host"], src_address=layers["ipv6"]["ipv6.src_host"])

        if "tcp" in layers:
            kwargs["tcp"] = dict(dst_port=layers["tcp"]["tcp.dstport"], src_port=layers["tcp"]["tcp.srcport"])
        elif "udp" in layers:
            kwargs["udp"] = dict(dst_port=layers["udp"]["udp.dstport"], src_port=layers["udp"]["udp.srcport"])

        packet = WiresharkPacket(**kwargs)
        packets.append(packet)

    packets_file.close()

    return packets


# Test packets_from_JSON, asks for the file name to parse packets from and print out the first 20 packets parsed.
if __name__ == "__main__":
    file_name = input("Enter a FileName: ")
    packets = packets_from_JSON(file_name)

    for i in range(min(20, len(packets))):
        print(packets[i])
