import json
import analyzer_packet

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

        packet = analyzer_packet.PacketData(**kwargs)
        packets.append(packet)

    packets_file.close()

    return packets

# Test packets_from_JSON, asks for the file name to parse packets from and print out the first 20 packets parsed.
if __name__ == "__main__":
    file_name = input("Enter a FileName: ")
    packets = packets_from_JSON(file_name)

    for i in range(min(20, len(packets))):
        print packets[i]






