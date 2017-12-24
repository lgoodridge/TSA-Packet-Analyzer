from capturer.tsa_packet import TSAPacket

class TSAStream:
    """
    Representation of a stream of TSAPackets.

    Contains helper methods for efficient querying and filtering
    of the packets.
    """

    def __init__(self, tsa_packets):
        self._packets = list(tsa_packets)

    def __len__(self):
        return len(self._packets)

    def __repr__(self):
        index_list = []
        str_list = []

        # Only include the first two and last two packets
        # in the string if the stream has > 4 packets
        length = len(self._packets)
        if length > 4:
            index_list = [0, 1, -1, length-2, length-1]
        else:
            index_list = list(range(length))

        for index in index_list:
            if index == -1:
                str_list.append("\n\t...\n\t")
            else:
                packet = self._packets[index]
                packet_split = (str(packet)).split("\n")
                new_header = "\tTSA Packet #%d: {\n\t" % index
                str_list.append(new_header + "\n\t".join(packet_split[1:]))

        return "TSA Stream: {\n%s\n}" % "\n".join(str_list)

    def get_packets(self, sort_key=None, include_missing=False):
        """
        Returns a list of TSAPackets in the stream.

        If sort_key is provided, the packets are sorted by their
        values for that key. Raises KeyError if the provided key
        is not a valid TSAPacket field.

        If include_missing is True, packets that are missing the
        field specified by sort_key are included in the returned
        list, at the end. Otherwise, they are omitted.
        """
        if sort_key:
            if sort_key not in TSAPacket.FIELDS:
                raise KeyError("Sort key '" + sort_key +
                        "' is not a valid TSAPacket field")
            sorted_packets = sorted(self._packets,
                    key=lambda x: (x[sort_key] is None, x[sort_key]))
            if not include_missing:
                sorted_packets = filter(lambda x: x[sort_key] is not None,
                        sorted_packets)
            return list(sorted_packets)
        else:
            return self._packets

    def get_values_for_key(self, key):
        """
        Returns a list of values for the provided key - one for
        each packet in the stream.

        Raises KeyError if the provided key is not a valid
        TSAPacket field.
        """
        if key not in TSAPacket.FIELDS:
            raise KeyError("Key '" + key + "' is not a valid TSAPacket field")
        return list(map(lambda x: x[key], self._packets))

    def filter(self, filter_dict):
        """
        Returns a TSAStream containing only packets whose values
        match those in the provided dict, for all keys in the dict.

        Raises KeyError if any of the keys in the dict is not
        a valid TSAPacket field.
        """
        filtered_list = self._packets
        for key, value in filter_dict.items():
            if key not in TSAPacket.FIELDS:
                raise KeyError("Key '" + key + "' is not a valid " +
                        " TSAPacket field")
            filtered_list = filter(lambda x: x[key] == value, filtered_list)
        return TSAStream(filtered_list)
