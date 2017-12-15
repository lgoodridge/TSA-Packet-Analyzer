from capturer.tsa_packet import TSAPacket

class TSAStream:
    """
    Representation of a stream of TSAPackets.

    Contains helper methods for efficient querying and filtering
    of the packets.
    """

    def __init__(self, tsa_packets):
        self.packets = tsa_packets

    def __repr__(self):
        raise NotImplementedError()

    def get_packets(sort_key = None):
        """
        Returns a list of TSAPackets in the stream.

        If sort_key is provided, the packets are sorted by their
        values for that key (with packets lacking the key placed
        last).
        """
        if sort_key:
            raise NotImplementedError
        return self.packets

    def get_values_for_key(key):
        """
        Returns a list of values for the provided key - one for
        each packet in the stream.
        """
        raise NotImplementedError

    def filter(filter_dict):
        """
        Returns a TSAStream containing only packets whose values
        match those in the provided dict, for all keys in the dict.
        """
        raise NotImplementedError
