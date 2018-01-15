"""
This module contains metrics related analysis functions
"""

def get_bandwidth(stream, buckets=50):
    """
    Calculates the bandwidth / traffic rate for the stream of packets
    from the lowest time stamp to the highest time stamp.

    Granularity is determined using buckets

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A list of tuples where the first member of each tuple is
        the time and the second member is the size of traffic at
        that time.
    """
    time_length_dicts = [dict(time=packet.timestamp, length=packet.length) for packet in stream]

    latest_time = max(time_length_dicts, key=lambda item:item['time'])['time']
    earliest_time = min(time_length_dicts, key=lambda item:item['time'])['time']

    total_traffic = sum([item['length'] for item in time_length_dicts])
    traffic_duration =  latest_time - earliest_time
    step = traffic_duration / buckets

    y = []
    x = []
    left_bound = earliest_time
    right_bound = left_bound + step

    sum_total = 0
    while left_bound < latest_time:
        total = 0
        for time_length in time_length_dicts:
            if time_length['time'] >= left_bound and time_length['time'] < right_bound:
                total += time_length['length']

            # Deal with corner case of last edge / bound
            if right_bound == latest_time and time_length['time'] == right_bound:
                total += time_length['length']


        y.append(total)
        sum_total += total
        x.append(left_bound + step/2)

        left_bound += step
        right_bound += step

    assert (sum_total == total_traffic)

    return list(zip(x, y))





