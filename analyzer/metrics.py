"""
This module contains metrics related analysis functions
"""

BANDWIDTH_DATA = "bandwidth"
TRAFFIC_VOLUME_DATA = "traffic volume"
AVERAGE_BANDWIDTH = "average bandwidth"

MICROSECONDS_IN_SECONDS = 1000000

def get_bandwidth_traffic_volume(stream, buckets=50):
    """
    Calculates the bandwidth and traffic rate for the stream of packets
    from the lowest time stamp to the highest time stamp.

    Granularity is determined using buckets

    Args:
        packets (list): List of TSAPacket objects

    Returns:
        A dictionary with these mappings:
            "bandwidth":
                 list of tuples. Each tuple is of the form (time, bandwidth)
            "traffic volume":
                 list of tuples. Each tuple is of the form (time, traffic volume)
            "average bandwidth":
                  average bandwidth
        Where time is a datetime object, bandwidth and average bandwidth are in
        bits per second, and traffic volume is in bytes
    """
    time_length_dicts = [dict(time=packet.timestamp, length=packet.length) for packet in stream]

    if len(time_length_dicts) == 0:
        return {BANDWIDTH_DATA: [], TRAFFIC_VOLUME_DATA: [], AVERAGE_BANDWIDTH: 0}

    total_traffic = sum([item['length'] for item in time_length_dicts])

    latest_time = max(time_length_dicts, key=lambda item:item['time'])['time']
    earliest_time = min(time_length_dicts, key=lambda item:item['time'])['time']
    traffic_duration =  latest_time - earliest_time
    step = traffic_duration / buckets
    step_in_seconds = (step.seconds) + (step.microseconds / MICROSECONDS_IN_SECONDS)

    y_traffic_volume = []
    y_bandwidth = []
    x = []

    left_bound = earliest_time
    right_bound = left_bound + step

    sum_total_of_traffic = 0
    sum_total_of_bandwidth = 0

    while left_bound < latest_time:
        sum_traffic = 0
        # sum data for all packets that fall in current windoes
        for time_length in time_length_dicts:
            if time_length['time'] >= left_bound and time_length['time'] < right_bound:
                sum_traffic += time_length['length']

            # Deal with corner case of last edge / bound
            if right_bound == latest_time and time_length['time'] == right_bound:
                sum_traffic += time_length['length']


        bandwidth = (sum_traffic * 8) / step_in_seconds

        sum_total_of_traffic += sum_traffic
        sum_total_of_bandwidth += bandwidth
        # time period at the center of this bound
        x.append(left_bound + step/2)
        # total traffic for this time period in bytes
        y_traffic_volume.append(sum_traffic)
        # bandwidth for this time period in bits per second
        y_bandwidth.append(bandwidth)

        left_bound += step
        right_bound += step

    assert (sum_total_of_traffic == total_traffic)
    assert (len(x) == len(y_bandwidth) == len(y_traffic_volume))

    traffic_points = list(zip(x, y_traffic_volume))
    bandwidth_points = list(zip(x, y_bandwidth))
    ave_bandwidth = sum_total_of_bandwidth / len(bandwidth_points)

    return {BANDWIDTH_DATA: bandwidth_points, TRAFFIC_VOLUME_DATA: traffic_points, AVERAGE_BANDWIDTH: ave_bandwidth}



