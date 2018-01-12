"""
Defines the entry point for the application.
"""

from capturer import p0f_proxy, wireshark_proxy
from analyzer import tsa_statistics
from settings import get_setting
from sys import argv, exit
from time import sleep

if __name__ == "__main__":

    # Initialize the capturer layer
    use_live_capture = get_setting('app', 'UseLiveCapture', 'bool')
    if use_live_capture:
        capture_interface = get_setting('app', 'CaptureInterface')
        wireshark_proxy.init_live_capture(capture_interface)
        # p0f_proxy.init_live_capture()
        print("Capturing initial packets...")
        sleep(10)
        print("Done!")
    else:
        init_filepath = get_setting('app', 'InitFileLocation')
        wireshark_proxy.init_from_file(init_filepath)
        p0f_proxy.init_from_file(init_filepath)

    print("Capturer layer initialized.")
    print(wireshark_proxy.read_packets())

    # Test analyzer. Analyzer module Will be used by visualizer.
    country_counts = tsa_statistics.get_country_counts(wireshark_proxy.read_packets().get_packets())
    print("\n")
    for country, count in country_counts.items():
        print("Country: {}, Count: {}\n".format(country, count))

    fqdn_counts = tsa_statistics.get_fqdn_counts(wireshark_proxy.read_packets().get_packets())
    print("\n")
    for fqdn, count in fqdn_counts.items():
        print("Domain Name: {}, Count: {}\n".format(fqdn, count))

    # TODO: Start up visualizer

    print("Finished!")
    exit(0)
