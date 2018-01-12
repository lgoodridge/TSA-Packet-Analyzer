"""
Defines the entry point for the application.
"""

from capturer import p0f_proxy, wireshark_proxy
from analyzer import tsa_statistics
from visualizer import tsa_ui
from settings import get_setting
from sys import argv, exit

if __name__ == "__main__":

    # # Initialize the capturer layer
    # use_live_capture = get_setting('app', 'UseLiveCapture', 'bool')
    # if use_live_capture:
    #     wireshark_proxy.init_live_capture()
    #     p0f_proxy.init_live_capture()
    # else:
    #     ws_init_filepath = get_setting('app', 'InitFileLocation')
    #     p0f_init_filepath = get_setting('app', 'InitFileLocation')
    #     wireshark_proxy.init_from_file(ws_init_filepath)
    #     print(wireshark_proxy.read_packets())
    #     # p0f_proxy.init_from_file(p0f_init_filepath)
    #
    # # Test analyzer. Analyzer module Will be used by visualizer.
    # country_counts = tsa_statistics.get_country_counts(wireshark_proxy.read_packets().get_packets())
    # print("\n")
    # for country, count in country_counts.items():
    #     print("Country: {}, Count: {}\n".format(country, count))
    #
    # fqdn_counts = tsa_statistics.get_fqdn_counts(wireshark_proxy.read_packets().get_packets())
    # print("\n")
    # for fqdn, count in fqdn_counts.items():
    #     print("Domain Name: {}, Count: {}\n".format(fqdn, count))

    # TODO: Start up visualizer
    tsa_ui.start_tsa_ui()

    print("Well, here you go.\nHope it gets interesting soon...\n")
    exit(0)
