"""
Defines the entry point for the application.
"""

from capturer import p0f_proxy, wireshark_proxy
from settings import get_setting
from sys import argv, exit

if __name__ == "__main__":

    # Initialize the capturer layer
    use_live_capture = get_setting('app', 'UseLiveCapture', 'bool')
    if use_live_capture:
        wireshark_proxy.init_live_capture()
        p0f_proxy.init_live_capture()
    else:
        ws_init_filepath = get_setting('wireshark', 'InitFileLocation')
        p0f_init_filepath = get_setting('p0f', 'InitFileLocation')
        wireshark_proxy.init_from_file(ws_init_filepath)
        print(wireshark_proxy.read_packets())
        p0f_proxy.init_from_file(p0f_init_filepath)

    # TODO: Start up visualizer

    print("Well, here you go.\nHope it gets interesting soon...\n")
    exit(0)
