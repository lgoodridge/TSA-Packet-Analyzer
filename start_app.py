"""
Defines the entry point for the application.
"""

from capturer import geoip_proxy, p0f_proxy, wireshark_proxy
from analyzer.country import get_country_to_packet_count
from analyzer.dns import get_fqdn_to_packet_count
from visualizer import tsa_ui

from settings import get_setting
from sys import argv, exit
from time import sleep
import threading

if __name__ == "__main__":
    # Initialize the capturer layer
    use_live_capture = get_setting('app', 'UseLiveCapture', 'bool')
    if use_live_capture:
        capture_interface = get_setting('app', 'CaptureInterface')
        wireshark_proxy.init_live_capture(capture_interface)
        p0f_proxy.init_live_capture(capture_interface)
        geoip_proxy.init_module()
        print("Capturing initial packets...")
        sleep(10)
        print("Done!")
    else:
        init_filepath = get_setting('app', 'InitFileLocation')
        wireshark_proxy.init_from_file(init_filepath)
        p0f_proxy.init_from_file(init_filepath)

    # Print out some capturer layer results
    print("Capturer layer initialized.")
    tsa_stream = wireshark_proxy.read_packets()
    tsa_packets = tsa_stream.get_packets()

    print("\nCaptured stream:")
    print(tsa_stream)

    print("\nCaptured security info:")
    if len(tsa_packets) > 1:
        print(p0f_proxy.get_security_info(tsa_packets[0].dst_addr))
        print(p0f_proxy.get_security_info(tsa_packets[-1].dst_addr))

    # TODO: Fix DNS response packets potentially not having dns.resp.a field

    # Test analyzer. Analyzer module Will be used by visualizer.
    country_counts = get_country_to_packet_count(tsa_packets)
    print("\n")
    for country, count in country_counts.items():
        print("Country: {}, Count: {}\n".format(country, count))

    fqdn_counts = get_fqdn_to_packet_count(tsa_packets)
    print("\n")
    for fqdn, count in fqdn_counts.items():
        print("Domain Name: {}, Count: {}\n".format(fqdn, count))

    # start ui
    tsa_ui.start_ui(live_capture=use_live_capture)

    # Perform clean up and exit the app
    print("All done. Perfoming cleanup...")
    wireshark_proxy.cleanup()
    p0f_proxy.cleanup()
    print("Cleanup finished. Exiting.")
    exit(0)
