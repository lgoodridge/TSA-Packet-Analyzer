
# TSA libraries
from capturer import p0f_proxy, wireshark_proxy
from analyzer import tsa_statistics
from settings import get_setting

# DASH ui libraries and plotly
import dash
import plotly.graph_objs as go

# Python builtin libraries
import threading
from time import sleep

# App layout
from . import layout

# Global variables
state = {}

app = dash.Dash()

app.layout = layout.get_app_layout()


def start_ui(live_capture=False):
    if live_capture:
        # start up background thread to periodically update ui state.
        ui_state_thread = threading.Thread(target=updater)
        ui_state_thread.start()
    else:
        update_ui_state()

    app.run_server(debug=True)

def updater():
    # update state every 5 seconds
    while True:
        sleep(5)
        update_ui_state()

def update_ui_state():
    global state

    packets = wireshark_proxy.read_packets().get_packets()

    country_count_tups = [tuple([key, count]) for key, count in
                          tsa_statistics.get_country_counts(packets).items()]
    fqdn_count_tups = [tuple([key, count]) for key, count in
                       tsa_statistics.get_fqdn_counts(packets).items()]

    state["country_counts"] = country_count_tups
    state["fqdn_counts"] = fqdn_count_tups


