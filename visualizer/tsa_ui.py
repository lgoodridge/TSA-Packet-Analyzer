
# TSA libraries
from capturer import p0f_proxy, wireshark_proxy
from analyzer.country import get_country_to_packet_count, get_country_to_traffic_size
from analyzer.dns import get_tldn_to_packet_count, get_tldn_to_traffic_size, consolidate_fqdn_data
from settings import get_setting

# DASH ui libraries and plotly
import dash
import dash_core_components as dcc
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go


# Python builtin libraries
import threading
from time import sleep

# App layout
from . import layouts
from . import styles

# Global variables
state = {}

COUNTRY_COUNTS = "country_counts"
TLDN_COUNTS = "tldn_counts"
COUNTRY_TRAFFIC = "country_traffic"
TLDN_TRAFFIC = "tldn_traffic"
TLDN_OVERALL_INFO = "tldn_overall_info"

STATE_UPDATE_RATE = 5 # seconds

app = dash.Dash()
# suppress callback exceptions so that we can assign callbacks to
# components generated by other callbacks.
app.config['suppress_callback_exceptions']=True
app.layout = layouts.get_app_layout()


def start_ui(live_capture=False):
    if live_capture:
        # start up background thread to periodically update ui state.
        ui_state_thread = threading.Thread(target=updater)
        ui_state_thread.start()
    else:
        update_ui_state()

    app.run_server(debug=get_setting('app', 'EnableDebugMode'))

def updater():
    sleep(1)
    update_ui_state()

    # update state every UPDATE_RATE seconds
    while True:
        sleep(STATE_UPDATE_RATE)
        update_ui_state()

def update_ui_state():
    global state

    packets = wireshark_proxy.read_packets().get_packets()

    country_count_tups = list(get_country_to_packet_count(packets).items())
    country_traffic_tups = list(get_country_to_traffic_size(packets).items())
    tldn_count_tups = list(get_tldn_to_packet_count(packets).items())
    tldn_traffic_tups = list(get_tldn_to_traffic_size(packets).items())
    tldn_overall_info = list(consolidate_fqdn_data(packets).items())

    state[COUNTRY_COUNTS] = country_count_tups
    state[COUNTRY_TRAFFIC] = country_traffic_tups
    state[TLDN_COUNTS] = tldn_count_tups
    state[TLDN_TRAFFIC] = tldn_traffic_tups
    state[TLDN_OVERALL_INFO] = tldn_overall_info

def get_curr_state():
    return state


##########################
# Callbacks to update UI #
##########################

# Update packet count statistics graph.
@app.callback(Output('statistics-packet-counts-graph', 'figure'),
              [Input('statistics-packet-counts-radio', 'value')])
def update_count_statistics_graph(radio_option):
    size_disp = 15

    if radio_option == 'CNTRY':
        max_vals = state.get(COUNTRY_COUNTS, [])
        statistics_type = 'Country'
    elif radio_option == 'FQDN':
        max_vals = state.get(TLDN_COUNTS, [])
        statistics_type = 'Domain Name'

    max_vals.sort(key=lambda tup: tup[1], reverse=True)
    max_vals = max_vals[0:size_disp] if len(max_vals) > 10 else max_vals

    labels = [item[0][0:20] for item in max_vals]
    values = [item[1] for item in max_vals]

    data = go.Pie(labels=labels, values=values, text=statistics_type, hovertext=values)

    layout = go.Layout(
        title='Number of Packets by {} (Top {})'.format(statistics_type, size_disp),
        margin=go.Margin(l=40, r=0, t=40, b=30)
    )

    return go.Figure(data=[data], layout=layout)


# Update packet traffic statistics graph.
@app.callback(Output('statistics-packet-traffic-graph', 'figure'),
              [Input('statistics-packet-traffic-radio', 'value')])
def update_traffic_statistics_graph(radio_option):
    size_disp = 15

    if radio_option == 'CNTRY':
        max_vals = state.get(COUNTRY_TRAFFIC, [])
        statistics_type = 'Country'
    elif radio_option == 'FQDN':
        max_vals = state.get(TLDN_TRAFFIC, [])
        statistics_type = 'Domain Name'

    max_vals.sort(key=lambda tup: tup[1], reverse=True)
    max_vals = max_vals[0:size_disp] if len(max_vals) > 10 else max_vals

    labels = [item[0][0:20] for item in max_vals]
    values = [item[1] for item in max_vals]

    data = go.Pie(labels=labels, values=values, text=statistics_type, hovertext=values)

    layout = go.Layout(
        title='Size of Traffic by {} (Top {})'.format(statistics_type, size_disp),
        margin=go.Margin(l=40, r=0, t=40, b=30)
    )

    return go.Figure(data=[data], layout=layout)


# Update country traffic choropleth map
@app.callback(Output('country-traffic-choropleth-maps', 'children'),
              [Input('country-traffic-choropleth-maps-refresh-button', 'n_clicks')])
def update_country_traffic_statistics_map(n_clicks):

    map_graphs = []
    for idx, figure in enumerate(layouts.get_choropleth_map_figures()):
        id = "country-traffic-choropleth-figure-{}".format(idx)
        graph = dcc.Graph(id=id, figure=figure, style=styles.FLOAT_LEFT_HALF_WIDTH)
        map_graphs.append(graph)

    return map_graphs

# Update country traffic choropleth map
@app.callback(Output('overview-table', 'figure'),
              [Input('overview-table-radio', 'value')])
def update_overview_table(radio_option):

    figure = None
    if radio_option == 'GNRL':
        figure = layouts.get_general_table_figure()
    elif radio_option == 'SCRTY':
        figure = layouts.get_security_table_figure()

    return figure


# Update the page on url update
@app.callback(Output('page-content', 'children'),
              [Input('url', 'pathname')])
def update_page(pathname):
    if pathname == '/overview':
        return layouts.get_overview_page()
    elif pathname == '/statistics':
        return layouts.get_statistics_page()
    elif pathname == '/maps':
        return layouts.get_map_page()
    elif pathname == '/metrics':
        return layouts.get_metrics_page()
    elif pathname == '/security':
        return layouts.get_security_page()
    else:
        return layouts.get_index_page()

