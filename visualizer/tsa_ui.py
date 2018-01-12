
# TSA libraries
from capturer import p0f_proxy, wireshark_proxy
from analyzer import tsa_statistics
from settings import get_setting

# DASH ui libraries and plotly
import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
import plotly.graph_objs as go

# Python builtin libraries
import threading
from time import sleep

# Global variables
state = {}

app = dash.Dash()

app.layout = html.Div(children=[
    html.H1(children='TSA Statistics'),

    html.Div(children='''
        Powered by Dash: A web application framework for Python.
    '''),

    dcc.Graph(
        id='example-graph'
    ),

    html.Label('Statistics'),
    dcc.Dropdown(id='statistics-dropdown',
        options=[
            {'label': 'Countries', 'value': 'CNTRY'},
            {'label': 'Domain Names', 'value': 'FQDN'}
        ],
        value='CNTRY'
    )
])

@app.callback(Output('example-graph', 'figure'),
              [Input('statistics-dropdown', 'value')])
def update_output(dropdown_option):

    if dropdown_option == 'CNTRY':
        max_vals = state["country_counts"]
        stat_type = 'Country'
    elif dropdown_option == 'FQDN':
        max_vals = state["fqdn_counts"]
        stat_type = 'Domain Name'

    labels = [item[0][0:40] for item in max_vals]
    values = [item[1] for item in max_vals]

    data = go.Pie(labels=labels, values=values, text=stat_type)

    layout = go.Layout(
        title='Number of Packets by {} (Top 10)'.format(stat_type),
        margin=go.Margin(l=40, r=0, t=40, b=30)
    )

    return go.Figure(data=[data], layout=layout)


def start_ui(live_capture=False):
    if live_capture:
        # start up background thread to periodically update ui state.
        ui_state_thread = threading.Thread(target=updater)
        ui_state_thread.start()
    else:
        update_ui_state()

    app.run_server(debug=True)

def updater():
    # update state every 10 seconds
    while True:
        sleep(30)
        update_ui_state()

def update_ui_state():
    global state

    packets = wireshark_proxy.read_packets().get_packets()

    country_count_tups = [tuple([key, count]) for key, count in
                          tsa_statistics.get_country_counts(packets).items()]
    fqdn_count_tups = [tuple([key, count]) for key, count in
                       tsa_statistics.get_fqdn_counts(packets).items]

    state["country_counts"] = country_count_tups
    state["fqdn_counts"] = fqdn_count_tups


