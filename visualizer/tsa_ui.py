
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

ws_init_filepath = get_setting('app', 'InitFileLocation')
wireshark_proxy.init_from_file(ws_init_filepath)

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

    packets = wireshark_proxy.read_packets().get_packets()

    if dropdown_option == 'CNTRY':
        key_counts_dict = tsa_statistics.get_country_counts(packets)
        stat_type = 'Country'
    elif dropdown_option == 'FQDN':
        key_counts_dict = tsa_statistics.get_fqdn_counts(packets)
        stat_type = 'Domain Name'

    max_vals = []
    for key, count in key_counts_dict.items():
        if len(max_vals) < 10:
            max_vals.append(tuple([key, count]))
        else:
            if count > max_vals[-1][1]:
                max_vals[-1] = tuple([key, count])

        max_vals.sort(key=lambda tup: tup[1], reverse=True)


    labels = [item[0][0:40] for item in max_vals]
    values = [item[1] for item in max_vals]

    data = go.Pie(labels=labels, values=values, text=stat_type)

    layout = go.Layout(
        title='Number of Packets by {} (Top 10)'.format(stat_type),
        margin=go.Margin(l=40, r=0, t=40, b=30)
    )

    print (labels)
    print (values)

    return go.Figure(data=[data], layout=layout)


def start_tsa_ui():
    app.run_server(debug=True)

