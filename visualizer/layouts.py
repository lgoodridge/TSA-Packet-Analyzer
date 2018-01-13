# Plotly and Dash modules
import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go
from . import tsa_ui

link_style = {'color':'#0000ff'}

def get_app_layout():
    return html.Div(children=[
        dcc.Location(id='url', refresh=False),

        html.Div(
            children=[
                html.H1(children='TSA App'),
                html.Div(children='''
                Powered by Dash: A web application framework for Python.
                ''')]
        ),

        html.Div(id='page-content')
    ])

def get_index_page():
    return html.Div([
        html.H1('Main'),
        dcc.Link('Search', href='/search', style=link_style),
        html.Br(),
        dcc.Link('Statistics', href='/statistics', style=link_style),
        html.Br(),
        dcc.Link('Metrics', href='/metrics', style=link_style),
        html.Br(),
        dcc.Link('Security', href='/security', style=link_style),
    ])


def get_search_page():
    return html.Div([
        html.H1('Search'),
        dcc.Link('Back to Main', href='/', style=link_style),
        html.Div([
            dcc.Input(id='input-domain-info-search', type='text', value='Domain Name'),
            html.Button(id='domain-info-button', n_clicks=0, children='Go')
        ])
    ])


def get_statistics_page():

    count_graph_with_radio = html.Div([
        dcc.Graph(id='statistics-packet-counts-graph'),
        dcc.RadioItems(id='statistics-packet-counts-radio',
                       options=[
                           {'label': 'Countries', 'value': 'CNTRY'},
                           {'label': 'Domain Names', 'value': 'FQDN'}
                       ],
                       value='CNTRY')
    ])

    trafic_graph_with_radio = html.Div([
        dcc.Graph(id='statistics-packet-traffic-graph'),
        dcc.RadioItems(id='statistics-packet-traffic-radio',
                       options=[
                           {'label': 'Countries', 'value': 'CNTRY'},
                           {'label': 'Domain Names', 'value': 'FQDN'}
                       ],
                       value='CNTRY')
    ])

    choropleth_map_with_button = html.Div([
        dcc.Graph(id='country-traffic-choropleth-map'),
        html.Button('Refresh', id='country-traffic-choropleth-map-refresh-button')
    ])

    return html.Div([
        html.H1('Statistics'),
        dcc.Link('Back to Main', href='/', style=link_style),
        html.Div([
            count_graph_with_radio,
            trafic_graph_with_radio,
            choropleth_map_with_button
        ])
    ])


def get_metrics_page():
    return html.Div([
        html.H1('Metrics'),
        dcc.Link('Back to Main', href='/', style=link_style),
    ])


def get_security_page():
    return html.Div([
        html.H1('Security'),
        dcc.Link('Back to Main', href='/', style=link_style),
    ])


def get_choropleth_map_figure():

    UNKNOWN = 'Unknown'

    country_traffic_tups = tsa_ui.get_curr_state().get("country_traffic", [])
    country_traffic_tups = [tup for tup in country_traffic_tups if tup[0] != UNKNOWN]

    locations = [tup[0] for tup in country_traffic_tups]
    locationmode = "country names"
    z = [tup[1] for tup in country_traffic_tups]

    colorscale = [[0, "rgb(5, 10, 172)"], [0.35, "rgb(40, 60, 190)"], [0.5, "rgb(70, 100, 245)"],
                  [0.6, "rgb(90, 120, 245)"], [0.7, "rgb(106, 137, 247)"], [1, "rgb(220, 220, 220)"]]
    autocolorscale = False
    reversescale = True

    marker = dict(
        line=dict(
            color='rgb(180,180,180)',
            width=0.5
        ))
    colorbar = dict(
        ticksuffix=' Bytes',
        title='Size of Traffic (bytes)')

    layout = dict(
        title='Map of Country Traffic',
        geo=dict(
            showframe=True,
            showcoastlines=True,
            showcountries=True,
            projection=dict(
                type='Mercator'
            )
        )
    )

    data = go.Choropleth(locations=locations, text=locations, colorscale=colorscale,
                         autocolorscale=autocolorscale, reversescale=reversescale,
                         marker=marker, colorbar=colorbar, z=z, locationmode=locationmode)

    return go.Figure(data=[data], layout=layout)

