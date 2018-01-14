# Plotly and Dash modules
import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go
from . import tsa_ui
from . import styles

POSSIBLE_CHOROPLETH_SCOPES = ["world", "usa", "europe", "asia", "africa", "north america", "south america"]
UNKNOWN = 'Unknown'


def get_app_layout():
    return html.Div(children=[
        dcc.Location(id='url', refresh=False),

        html.Div(
            children=[
                html.H1(children='TSA App'),
                html.Div(children='''Powered by Dash: A web application framework for Python.''')]
        ),

        html.Div(id='page-content')
    ])

def get_index_page():
    return html.Div([
        dcc.Link('Search', href='/search', style=styles.LINK),
        html.Br(),
        dcc.Link('Statistics', href='/statistics', style=styles.LINK),
        html.Br(),
        dcc.Link('Maps', href='/maps', style=styles.LINK),
        html.Br(),
        dcc.Link('Metrics', href='/metrics', style=styles.LINK),
        html.Br(),
        dcc.Link('Security', href='/security', style=styles.LINK),
    ])


def get_search_page():
    return html.Div([
        html.H1('Search'),
        dcc.Link('Back to Main', href='/', style=styles.LINK),
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
    ], style=styles.FLOAT_LEFT_HALF_WIDTH)

    trafic_graph_with_radio = html.Div([
        dcc.Graph(id='statistics-packet-traffic-graph'),
        dcc.RadioItems(id='statistics-packet-traffic-radio',
                       options=[
                           {'label': 'Countries', 'value': 'CNTRY'},
                           {'label': 'Domain Names', 'value': 'FQDN'}
                       ],
                       value='CNTRY')
    ], style=styles.FLOAT_LEFT_HALF_WIDTH)

    return html.Div([
        html.H1('Statistics'),
        dcc.Link('Back to Main', href='/', style=styles.LINK),
        html.Div([
            count_graph_with_radio,
            trafic_graph_with_radio,
        ])
    ])


def get_metrics_page():
    return html.Div([
        html.H1('Metrics'),
        dcc.Link('Back to Main', href='/', style=styles.LINK),
    ])


def get_security_page():
    return html.Div([
        html.H1('Security'),
        dcc.Link('Back to Main', href='/', style=styles.LINK),
    ])

def get_map_page():

    choropleth_map_with_button = html.Div([
        html.Button('Refresh', id='country-traffic-choropleth-maps-refresh-button'),
        html.Div(id='country-traffic-choropleth-maps')
    ])

    return html.Div([
        html.H1('Maps'),
        dcc.Link('Back to Main', href='/', style=styles.LINK),
        html.Div(choropleth_map_with_button),
    ])

# Get a choropleth map figures based on current state
def get_choropleth_map_figures():

    country_traffic_tups = tsa_ui.get_curr_state().get("country_traffic", [])
    country_traffic_tups = [tup for tup in country_traffic_tups if tup[0] != UNKNOWN]

    locations = [tup[0] for tup in country_traffic_tups]
    locationmode = "country names"
    z = [tup[1] for tup in country_traffic_tups]

    desired_scopes = ['world', 'north america', 'europe', 'asia', 'africa', 'south america']

    map_figures = []
    for scope in desired_scopes:
        args = [locations, z, locationmode, scope]
        map_figures.append(get_choropleth_map_figure(*args))

    return map_figures

# Get a choropleth map trace based on current state. Can specify a scope for the map.
# The scope must be one of:
# "world" | "usa" | "europe" | "asia" | "africa" | "north america" | "south america"
def get_choropleth_map_figure(locations, z, locationmode, scope="world"):
    scope = scope.lower()

    if scope not in POSSIBLE_CHOROPLETH_SCOPES:
        message = '"{}" is not a valid scope. Scope must be one of: {}'.format(scope, ", ".join(POSSIBLE_CHOROPLETH_SCOPES))
        raise ChoroplethScopeException(message)


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
        title='Map of Country Traffic. Region: {}'.format(scope.capitalize()),
        geo=dict(
            scope=scope,
            showframe=False,
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


class ChoroplethScopeException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)