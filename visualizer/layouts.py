# Plotly and Dash modules
import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go
from . import tsa_ui
from . import styles

from analyzer.ip import PACKET_COUNT, TRAFFIC_SIZE, SECURITY_INFO, COUNTRY_NAMES
DOMAIN_NAME = "Top Level Domain Name"

OS_FULL_NAME = "os_full_name"
APP_FULL_NAME = "app_full_name"
SYSTEM_LANGUAGE = "language"
LINK_TYPE = "link_type"
NUM_HOPS = "num_hops"
UPTIME = "uptime" #estimated uptime of the system in minutes

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
        dcc.Link('Overview', href='/overview', style=styles.LINK),
        html.Br(),
        dcc.Link('Statistics', href='/statistics', style=styles.LINK),
        html.Br(),
        dcc.Link('Maps', href='/maps', style=styles.LINK),
        html.Br(),
        dcc.Link('Metrics', href='/metrics', style=styles.LINK),
        html.Br(),
        dcc.Link('Security', href='/security', style=styles.LINK),
    ])


def get_overview_page():

    overview_with_radio = html.Div([
        dcc.RadioItems(id='overview-table-radio',
                       options=[
                           {'label': 'General', 'value': 'GNRL'},
                           {'label': 'Security', 'value': 'SCRTY'}
                       ],
                       value='GNRL'),
        dcc.Graph(id='overview-table')
    ])

    return html.Div([
        html.H1('Overview'),
        dcc.Link('Back to Main', href='/', style=styles.LINK),
        overview_with_radio
    ])


def get_statistics_page():

    count_graph_with_radio = html.Div([
        dcc.RadioItems(id='statistics-packet-counts-radio',
                       options=[
                           {'label': 'Countries', 'value': 'CNTRY'},
                           {'label': 'Domain Names', 'value': 'FQDN'}
                       ],
                       value='CNTRY'),
        dcc.Graph(id='statistics-packet-counts-graph')
    ], style=styles.FLOAT_LEFT_HALF_WIDTH)

    trafic_graph_with_radio = html.Div([
        dcc.RadioItems(id='statistics-packet-traffic-radio',
                       options=[
                           {'label': 'Countries', 'value': 'CNTRY'},
                           {'label': 'Domain Names', 'value': 'FQDN'}
                       ],
                       value='CNTRY'),
        dcc.Graph(id='statistics-packet-traffic-graph'),
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

    country_traffic_tups = tsa_ui.get_curr_state().get(tsa_ui.COUNTRY_TRAFFIC, [])
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

def get_general_table_figure():
    header_names = [DOMAIN_NAME, TRAFFIC_SIZE, COUNTRY_NAMES, PACKET_COUNT]

    overview_info_tups = tsa_ui.get_curr_state().get(tsa_ui.TLDN_OVERALL_INFO, [])

    all_domain_names = []
    all_traffic_sizes = []
    all_country_names = []
    all_packet_counts = []

    for info_tup in overview_info_tups:
        temp_country_names = info_tup[1].get(COUNTRY_NAMES, [])
        names = ", ".join(set(temp_country_names))

        all_domain_names.append(info_tup[0])
        all_traffic_sizes.append(info_tup[1].get(TRAFFIC_SIZE, []))
        all_country_names.append(names)
        all_packet_counts.append(info_tup[1].get(PACKET_COUNT, []))

    cell_values = [all_domain_names, all_traffic_sizes, all_country_names, all_packet_counts]

    header = dict(values=header_names,
                    fill=dict(color='#C2D4FF'),
                    align="left")
    cells = dict(values=cell_values,
                   fill=dict(color='#F5F8FF'),
                   align="left")

    table_data = go.Table(
        header=header,
        cells=cells
    )

    return go.Figure(data=[table_data])

def get_security_table_figure():
    header_names = [DOMAIN_NAME, "OS Name", "HTTP Application Name",
                    "System Language", "Link Type", "Distance (Number of Packet Hops)",
                    "Estimated Up-Time (in minutes)"]

    overview_info_tups = tsa_ui.get_curr_state().get(tsa_ui.TLDN_OVERALL_INFO, [])

    all_domain_names = []
    all_os_names = []
    all_http_app_names = []
    all_system_languages = []
    all_link_types = []
    all_num_hops = []
    all_uptimes = []


    cell_values = [all_domain_names, all_os_names, all_http_app_names, all_system_languages,
                   all_link_types, all_num_hops, all_uptimes]
    security_info_keys = [OS_FULL_NAME, APP_FULL_NAME, SYSTEM_LANGUAGE, LINK_TYPE, NUM_HOPS, UPTIME]

    for info_tup in overview_info_tups:
        all_domain_names.append(info_tup[0])

        # get list of security dictionaries (or list of None) for this domain name
        security_info_list = info_tup[1].get(SECURITY_INFO, None)

        temp_security_info_dict = {}

        # for each security info dict in the list
        for info in security_info_list:
            # if there is a dict
            if info:
                # for type of security info in dict
                for key, value in info.items():
                    # if it value not none
                    if value:
                        if key in temp_security_info_dict:
                            temp_security_info_dict[key].add(value)
                        else:
                            temp_security_info_dict[key] = set([value])

        for idx in range(len(cell_values[1:])):
            key = security_info_keys[idx]
            if key in temp_security_info_dict:
                res = [str(item) for item in temp_security_info_dict.get(key)]
                cell_values[idx+1].append(", ".join(res))
            else:
                cell_values[idx+1].append("")


    header = dict(values=header_names,
                    fill=dict(color='#C2D4FF'),
                    align="left")
    cells = dict(values=cell_values,
                   fill=dict(color='#F5F8FF'),
                   align="left")

    table_data = go.Table(
        header=header,
        cells=cells
    )

    return go.Figure(data=[table_data])


class ChoroplethScopeException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)