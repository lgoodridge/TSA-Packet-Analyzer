import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go


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
    return html.Div([
        html.H1('Statistics'),
        dcc.Link('Back to Main', href='/', style=link_style),
        _get_choropleth_map(),
        dcc.Graph(id='statistics-graph'),
        html.Label('Statistics'),
        dcc.Dropdown(id='statistics-dropdown',
                     options=[
                         {'label': 'Countries', 'value': 'CNTRY'},
                         {'label': 'Domain Names', 'value': 'FQDN'}
                     ],
                     value='CNTRY')
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


def _get_choropleth_map():
    locations = ['NGA', 'USA', 'GBR']
    text = ['Nigeria', 'United States', 'United Kingdom']
    z = [10, 5, 2]

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
        tickprefix='$$',
        title='GDP<br>Billions US$')

    layout = dict(
        title='Choropleth Test',
        geo=dict(
            showframe=True,
            showcoastlines=True,
            projection=dict(
                type='Mercator'
            )
        )
    )

    data = go.Choropleth(locations=locations, text=text, colorscale=colorscale,
                         autocolorscale=autocolorscale, reversescale=reversescale,
                         marker=marker, colorbar=colorbar, z=z)

    figure = go.Figure(data=[data], layout=layout)

    return dcc.Graph(id='test-choropleth-map', figure=figure)