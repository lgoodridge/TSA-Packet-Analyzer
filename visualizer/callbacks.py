from .tsa_ui import app
from .tsa_ui import state

from dash.dependencies import Input, Output, State


@app.callback(Output('statistics-graph', 'figure'),
              [Input('statistics-dropdown', 'value')])
def update_output(dropdown_option):

    if dropdown_option == 'CNTRY':
        max_vals = state.get("country_counts", [])
        stat_type = 'Country'
    elif dropdown_option == 'FQDN':
        max_vals = state.get("fqdn_counts", [])
        stat_type = 'Domain Name'

    max_vals.sort(key=lambda tup: tup[1], reverse=True)
    max_vals = max_vals[0:15] if len(max_vals) > 10 else max_vals

    labels = [item[0][0:40] for item in max_vals]
    values = [item[1] for item in max_vals]

    data = go.Pie(labels=labels, values=values, text=stat_type)

    layout = go.Layout(
        title='Number of Packets by {} (Top 10)'.format(stat_type),
        margin=go.Margin(l=40, r=0, t=40, b=30)
    )

    return go.Figure(data=[data], layout=layout)