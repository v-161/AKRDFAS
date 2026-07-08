from dash import html
import dash_bootstrap_components as dbc

from utils.loader import latest_case_dir

import os


def get_layout():

    case = latest_case_dir()

    if case:

        case_id = os.path.basename(case)

    else:

        case_id = "No Investigation"

    return dbc.Card(

        dbc.CardBody(

            [

                html.H5(
                    "Current Investigation",
                    className="mb-3"
                ),

                html.P([
                    html.B("Case ID: "),
                    case_id
                ]),

                html.P([
                    html.B("Evidence Folder: "),
                    "Available" if case else "Not Found"
                ]),

                html.P([
                    html.B("Reports: "),
                    "Generated"
                ])

            ]

        ),

        style={
            "backgroundColor": "#151A21",
            "border": "1px solid #252B36",
            "borderRadius": "12px"
        }

    )
