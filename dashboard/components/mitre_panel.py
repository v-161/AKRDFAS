from dash import html
import dash_bootstrap_components as dbc

from utils.loader import load


def get_layout():

    mitre = load("mitre_mapping.json")

    techniques = mitre.get("techniques", [])

    if not techniques:

        return dbc.Card(

            [

                dbc.CardHeader(

                    "MITRE ATT&CK",

                    style={
                        "backgroundColor": "#10151B",
                        "color": "#00E5FF",
                        "fontWeight": "bold"
                    }

                ),

                dbc.CardBody(

                    html.Div(

                        "No ATT&CK techniques detected.",

                        style={"color": "#9CA3AF"}

                    )

                )

            ],

            style={"backgroundColor": "#151A21"}

        )

    badges = []

    for tech in techniques:

        badges.append(

            dbc.Badge(

                f"{tech['id']} - {tech['name']}",

                color="danger",

                className="me-2 mb-2",

                style={

                    "fontSize": "15px",

                    "padding": "10px"

                }

            )

        )

    return dbc.Card(

        [

            dbc.CardHeader(

                "MITRE ATT&CK",

                style={

                    "backgroundColor": "#10151B",

                    "color": "#00E5FF",

                    "fontWeight": "bold"

                }

            ),

            dbc.CardBody(

                badges

            )

        ],

        style={"backgroundColor": "#151A21"}

    )
