from dash import html
import dash_bootstrap_components as dbc

from utils.loader import load

def get_layout():

    threat = load("threat_assessment.json")

    reasons = threat.get("reasons", [])

    if not reasons:

        reasons = ["No suspicious findings detected."]

    items = []

    for reason in reasons:

        items.append(

            dbc.ListGroupItem(

                "⚠ " + reason,

                style={
                    "backgroundColor":"#151A21",
                    "color":"white",
                    "border":"1px solid #252B36"
                }

            )

        )

    return dbc.Card(

        [

            dbc.CardHeader(

                "Latest Findings",

                style={
                    "backgroundColor":"#10151B",
                    "color":"#00E5FF",
                    "fontWeight":"bold"
                }

            ),

            dbc.ListGroup(

                items,

                flush=True

            )

        ],

        style={

            "backgroundColor":"#151A21",

            "marginTop":"30px"

        }

    )
