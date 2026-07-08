from dash import html
import dash_bootstrap_components as dbc

from utils.loader import load

card_style = {
    "backgroundColor": "#151A21",
    "border": "1px solid #252B36",
    "borderRadius": "12px",
    "padding": "20px",
    "boxShadow": "0px 0px 12px rgba(0,229,255,0.08)"
}


def get_layout():

    threat = load("threat_assessment.json")

    score = threat.get("threat_score", 0)
    level = threat.get("threat_level", "UNKNOWN")

    reasons = threat.get("reasons", [])
    recommendations = threat.get("recommendations", [])

    return dbc.Card(

        dbc.CardBody(

            [

                html.H3(
                    "Threat Summary",
                    className="mb-3"
                ),

                html.H4(
                    f"Threat Score : {score}/100",
                    style={
                        "color": "#FFC107"
                    }
                ),

                html.H5(
                    f"Threat Level : {level}",
                    style={
                        "color": "#FF5252"
                    }
                ),

                html.Hr(),

                html.H5("Why was this score assigned?"),

                html.Ul(

                    [

                        html.Li(reason)

                        for reason in reasons

                    ]

                    if reasons else

                    [

                        html.Li(
                            "No suspicious activity detected."
                        )

                    ]

                ),

                html.Hr(),

                html.H5("Recommended Action"),

                html.Ul(

                    [

                        html.Li(item)

                        for item in recommendations

                    ]

                )

            ]

        ),

        style=card_style

    )
