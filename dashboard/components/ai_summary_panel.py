import os
import json

from dash import html, dcc
import dash_bootstrap_components as dbc


def load_ai_report():
    evidence_root = "evidence"

    if not os.path.exists(evidence_root):
        return None

    cases = sorted(os.listdir(evidence_root), reverse=True)

    for case in cases:
        report = os.path.join(
            evidence_root,
            case,
            "evidence",
            "ai_explanation.json"
        )

        if os.path.exists(report):
            with open(report, "r") as f:
                return json.load(f)

    return None


def get_layout():

    data = load_ai_report()

    if not data:
        return dbc.Card(
            dbc.CardBody(
                [
                    html.H4("🤖 AI Investigation Analyst"),
                    html.Hr(),
                    html.P("No AI investigation has been generated yet.")
                ]
            ),
            className="mt-4"
        )

    return dbc.Card(

        dbc.CardBody(

            [

                html.H4(
                    "🤖 AI Investigation Analyst",
                    className="text-info"
                ),

                html.Hr(),

                dcc.Markdown(
                    data.get("analysis", ""),
                    style={
                        "whiteSpace": "pre-wrap",
                        "fontSize": "15px",
                        "lineHeight": "1.8"
                    }
                )

            ]

        ),

        className="mt-4"

    )