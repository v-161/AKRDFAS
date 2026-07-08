from dash import html
import dash_bootstrap_components as dbc
import os
import json

BASE_DIR = os.getcwd()

EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")


def load_cases():

    cases = []

    if not os.path.exists(EVIDENCE_DIR):
        return cases

    for folder in sorted(os.listdir(EVIDENCE_DIR), reverse=True):

        case_path = os.path.join(EVIDENCE_DIR, folder)

        if not os.path.isdir(case_path):
            continue

        threat_file = os.path.join(
            case_path,
            "evidence",
            "threat_assessment.json"
        )

        level = "-"
        score = "-"

        if os.path.exists(threat_file):

            with open(threat_file) as f:

                threat = json.load(f)

                level = threat.get("threat_level", "-")
                score = threat.get("threat_score", "-")

        report_name = f"AKRDFAS_{folder}.html"

        cases.append(
            {
                "case": folder,
                "score": score,
                "level": level,
                "report_name": report_name
            }
        )

    return cases


def get_layout():

    rows = []

    for case in load_cases():

        rows.append(

            html.Tr(

                [

                    html.Td(case["case"]),

                    html.Td(case["score"]),

                    html.Td(case["level"]),

                    html.Td(

                        html.A(
                            "Open",
                            href=f"/generated_reports/{case['report_name']}",
                            target="_blank",
                            style={"color": "#00E5FF"}
                        )

                    )

                ]

            )

        )

    return dbc.Container(

        [

            html.H2(
                "Investigations",
                className="mb-4"
            ),

            dbc.Table(

                [

                    html.Thead(

                        html.Tr(

                            [

                                html.Th("Case ID"),

                                html.Th("Threat Score"),

                                html.Th("Threat Level"),

                                html.Th("Report")

                            ]

                        )

                    ),

                    html.Tbody(

                        rows if rows else [

                            html.Tr(

                                [

                                    html.Td(

                                        "No investigations found. Run a scan using main.py to generate an investigation.",

                                        colSpan=4,

                                        style={
                                            "textAlign": "center",
                                            "padding": "25px",
                                            "color": "#9CA3AF"
                                        }

                                    )

                                ]

                            )

                        ]

                    )

                ],

                bordered=True,
                hover=True,
                responsive=True

            )

        ],

        fluid=True

    )


layout = get_layout()
