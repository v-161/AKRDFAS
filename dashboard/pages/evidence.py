import os

from dash import html
import dash_bootstrap_components as dbc

from utils.loader import latest_case_dir


def get_layout():

    case = latest_case_dir()

    rows = []

    if case:

        evidence_dir = os.path.join(case, "evidence")

        if os.path.exists(evidence_dir):

            files = sorted(os.listdir(evidence_dir))

            for file in files:

                rows.append(

                    html.Tr(

                        [

                            html.Td(file),

                            html.Td(

                                html.A(

                                    dbc.Button(

                                        "Download",

                                        color="success",

                                        size="sm"

                                    ),

                                    href=f"/generated_evidence/{os.path.basename(case)}/evidence/{file}",

                                    target="_blank"

                                )

                            )

                        ]

                    )

                )

    return html.Div(

        [

            html.H2(
                "Evidence Files",
                className="mb-4"
            ),

            dbc.Table(

                [

                    html.Thead(

                        html.Tr(

                            [

                                html.Th("Evidence File"),

                                html.Th("Download")

                            ]

                        )

                    ),

                    html.Tbody(

                        rows if rows else [

                            html.Tr(

                                [

                                    html.Td(

                                        "No evidence found.",

                                        colSpan=2,

                                        style={
                                            "textAlign":"center",
                                            "color":"gray"
                                        }

                                    )

                                ]

                            )

                        ]

                    )

                ],

                hover=True,

                responsive=True,

                bordered=False,

                striped=True,

                style={

                    "backgroundColor":"#151A21",

                    "color":"white"

                }

            )

        ]

    )


layout = get_layout()
