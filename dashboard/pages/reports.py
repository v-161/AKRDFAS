import os

from dash import html
import dash_bootstrap_components as dbc

REPORT_DIR = os.path.join(
    os.getcwd(),
    "reports",
    "generated"
)


def get_layout():

    rows = []

    if os.path.exists(REPORT_DIR):

        reports = sorted(
            os.listdir(REPORT_DIR),
            reverse=True
        )

        for report in reports:

            # Changed this block - now only PDF files are processed
            if not report.endswith(".pdf"):
                continue

            report_type = "PDF"  # Since we only process PDF files now

            rows.append(

                html.Tr(

                    [

                        html.Td(report),

                        html.Td(report_type),

                        html.Td(

                            html.A(  # Changed this block

                                dbc.Button(

                                    "Open PDF",

                                    color="info",

                                    size="sm"

                                ),

                                href=f"/generated_reports/{report}",

                                target="_blank"

                            )

                        )

                    ]

                )

            )

    return html.Div(

        [

            html.H2(
                "Generated Reports",
                className="mb-4"
            ),

            dbc.Table(

                [

                    html.Thead(

                        html.Tr(

                            [

                                html.Th("Report"),

                                html.Th("Type"),

                                html.Th("Action")

                            ]

                        )

                    ),

                    html.Tbody(

                        rows if rows else [

                            html.Tr(

                                [

                                    html.Td(

                                        "No reports generated yet.",

                                        colSpan=3,

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

                bordered=False,
                hover=True,
                responsive=True,
                striped=True,

                style={
                    "backgroundColor":"#151A21",
                    "color":"white"
                }

            )

        ]

    )


layout = get_layout()
