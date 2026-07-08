from dash import html, dcc  # Updated import
import dash_bootstrap_components as dbc
from utils.loader import load
from components.latest_findings import get_layout as latest_findings
from components.mitre_panel import get_layout as mitre_panel
from components.threat_summary import get_layout as threat_summary
from components.case_details_panel import get_layout as case_details_panel
from components.charts import get_layout as charts_panel


def get_dashboard_data():

    return {

        "threat": load("threat_assessment.json"),

        "hidden_modules": load("hidden_modules.json"),

        "hidden_processes": load("hidden_processes.json"),

        "hooks": load("kernel_hooks.json"),

        "mitre": load("mitre_mapping.json"),

        "ioc": load("ioc_matches.json"),

        "correlation": load("correlation_findings.json")

    }


card_style = {
    "backgroundColor": "#151A21",
    "border": "1px solid #252B36",
    "borderRadius": "12px",
    "padding": "20px",
    "textAlign": "center",
    "height": "140px",
    "boxShadow": "0px 0px 12px rgba(0,229,255,0.08)"
}


def make_card(title, value, color="#00E5FF"):

    return dbc.Card(

        dbc.CardBody(

            [

                html.H5(
                    title,
                    style={"color": "#9CA3AF"}
                ),

                html.H2(
                    value,
                    style={
                        "color": color,
                        "fontWeight": "bold"
                    }
                )

            ]

        ),

        style=card_style

    )


def get_layout():
    data = get_dashboard_data()

    threat = data["threat"]

    hidden_modules = data["hidden_modules"]

    hidden_processes = data["hidden_processes"]

    hooks = data["hooks"]

    mitre = data["mitre"]

    ioc = data["ioc"]

    correlation = data["correlation"]

    # --------------------------
    # Fix Kernel Hooks Count
    # --------------------------
    kernel_hooks = threat.get(
        "summary",
        {}
    ).get(
        "kernel_hooks",
        0
    )

    # --------------------------
    # Fix MITRE Count
    # --------------------------
    mitre_count = mitre.get(
        "summary",
        {}
    ).get(
        "techniques_detected",
        0
    )

    # --------------------------
    # Fix Correlation Score
    # --------------------------
    correlation_score = threat.get(
        "summary",
        {}
    ).get(
        "correlation_score",
        0
    )

    return html.Div(

        [

            # --------------------------
            # START INVESTIGATION BUTTON
            # --------------------------
            dbc.Row(

                [

                    dbc.Col(

                        dbc.Button(

                            "▶ Start Investigation",

                            id="start-scan",

                            color="danger",

                            size="lg",

                            className="mb-4",

                            style={

                                "width": "280px",

                                "fontWeight": "bold"

                            }

                        ),

                        width="auto"

                    ),

                    dbc.Col(

                        html.Div(

                            id="scan-status",

                            children="Ready.",

                            style={

                                "color":"#00FF9D",

                                "paddingTop":"12px",

                                "fontWeight":"bold"

                            }

                        )

                    ),

                    dcc.Interval(
                        id="scan-check",
                        interval=2000,
                        disabled=True
                    ),
                    dcc.Location(
                        id="page-refresh",
                        refresh=True
                    ),

                ],

                className="mb-4"

            ),

            # --------------------------
            # DASHBOARD CARDS
            # --------------------------

            # Cards row 1
            dbc.Row(

                [

                    dbc.Col(
                        make_card(
                            "🛡 Threat Score",
                            f"{threat.get('threat_score',0)} /100",
                            "#FFC107"
                        ),
                        width=3
                    ),

                    dbc.Col(
                        make_card(
                            "🚨 Threat Level",
                            threat.get("threat_level","-"),
                            "#FFC107"
                        ),
                        width=3
                    ),

                    dbc.Col(
                        make_card(
                            "📦 Hidden Modules",
                            str(hidden_modules.get("summary",{}).get("discrepancies",0)),
                            "#00FF9D"
                        ),
                        width=3
                    ),

                    dbc.Col(
                        make_card(
                            "👤 Hidden Processes",
                            str(hidden_processes.get("summary",{}).get("discrepancies",0)),
                            "#00FF9D"
                        ),
                        width=3
                    )

                ],

                className="mb-4"

            ),

            # Cards row 2
            dbc.Row(

                [

                    dbc.Col(
                        make_card(
                            "🪝 Kernel Hooks",
                            str(kernel_hooks)
                        ),
                        width=3
                    ),

                    dbc.Col(
                        make_card(
                            "🎯 IOC Matches",
                            str(ioc.get("summary",{}).get("ioc_matches",0))
                        ),
                        width=3
                    ),

                    dbc.Col(
                        make_card(
                            "🛡 MITRE ATT&CK",
                            str(mitre_count)
                        ),
                        width=3
                    ),

                    dbc.Col(
                        make_card(
                            "📊 Correlation",
                            str(correlation_score)
                        ),
                        width=3
                    )

                ]

            ),

            # --------------------------
            # CASE DETAILS + THREAT SUMMARY
            # --------------------------
            dbc.Row(

                [

                    dbc.Col(

                        case_details_panel(),

                        md=4

                    ),

                    dbc.Col(

                        threat_summary(),

                        md=8

                    )

                ],

                className="mb-4 mt-4"

            ),

            # --------------------------
            # CHARTS PANEL
            # --------------------------
            dbc.Row(

                [

                    dbc.Col(

                        charts_panel(),

                        width=12

                    )

                ],

                className="mt-4"

            ),

            # --------------------------
            # LATEST FINDINGS
            # --------------------------
            dbc.Row(

                [

                    dbc.Col(

                        latest_findings(),

                        width=12

                    )

                ],

                className="mt-4"

            ),

            # --------------------------
            # MITRE PANEL
            # --------------------------
            dbc.Row(

                [

                    dbc.Col(

                        mitre_panel(),

                        width=12

                    )

                ],

                className="mt-4"

            )

        ]

    )


# For compatibility with the router
layout = get_layout()
