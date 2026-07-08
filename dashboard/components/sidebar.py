from dash import html, dcc
import dash_bootstrap_components as dbc

SIDEBAR_STYLE = {
    "position": "fixed",
    "top": 0,
    "left": 0,
    "bottom": 0,
    "width": "250px",
    "padding": "25px",
    "backgroundColor": "#151A21",
    "borderRight": "1px solid #252B36",
}

LINK_STYLE = {
    "display": "block",
    "padding": "15px",
    "marginBottom": "12px",
    "textDecoration": "none",
    "color": "#EAEAEA",
    "borderRadius": "10px",
    "fontWeight": "600",
    "transition": "0.2s"
}

sidebar = html.Div(

    [

        html.Div(

            [

                html.H2(
                    "🛡 AKRDFAS",
                    style={
                        "color":"#00E5FF",
                        "textAlign":"center",
                        "marginBottom":"5px"
                    }
                ),

                html.P(

                    "Version 1.0",

                    style={
                        "textAlign":"center",
                        "color":"#9CA3AF",
                        "fontSize":"13px",
                        "marginBottom":"2px"
                    }

                ),

                html.P(

                    "Kernel Rootkit Detection",

                    style={
                        "textAlign":"center",
                        "color":"#6B7280",
                        "fontSize":"11px",
                        "marginBottom":"30px"
                    }

                )

            ]

        ),

        dcc.Link("🏠 Dashboard", href="/", style=LINK_STYLE),

        dcc.Link("📂 Investigations", href="/investigations", style=LINK_STYLE),

        dcc.Link("📄 Reports", href="/reports", style=LINK_STYLE),

        dcc.Link("🧾 Evidence", href="/evidence", style=LINK_STYLE),

        html.Hr(),

        html.H6(

            "System Status",

            style={

                "color":"#9CA3AF",

                "marginTop":"20px"

            }

        ),

        dbc.Alert(

            [

                "🟢 Ready"

            ],

            color="success",

            style={

                "fontWeight":"bold",

                "textAlign":"center"

            }

        )

    ],

    style=SIDEBAR_STYLE

)
