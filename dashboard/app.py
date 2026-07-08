import dash
import os
import subprocess
import threading

from dash import Dash, html, dcc, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
from flask import send_from_directory

from components.sidebar import sidebar
from pages import dashboard
from pages import investigations
from pages import reports
from pages import evidence

app = Dash(
    __name__,
    suppress_callback_exceptions=True,
    external_stylesheets=[
        dbc.themes.BOOTSTRAP
    ]
)

server = app.server

# Global variable to track scan status
SCAN_RUNNING = False

REPORT_DIR = os.path.join(
    os.getcwd(),
    "reports",
    "generated"
)


@server.route("/generated_reports/<path:filename>")
def generated_reports(filename):
    return send_from_directory(
        REPORT_DIR,
        filename
    )


EVIDENCE_DIR = os.path.join(
    os.getcwd(),
    "evidence"
)


@server.route("/generated_evidence/<path:filename>")
def generated_evidence(filename):
    return send_from_directory(
        os.getcwd(),
        os.path.join(
            "evidence",
            filename
        ),
        as_attachment=True
    )


app.title = "AKRDFAS Dashboard"

CONTENT_STYLE = {
    "marginLeft": "270px",
    "padding": "25px",
    "backgroundColor": "#0B0F14",
    "minHeight": "100vh",
    "color": "#EAEAEA"
}

app.layout = html.Div(
    [
        dcc.Location(
            id="url"
        ),

        # Page refresh location for automatic reload
        dcc.Location(
            id="page-refresh",
            refresh=True
        ),

        sidebar,

        html.Div(
            [
                html.Div(
                    id="page-content"
                )
            ],
            style=CONTENT_STYLE
        )
    ]
)


# Function to run the scan
def run_scan():
    global SCAN_RUNNING
    SCAN_RUNNING = True
    try:
        subprocess.run(
            ["python", "main.py"],
            cwd=os.getcwd()
        )
    finally:
        SCAN_RUNNING = False


@app.callback(
    Output("page-content", "children"),
    Input("url", "pathname")
)
def router(path):
    if path == "/investigations":
        return investigations.get_layout()
    elif path == "/reports":
        return reports.get_layout()
    elif path == "/evidence":
        return evidence.get_layout()
    return dashboard.get_layout()


# Combined callback that handles both starting the scan AND updating status
@app.callback(
    Output("scan-status", "children"),
    Output("scan-status", "style"),
    Output("scan-check", "disabled"),
    Output("start-scan", "disabled"),
    Output("start-scan", "children"),
    Output("page-refresh", "href"),
    Input("start-scan", "n_clicks"),
    Input("scan-check", "n_intervals"),
    prevent_initial_call=True
)
def handle_scan_and_status(start_clicks, intervals):
    global SCAN_RUNNING

    ctx = callback_context
    trigger_id = ctx.triggered[0]["prop_id"].split(".")[0] if ctx.triggered else None

    # Handle the case when the scan button is clicked
    if trigger_id == "start-scan":
        if SCAN_RUNNING:
            return (
                "Investigation already running...",
                {
                    "color": "orange",
                    "fontWeight": "bold",
                    "paddingTop": "12px"
                },
                False,
                True,
                "⏳ Running...",
                dash.no_update
            )

        # Start the scan in a background thread
        thread = threading.Thread(
            target=run_scan,
            daemon=True
        )
        thread.start()

        return (
            "Investigation Started...",
            {
                "color": "orange",
                "fontWeight": "bold",
                "paddingTop": "12px"
            },
            False,
            True,
            "⏳ Running...",
            dash.no_update
        )

    # Handle the case when the interval triggers (status update)
    elif trigger_id == "scan-check":
        if SCAN_RUNNING:
            return (
                "Investigation Running...",
                {
                    "color": "orange",
                    "fontWeight": "bold",
                    "paddingTop": "12px"
                },
                False,
                True,
                "⏳ Running...",
                dash.no_update
            )

        # Investigation complete
        return (
            "✔ Investigation Complete",
            {
                "color": "#00FF9D",
                "fontWeight": "bold",
                "paddingTop": "12px"
            },
            True,
            False,
            "▶ Start Investigation",
            "/"
        )

    # Default fallback (should not reach here)
    return dash.no_update


if __name__ == "__main__":
    app.run(debug=True)
