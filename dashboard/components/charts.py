from dash import dcc, html
import plotly.graph_objects as go
import os
import json

BASE_DIR = os.getcwd()
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")


def load_cases():

    scores = []
    labels = []

    hidden = 0
    processes = 0
    hooks = 0
    persistence = 0
    iocs = 0

    if not os.path.exists(EVIDENCE_DIR):
        return [], [], [0, 0, 0, 0, 0]

    folders = sorted(os.listdir(EVIDENCE_DIR))

    for folder in folders:

        case = os.path.join(EVIDENCE_DIR, folder, "evidence")

        threat = os.path.join(case, "threat_assessment.json")

        if os.path.exists(threat):

            with open(threat) as f:

                data = json.load(f)

            scores.append(data.get("threat_score", 0))

            labels.append(folder[-6:])

        hm = os.path.join(case, "hidden_modules.json")

        if os.path.exists(hm):

            with open(hm) as f:

                hidden += json.load(f).get("summary", {}).get("discrepancies", 0)

        hp = os.path.join(case, "hidden_processes.json")

        if os.path.exists(hp):

            with open(hp) as f:

                processes += json.load(f).get("summary", {}).get("discrepancies", 0)

        hk = os.path.join(case, "kernel_hooks.json")

        if os.path.exists(hk):

            with open(hk) as f:

                hooks += len(json.load(f).get("findings", []))

        per = os.path.join(case, "persistence.json")

        if os.path.exists(per):

            with open(per) as f:

                persistence += len(json.load(f).get("findings", []))

        ioc = os.path.join(case, "ioc_matches.json")

        if os.path.exists(ioc):

            with open(ioc) as f:

                iocs += json.load(f).get("summary", {}).get("ioc_matches", 0)

    return labels, scores, [hidden, processes, hooks, persistence, iocs]


def get_layout():

    labels, scores, pie = load_cases()

    line = go.Figure()

    line.add_trace(

        go.Scatter(

            x=labels,

            y=scores,

            mode="lines+markers",

            name="Threat Score"

        )

    )

    line.update_layout(

        template="plotly_dark",

        height=320,

        margin=dict(l=20, r=20, t=40, b=20),

        title="Threat Score Trend"

    )

    donut = go.Figure(

        data=[

            go.Pie(

                labels=[

                    "Hidden Modules",

                    "Hidden Processes",

                    "Kernel Hooks",

                    "Persistence",

                    "IOC Matches"

                ],

                values=pie,

                hole=.45

            )

        ]

    )

    donut.update_layout(

        template="plotly_dark",

        height=320,

        margin=dict(l=20, r=20, t=40, b=20),

        title="Findings Distribution"

    )

    return html.Div(

        [

            html.Div(

                dcc.Graph(

                    figure=line,

                    config={"displayModeBar": False}

                ),

                style={"width": "50%"}

            ),

            html.Div(

                dcc.Graph(

                    figure=donut,

                    config={"displayModeBar": False}

                ),

                style={"width": "50%"}

            )

        ],

        style={

            "display": "flex",

            "gap": "20px",

            "marginBottom": "25px"

        }

    )
