import json
import os


BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

EVIDENCE_ROOT = os.path.join(
    BASE_DIR,
    "evidence"
)


def latest_case():

    if not os.path.exists(EVIDENCE_ROOT):
        return None

    cases = sorted(

        d for d in os.listdir(EVIDENCE_ROOT)

        if d.startswith("CASE-")

    )

    if not cases:
        return None

    return os.path.join(

        EVIDENCE_ROOT,

        cases[-1],

        "evidence"

    )


def latest_case_dir():

    evidence_root = os.path.join(
        os.getcwd(),
        "evidence"
    )

    if not os.path.exists(evidence_root):

        return None

    cases = [

        d for d in os.listdir(evidence_root)

        if d.startswith("CASE-")

    ]

    if not cases:

        return None

    cases.sort()

    return os.path.join(

        evidence_root,

        cases[-1]

    )


def latest_case_id():

    case = latest_case_dir()

    if case:

        return os.path.basename(case)

    return "-"


def load(filename):

    folder = latest_case()

    if folder is None:
        return {}

    path = os.path.join(
        folder,
        filename
    )

    # Temporary test print
    print(path)

    if not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        return json.load(f)
