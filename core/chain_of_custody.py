import json
import os
from datetime import datetime


class ChainOfCustody:

    def __init__(self, case_manager):

        self.case = case_manager

        self.evidence_dir = os.path.join(
            self.case.get_case_directory(),
            "evidence"
        )

        self.path = os.path.join(
            self.evidence_dir,
            "chain_of_custody.json"
        )

    def log(self, action, file_name="", status="SUCCESS"):

        if os.path.exists(self.path):

            with open(self.path, "r") as f:

                entries = json.load(f)

        else:

            entries = []

        entries.append({

            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "action": action,

            "file": file_name,

            "status": status

        })

        with open(self.path, "w") as f:

            json.dump(
                entries,
                f,
                indent=4
            )