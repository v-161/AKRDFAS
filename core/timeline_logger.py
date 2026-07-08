import json
import os
from datetime import datetime


class TimelineLogger:

    def __init__(self, case_manager):

        self.case = case_manager

        self.timeline = []

    def add_event(
        self,
        event
    ):

        self.timeline.append({

            "time": datetime.now().strftime(
                "%H:%M:%S"
            ),

            "event": event

        })

    def save(self):

        evidence_dir = os.path.join(

            self.case.get_case_directory(),

            "evidence"

        )

        with open(

            os.path.join(
                evidence_dir,
                "timeline.json"
            ),

            "w"

        ) as file:

            json.dump(

                {

                    "events": self.timeline

                },

                file,

                indent=4

            )
