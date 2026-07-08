import json
import os


class BaselineManager:

    def __init__(self):

        self.path = os.path.join(
            "baseline",
            "trusted_baseline.json"
        )

    def exists(self):

        return os.path.exists(
            self.path
        )

    def load(self):

        if not self.exists():

            return None

        with open(self.path, "r") as f:

            return json.load(f)

    def save(self, data):

        os.makedirs(
            "baseline",
            exist_ok=True
        )

        with open(self.path, "w") as f:

            json.dump(
                data,
                f,
                indent=4
            )
