import json
from pathlib import Path


class Config:

    def __init__(self):

        self.base_dir = Path(__file__).resolve().parent.parent

        config_path = self.base_dir / "config" / "settings.json"

        with open(config_path, "r") as file:
            self.settings = json.load(file)

    def get(self, *keys):

        value = self.settings

        for key in keys:
            value = value[key]

        return value