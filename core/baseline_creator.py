import json
import os

from core.baseline_manager import BaselineManager


class BaselineCreator:

    def __init__(self, case):

        self.case = case

        self.evidence = os.path.join(
            case.get_case_directory(),
            "evidence"
        )

    def load(self, filename):

        path = os.path.join(
            self.evidence,
            filename
        )

        if not os.path.exists(path):
            return None

        with open(path, "r") as f:
            return json.load(f)

    def run(self):

        kernel = self.load(
            "kernel_baseline.json"
        )

        modules = self.load(
            "kernel_modules.json"
        )

        network = self.load(
            "network_connections.json"
        )

        if not kernel or not modules or not network:

            return

        baseline = {

            "kernel_release":
                kernel.get("kernel_release"),

            "kernel_version":
                kernel.get("kernel_version"),

            "architecture":
                kernel.get("architecture"),

            "hostname":
                kernel.get("hostname"),

            "modules": sorted([
                module["name"]
                for module in modules["findings"]
            ]),

            "listening_ports": sorted([
                connection["local"].split(":")[-1]
                for connection in network["connections"]
                if connection["status"] == "LISTEN"
            ])

        }

        manager = BaselineManager()

        if not manager.exists():

            manager.save(
                baseline
            )

            print(
                "[✓] Trusted Baseline Created"
            )

        else:

            print(
                "[✓] Trusted Baseline Already Exists"
            )
