import json
import os

from core.baseline_manager import BaselineManager
from core.evidence_manager import EvidenceManager


class BaselineComparator:

    def __init__(self, case):

        self.case = case

        self.evidence_path = os.path.join(
            case.get_case_directory(),
            "evidence"
        )

    def load(self, filename):

        path = os.path.join(
            self.evidence_path,
            filename
        )

        if not os.path.exists(path):
            return None

        with open(path, "r") as f:
            return json.load(f)

    def run(self):

        manager = BaselineManager()

        trusted = manager.load()

        if not trusted:

            print("[!] No trusted baseline found.")
            return

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

        current_modules = sorted([
            m["name"]
            for m in modules["findings"]
        ])

        current_ports = sorted([
            c["local"].split(":")[-1]
            for c in network["connections"]
            if c["status"] == "LISTEN"
        ])

        added_modules = sorted(
            list(
                set(current_modules) -
                set(trusted["modules"])
            )
        )

        removed_modules = sorted(
            list(
                set(trusted["modules"]) -
                set(current_modules)
            )
        )

        added_ports = sorted(
            list(
                set(current_ports) -
                set(trusted["listening_ports"])
            )
        )

        removed_ports = sorted(
            list(
                set(trusted["listening_ports"]) -
                set(current_ports)
            )
        )

        kernel_changed = (
            trusted["kernel_release"] !=
            kernel["kernel_release"]
        )

        architecture_changed = (
            trusted["architecture"] !=
            kernel["architecture"]
        )

        hostname_changed = (
            trusted["hostname"] !=
            kernel["hostname"]
        )

        report = {

            "kernel_changed": kernel_changed,

            "architecture_changed":
                architecture_changed,

            "hostname_changed":
                hostname_changed,

            "added_modules":
                added_modules,

            "removed_modules":
                removed_modules,

            "added_ports":
                added_ports,

            "removed_ports":
                removed_ports
        }

        evidence = EvidenceManager(
            self.case
        )

        evidence.add(
            "baseline_comparison",
            report
        )

        print("[✓] Baseline Comparison Completed")

        print(
            f"    Added Modules   : {len(added_modules)}"
        )

        print(
            f"    Removed Modules : {len(removed_modules)}"
        )

        print(
            f"    Added Ports     : {len(added_ports)}"
        )

        print(
            f"    Removed Ports   : {len(removed_ports)}"
        )

        if kernel_changed:
            print(
                "    Kernel Release Changed"
            )

        if architecture_changed:
            print(
                "    Architecture Changed"
            )

        if hostname_changed:
            print(
                "    Hostname Changed"
            )
