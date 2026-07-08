import json
import os

from core.evidence_manager import EvidenceManager


class MitreMapper:

    def __init__(self, case_manager):

        self.case = case_manager

        self.evidence_path = os.path.join(
            self.case.get_case_directory(),
            "evidence"
        )

    def load(self, filename):

        path = os.path.join(
            self.evidence_path,
            filename
        )

        if not os.path.exists(path):
            return None

        with open(path, "r") as file:
            return json.load(file)

    def run(self):

        techniques = []

        # -----------------------------
        # Hidden Modules -> T1014
        # -----------------------------

        hidden_modules = self.load(
            "hidden_modules.json"
        )

        if hidden_modules:

            discrepancies = hidden_modules.get(
                "summary",
                {}
            ).get(
                "discrepancies",
                0
            )

            if discrepancies > 0:

                techniques.append({

                    "id": "T1014",

                    "name": "Rootkit",

                    "severity": "CRITICAL",

                    "reason": f"{discrepancies} hidden kernel module(s) detected."

                })

        # -----------------------------
        # Hidden Processes -> T1564
        # -----------------------------

        hidden_processes = self.load(
            "hidden_processes.json"
        )

        if hidden_processes:

            discrepancies = hidden_processes.get(
                "summary",
                {}
            ).get(
                "discrepancies",
                0
            )

            if discrepancies > 0:

                techniques.append({

                    "id": "T1564",

                    "name": "Hide Artifacts",

                    "severity": "HIGH",

                    "reason": f"{discrepancies} hidden process(es) detected."

                })

        # -----------------------------
        # Persistence -> T1547
        # -----------------------------

        persistence = self.load(
            "persistence.json"
        )

        if persistence:

            suspicious = persistence.get(
                "summary",
                {}
            ).get(
                "suspicious_entries",
                0
            )

            if suspicious > 0:

                techniques.append({

                    "id": "T1547",

                    "name": "Boot or Logon Autostart Execution",

                    "severity": "HIGH",

                    "reason": f"{suspicious} persistence artifact(s) detected."

                })

        # -----------------------------
        # Kernel Hooks -> T1562
        # -----------------------------

        hooks = self.load(
            "kernel_hooks.json"
        )

        if hooks:

            suspicious = hooks.get(
                "summary",
                {}
            ).get(
                "suspicious_hooks",
                0
            )

            if suspicious > 0:

                techniques.append({

                    "id": "T1562",

                    "name": "Impair Defenses",

                    "severity": "HIGH",

                    "reason": f"{suspicious} suspicious kernel hook(s) detected."

                })

        # -----------------------------
        # Kernel Taint -> T1014
        # -----------------------------

        integrity = self.load(
            "kernel_integrity.json"
        )

        if integrity:

            if integrity.get(
                "kernel_tainted",
                "0"
            ) != "0":

                techniques.append({

                    "id": "T1014",

                    "name": "Rootkit",

                    "severity": "HIGH",

                    "reason": "Kernel reports a tainted state."

                })

        # -----------------------------
        # Baseline Changes
        # -----------------------------

        baseline = self.load(
            "baseline_comparison.json"
        )

        if baseline:

            added = baseline.get(
                "added_modules",
                []
            )

            if added:

                suspicious = []

                modules_data = self.load(
                    "kernel_modules.json"
                )

                if modules_data:

                    lookup = {
                        m["name"]: m
                        for m in modules_data.get(
                            "modules",
                            []
                        )
                    }

                    for module in added:

                        info = lookup.get(module)

                        if info and info.get(
                            "risk_level",
                            "LOW"
                        ) != "LOW":

                            suspicious.append(module)

                if suspicious:

                    techniques.append({

                        "id": "T1546",

                        "name": "Event Triggered Execution",

                        "severity": "MEDIUM",

                        "reason": "New suspicious kernel modules detected."

                    })

            if len(
                baseline.get(
                    "added_ports",
                    []
                )
            ) > 0:

                techniques.append({

                    "id": "T1046",

                    "name": "Network Service Discovery",

                    "severity": "LOW",

                    "reason": "New listening ports detected since trusted baseline."

                })

        # -----------------------------
        # Report
        # -----------------------------

        report = {

            "summary": {

                "techniques_detected": len(
                    techniques
                )

            },

            "techniques": techniques

        }

        evidence = EvidenceManager(
            self.case
        )

        evidence.add(
            "mitre_mapping",
            report
        )

        print("[✓] MITRE ATT&CK Mapping Completed")
