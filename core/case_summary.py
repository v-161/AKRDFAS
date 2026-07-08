import json
import os


class CaseSummary:

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
            return {}

        with open(path, "r") as f:
            return json.load(f)

    def run(self):

        kernel = self.load("kernel_information.json")
        modules = self.load("kernel_modules.json")
        hidden_modules = self.load("hidden_modules.json")
        hidden_processes = self.load("hidden_processes.json")
        logs = self.load("kernel_logs.json")
        hooks = self.load("kernel_hooks.json")
        persistence = self.load("persistence.json")
        baseline = self.load("baseline_comparison.json")
        correlation = self.load("correlation_findings.json")
        ioc = self.load("ioc_matches.json")
        threat = self.load("threat_assessment.json")
        integrity = self.load("integrity_verification.json")

        summary = {

            "case_id":
                self.case.get_case_id(),

            "hostname":
                kernel.get("hostname"),

            "kernel":
                kernel.get("kernel_release"),

            "architecture":
                kernel.get("architecture"),

            "threat_score":
                threat.get("threat_score"),

            "threat_level":
                threat.get("threat_level"),

            "modules":
                modules.get("summary", {}).get("modules_scanned", 0),

            "hidden_modules":
                hidden_modules.get("summary", {}).get("discrepancies", 0),

            "hidden_processes":
                hidden_processes.get("summary", {}).get("discrepancies", 0),

            "kernel_errors":
                logs.get("summary", {}).get("errors", 0),

            "kernel_panics":
                logs.get("summary", {}).get("panics", 0),

            "kernel_hooks":
                len(hooks.get("findings", [])),

            "persistence":
                persistence.get("summary", {}).get("suspicious_entries", 0),

            "added_modules":
                len(baseline.get("added_modules", [])),

            "removed_modules":
                len(baseline.get("removed_modules", [])),

            "added_ports":
                len(baseline.get("added_ports", [])),

            "removed_ports":
                len(baseline.get("removed_ports", [])),

            "ioc_matches":
                ioc.get("summary", {}).get("ioc_matches", 0),

            "correlation_score":
                correlation.get("total_score", 0),

            "evidence_verified":
                integrity.get("status") == "VERIFIED"
        }

        with open(
            os.path.join(
                self.evidence,
                "case_summary.json"
            ),
            "w"
        ) as f:

            json.dump(
                summary,
                f,
                indent=4
            )
