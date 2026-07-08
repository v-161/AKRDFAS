import json
import os


class CorrelationEngine:

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

        with open(path, "r") as f:
            return json.load(f)

    def suspicious_hook_count(self, hooks):

        if not hooks:
            return 0

        count = 0

        for finding in hooks.get("findings", []):

            if finding.get("type") == "Warning":

                count += 1

        return count

    def run(self):

        findings = []

        score = 0

        report = {

            "total_score": 0,

            "findings": []

        }

        # ----------------------------------
        # Load Evidence
        # ----------------------------------

        hidden_processes = self.load(
            "hidden_processes.json"
        )

        hidden_modules = self.load(
            "hidden_modules.json"
        )

        network = self.load(
            "network_connections.json"
        )

        hooks = self.load(
            "kernel_hooks.json"
        )

        integrity = self.load(
            "kernel_integrity.json"
        )

        baseline = self.load(
            "baseline_comparison.json"
        )

        persistence = self.load(
            "persistence.json"
        )

        logs = self.load(
            "kernel_logs.json"
        )

        ioc = self.load(
            "ioc_matches.json"
        )

        module_analysis = self.load(
            "module_analysis.json"
        )

        # ----------------------------------
        # CR-001
        # Hidden Process + Hidden Module
        # ----------------------------------

        if hidden_processes and hidden_modules:

            hp = hidden_processes["summary"]["discrepancies"]

            hm = hidden_modules["summary"]["discrepancies"]

            if hp > 0 and hm > 0:

                findings.append({

                    "rule": "CR-001",

                    "severity": "HIGH",

                    "score": 25,

                    "description":
                    "Hidden process correlates with hidden kernel module."

                })

                score += 25

        # ----------------------------------
        # CR-002
        # Hidden Process + Network Activity
        # ----------------------------------

        if hidden_processes and network:

            hp = hidden_processes["summary"]["discrepancies"]

            connections = network["summary"]["total_connections"]

            if hp > 0 and connections > 0:

                findings.append({

                    "rule": "CR-002",

                    "severity": "HIGH",

                    "score": 20,

                    "description":
                    "Hidden process with active network activity."

                })

                score += 20

        # ----------------------------------
        # CR-003
        # Kernel Hooks + Kernel Taint
        # ----------------------------------

        if hooks and integrity:

            tainted = integrity.get(
                "kernel_tainted",
                0
            )

            suspicious_hooks = hooks.get(
                "summary",
                {}
            ).get(
                "suspicious_hooks",
                0
            )

            if tainted != 0 and suspicious_hooks > 0:

                findings.append({

                    "rule": "CR-003",

                    "severity": "CRITICAL",

                    "score": 30,

                    "description":
                    "Kernel taint with suspicious hook activity."

                })

                score += 30

        # ----------------------------------
        # CR-004
        # Baseline Module Changes
        # ----------------------------------

        if baseline and module_analysis:

            added_modules = baseline.get(
                "added_modules",
                []
            )

            if len(added_modules) > 0:

                suspicious = []

                modules = module_analysis.get(
                    "modules",
                    []
                )

                lookup = {
                    m["name"]: m
                    for m in modules
                }

                for module in added_modules:

                    info = lookup.get(module)

                    if not info:
                        continue

                    if info.get(
                        "risk_level",
                        "LOW"
                    ) != "LOW":

                        suspicious.append(module)

                if suspicious:

                    findings.append({

                        "rule": "CR-004",

                        "severity": "MEDIUM",

                        "score": 20,

                        "description":
                        "New suspicious kernel modules differ from trusted baseline."

                    })

                    score += 20

        # ----------------------------------
        # CR-005
        # Persistence + New Modules
        # ----------------------------------

        if persistence and baseline:

            entries = persistence["summary"]["suspicious_entries"]

            added = len(
                baseline.get(
                    "added_modules",
                    []
                )
            )

            if entries > 0 and added > 0:

                findings.append({

                    "rule": "CR-005",

                    "severity": "HIGH",

                    "score": 20,

                    "description":
                    "Persistence artifacts correlate with new modules."

                })

                score += 20

        # ----------------------------------
        # CR-006
        # Kernel Hooks + Kernel Errors
        # ----------------------------------

        if hooks and logs:

            hook_count = self.suspicious_hook_count(hooks)

            errors = logs.get("summary", {}).get("errors", 0)

            if hook_count > 0 and errors > 0:

                findings.append({

                    "rule": "CR-006",

                    "severity": "MEDIUM",

                    "score": 15,

                    "description":
                    "Kernel hook activity coincides with kernel log errors."

                })

                score += 15

        # ----------------------------------
        # CR-007
        # Hidden Module + Added Module
        # ----------------------------------

        if hidden_modules and baseline:

            hm = hidden_modules["summary"]["discrepancies"]

            added = len(baseline.get("added_modules", []))

            if hm > 0 and added > 0:

                findings.append({

                    "rule": "CR-007",

                    "severity": "HIGH",

                    "score": 30,

                    "description":
                    "Hidden modules detected together with new kernel modules."

                })

                score += 30

        # ----------------------------------
        # CR-008
        # IOC + Hidden Module
        # ----------------------------------

        if ioc and hidden_modules:

            matches = ioc.get("summary", {}).get("ioc_matches", 0)

            hm = hidden_modules["summary"]["discrepancies"]

            if matches > 0 and hm > 0:

                findings.append({

                    "rule": "CR-008",

                    "severity": "CRITICAL",

                    "score": 50,

                    "description":
                    "Hidden kernel module matches known Indicators of Compromise."

                })

                score += 50

        # ----------------------------------
        # CR-009
        # IOC + Kernel Hook
        # ----------------------------------

        if ioc and hooks:

            matches = ioc.get("summary", {}).get("ioc_matches", 0)

            hook_count = self.suspicious_hook_count(hooks)

            if matches > 0 and hook_count > 0:

                findings.append({

                    "rule": "CR-009",

                    "severity": "CRITICAL",

                    "score": 45,

                    "description":
                    "Kernel hook activity correlates with known IOC."

                })

                score += 45

        # ----------------------------------
        # CR-010
        # New Listening Port + Kernel Hook
        # ----------------------------------

        if baseline and hooks:

            added_ports = len(
                baseline.get(
                    "added_ports",
                    []
                )
            )

            suspicious_hooks = hooks.get(
                "summary",
                {}
            ).get(
                "suspicious_hooks",
                0
            )

            if added_ports > 0 and suspicious_hooks > 0:

                findings.append({

                    "rule": "CR-010",

                    "severity": "HIGH",

                    "score": 25,

                    "description":
                    "New listening ports observed alongside kernel hook activity."

                })

                score += 25

        # ----------------------------------
        # Save Report
        # ----------------------------------

        report["total_score"] = score

        report["findings"] = findings

        with open(
            os.path.join(
                self.evidence_path,
                "correlation_findings.json"
            ),
            "w"
        ) as f:

            json.dump(
                report,
                f,
                indent=4
            )

        print("[✓] Threat Correlation Completed")
