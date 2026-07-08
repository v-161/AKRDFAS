import json
import os

from core.evidence_manager import EvidenceManager
from core.risk_engine import RiskEngine


class ThreatCorrelationEngine:

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

    def process_hidden_processes(
        self,
        hp,
        risk,
        reasons
    ):

        if not hp:
            return

        count = hp["summary"]["discrepancies"]

        if count > 0:

            risk.hidden_processes(count)

            reasons.append(
                f"{count} hidden process discrepancies detected."
            )

    def process_hidden_modules(
        self,
        hm,
        risk,
        reasons
    ):

        if not hm:
            return

        count = hm["summary"]["discrepancies"]

        if count > 0:

            risk.hidden_modules(count)

            reasons.append(
                f"{count} module visibility discrepancies found."
            )

    def process_kernel_integrity(
        self,
        integrity,
        risk,
        reasons
    ):

        if not integrity:
            return

        tainted = integrity.get("kernel_tainted", 0)

        if tainted != 0:

            risk.kernel_taint()

            reasons.append(
                "Kernel is tainted."
            )

    def process_network(
        self,
        network,
        risk,
        reasons
    ):

        if not network:
            return

        listening = network["summary"]["listening_ports"]

        if listening > 100:

            risk.add_custom(15)

            reasons.append(
                "Large number of listening ports detected."
            )

        elif listening > 50:

            risk.add_custom(10)

            reasons.append(
                "High number of listening ports detected."
            )

        elif listening > 20:

            risk.add_custom(5)

    def process_persistence(
        self,
        persistence,
        risk,
        reasons
    ):

        if not persistence:
            return

        count = persistence.get(
            "summary",
            {}
        ).get(
            "suspicious_entries",
            0
        )

        if count > 0:

            risk.persistence(count)

            reasons.append(
                f"{count} persistence artifacts detected."
            )

    def process_kernel_logs(
        self,
        logs,
        risk,
        reasons
    ):

        if not logs:
            return

        summary = logs.get(
            "summary",
            {}
        )

        errors = summary.get(
            "errors",
            0
        )

        panics = summary.get(
            "panics",
            0
        )

        taints = summary.get(
            "taints",
            0
        )

        if panics > 0:

            risk.kernel_panic()

            reasons.append(
                f"{panics} kernel panic/oops events detected."
            )

        if errors >= 5:

            risk.add_custom(15)

            reasons.append(
                f"{errors} kernel log errors detected."
            )

        if taints > 0:

            risk.kernel_taint()

            reasons.append(
                f"{taints} kernel taint log entries detected."
            )

    def process_kernel_hooks(
        self,
        hooks,
        risk,
        reasons
    ):

        if not hooks:
            return 0

        suspicious = 0

        for finding in hooks.get("findings", []):

            severity = finding.get(
                "severity",
                "INFO"
            )

            if severity in (
                "SUSPICIOUS",
                "CRITICAL"
            ):

                suspicious += 1

        if suspicious:

            risk.kernel_hooks(suspicious)

            reasons.append(
                f"{suspicious} suspicious kernel hook(s) detected."
            )

        return suspicious

    def run(self):

        risk = RiskEngine()

        reasons = []

        recommendations = []

        hp = self.load(
            "hidden_processes.json"
        )

        hm = self.load(
            "hidden_modules.json"
        )

        integrity = self.load(
            "kernel_integrity.json"
        )

        network = self.load(
            "network_connections.json"
        )

        persistence = self.load(
            "persistence.json"
        )

        logs = self.load(
            "kernel_logs.json"
        )

        hooks = self.load(
            "kernel_hooks.json"
        )

        baseline = self.load(
            "baseline_comparison.json"
        )

        correlation = self.load(
            "correlation_findings.json"
        )

        self.process_hidden_processes(
            hp,
            risk,
            reasons
        )

        self.process_hidden_modules(
            hm,
            risk,
            reasons
        )

        self.process_kernel_integrity(
            integrity,
            risk,
            reasons
        )

        self.process_network(
            network,
            risk,
            reasons
        )

        self.process_persistence(
            persistence,
            risk,
            reasons
        )

        self.process_kernel_logs(
            logs,
            risk,
            reasons
        )

        hook_score = self.process_kernel_hooks(
            hooks,
            risk,
            reasons
        )

        # -----------------------------
        # Baseline Comparison
        # -----------------------------

        if baseline:

            added_modules = len(
                baseline.get(
                    "added_modules",
                    []
                )
            )

            removed_modules = len(
                baseline.get(
                    "removed_modules",
                    []
                )
            )

            added_ports = len(
                baseline.get(
                    "added_ports",
                    []
                )
            )

            removed_ports = len(
                baseline.get(
                    "removed_ports",
                    []
                )
            )

            if added_modules > 0:

                if added_modules <= 2:

                    risk.add_custom(5)

                elif added_modules <= 5:

                    risk.add_custom(10)

                else:

                    risk.add_custom(20)

                reasons.append(
                    f"{added_modules} kernel module(s) added since trusted baseline."
                )

            if removed_modules > 0:

                risk.add_custom(
                    min(
                        removed_modules * 10,
                        30
                    )
                )

                reasons.append(
                    f"{removed_modules} kernel module(s) removed since trusted baseline."
                )

            if added_ports > 0:

                risk.add_custom(3)

                reasons.append(
                    f"{added_ports} new listening port(s) detected."
                )

            if removed_ports > 0:

                reasons.append(
                    f"{removed_ports} listening port(s) disappeared."
                )

            if baseline.get(
                "kernel_changed"
            ):

                risk.add_custom(20)

                reasons.append(
                    "Kernel release differs from trusted baseline."
                )

            if baseline.get(
                "architecture_changed"
            ):

                risk.add_custom(25)

                reasons.append(
                    "System architecture differs from trusted baseline."
                )

            if baseline.get("hostname_changed"):

                reasons.append(
                    "Hostname differs from trusted baseline."
                )

        # -----------------------------
        # Correlation Findings
        # -----------------------------

        correlation_score = 0

        if correlation:

            correlation_score = correlation.get(
                "total_score",
                0
            )

            if correlation_score > 0:

                risk.add_custom(
                    min(
                        correlation_score // 2,
                        20
                    )
                )

                for finding in correlation.get(
                    "findings",
                    []
                ):

                    reasons.append(
                        f"[{finding['rule']}] {finding['description']}"
                    )
        # -----------------------------
        # IOC Findings
        # -----------------------------
        ioc = self.load(
            "ioc_matches.json"
        )

        if ioc:

            ioc_score = 0

            for finding in ioc.get(
                "findings",
                []
            ):

                severity = finding.get(
                    "severity",
                    ""
                )

                if severity == "CRITICAL":

                    ioc_score += 20

                elif severity == "HIGH":

                    ioc_score += 10

                elif severity == "MEDIUM":

                    ioc_score += 5

                reasons.append(

                    f"[IOC] {finding['description']}"

                )

            risk.add_custom(
                min(
                    ioc_score,
                    50
                )
            )

        # -----------------------------
        # Final Risk Score
        # -----------------------------

        score = risk.total()

        # Safety cap for clean systems
        if (
            hp["summary"]["discrepancies"] == 0
            and hm["summary"]["discrepancies"] == 0
            and integrity.get("kernel_tainted", 0) == 0
            and ioc["summary"]["ioc_matches"] == 0
        ):
            score = min(score, 40)

        level = risk.level()

        # -----------------------------
        # Recommendations
        # -----------------------------

        if level == "LOW":

            recommendations.append(
                "Continue routine monitoring."
            )

        elif level == "MEDIUM":

            recommendations.append(
                "Review suspicious evidence."
            )

        elif level == "HIGH":

            recommendations.append(
                "Perform detailed forensic investigation."
            )

        else:

            recommendations.append(
                "Immediate forensic investigation recommended."
            )

        # -----------------------------
        # Threat Report
        # -----------------------------

        report = {

            "threat_score": score,

            "threat_level": level,

            "summary": {

                "hidden_processes": hp["summary"]["discrepancies"] if hp else 0,

                "hidden_modules": hm["summary"]["discrepancies"] if hm else 0,

                "kernel_tainted": integrity.get("kernel_tainted", 0) if integrity else 0,

                "listening_ports": network["summary"]["listening_ports"] if network else 0,

                "kernel_errors": logs.get("summary", {}).get("errors", 0) if logs else 0,

                "kernel_panics": logs.get("summary", {}).get("panics", 0) if logs else 0,

                "persistence_entries": persistence.get("summary", {}).get("suspicious_entries", 0) if persistence else 0,

                "kernel_hooks": hook_score,

                "added_modules": len(baseline.get("added_modules", [])) if baseline else 0,

                "removed_modules": len(baseline.get("removed_modules", [])) if baseline else 0,

                "added_ports": len(baseline.get("added_ports", [])) if baseline else 0,

                "removed_ports": len(baseline.get("removed_ports", [])) if baseline else 0,

                "correlation_score": correlation_score,

                "ioc_matches": ioc["summary"]["ioc_matches"] if ioc else 0

            },

            "reasons": reasons,

            "recommendations": recommendations

        }

        evidence = EvidenceManager(
            self.case
        )

        evidence.add(
            "threat_assessment",
            report
        )

                # -----------------------------
        # Console Output
        # -----------------------------
        print("\n========== Threat Assessment ==========")

        print(f"Threat Score : {score}/100")
        print(f"Threat Level : {level}")

        print("\nInvestigation Summary")

        print(f"• Hidden Processes : {report['summary']['hidden_processes']}")
        print(f"• Hidden Modules   : {report['summary']['hidden_modules']}")
        print(f"• Kernel Tainted   : {report['summary']['kernel_tainted']}")
        print(f"• Listening Ports  : {report['summary']['listening_ports']}")
        print(f"• Kernel Errors    : {report['summary']['kernel_errors']}")
        print(f"• Kernel Panics    : {report['summary']['kernel_panics']}")
        print(f"• Persistence      : {report['summary']['persistence_entries']}")
        print(f"• Kernel Hooks     : {report['summary']['kernel_hooks']}")
        print(f"• Added Modules    : {report['summary']['added_modules']}")
        print(f"• Removed Modules  : {report['summary']['removed_modules']}")
        print(f"• Added Ports      : {report['summary']['added_ports']}")
        print(f"• Removed Ports    : {report['summary']['removed_ports']}")
        print(f"• Correlation Score: {report['summary']['correlation_score']}")
        print(f"• IOC Matches      : {report['summary']['ioc_matches']}")

        print("\nReasons")

        if reasons:

            for reason in reasons:

                print(f"  • {reason}")

        else:

            print("  • No significant indicators detected.")

        print("\nRecommendations")

        for recommendation in recommendations:

            print(f"  • {recommendation}")

        print("\n=======================================\n")
