import json
import os

from core.evidence_manager import EvidenceManager

class IOCEngine:

    def __init__(self, case_manager):

        self.case = case_manager

        self.evidence_path = os.path.join(
            self.case.get_case_directory(),
            "evidence"
        )

        self.database_path = os.path.join(
            "database",
            "ioc_database.json"
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

    def load_database(self):

        with open(
            self.database_path,
            "r"
        ) as file:

            return json.load(file)

    def check_modules(
        self,
        database,
        findings
    ):

        modules = self.load(
            "kernel_modules.json"
        )

        if not modules:
            return

        known_modules = {

            name.lower()

            for name in database.get(
                "modules",
                []
            )

        }

        for module in modules.get(
            "findings",
            []
        ):

            module_name = module.get(
                "name",
                ""
            ).lower()

            if module_name in known_modules:

                findings.append({

                    "category": "Kernel Module",

                    "severity": "CRITICAL",

                    "ioc": module_name,

                    "description":
                    "Known malicious kernel module detected."

                })

    def check_processes(
        self,
        database,
        findings
    ):

        processes = self.load(
            "hidden_processes.json"
        )

        if not processes:
            return

        known_processes = {

            name.lower()

            for name in database.get(
                "processes",
                []
            )

        }

        for process in processes.get(
            "findings",
            []
        ):

            process_name = process.get(
                "name",
                ""
            ).lower()

            if process_name in known_processes:

                findings.append({

                    "category": "Hidden Process",

                    "severity": "CRITICAL",

                    "ioc": process_name,

                    "description":
                    "Known malicious process detected."

                })

    def check_ports(
        self,
        database,
        findings
    ):

        network = self.load(
            "network_connections.json"
        )

        if not network:
            return

        suspicious_ports = {

            int(port)

            for port in database.get(
                "ports",
                []
            )

        }

        for connection in network.get(
            "connections",
            []
        ):

            local = connection.get(
                "local",
                ""
            )

            if ":" not in local:
                continue

            try:

                port = int(
                    local.rsplit(
                        ":",
                        1
                    )[1]
                )

            except ValueError:

                continue

            if port in suspicious_ports:

                findings.append({

                    "category": "Network",

                    "severity": "HIGH",

                    "ioc": port,

                    "description":
                    "Known suspicious network port detected."

                })

    def check_files(
        self,
        database,
        findings
    ):

        persistence = self.load(
            "persistence.json"
        )

        if not persistence:
            return

        known_files = {

            file.lower()

            for file in database.get(
                "files",
                []
            )

        }

        for item in persistence.get(
            "findings",
            []
        ):

            path = item.get(
                "path",
                ""
            ).lower()

            if path in known_files and item.get(
                "exists",
                False
            ):

                findings.append({

                    "category": "Persistence File",

                    "severity": "HIGH",

                    "ioc": path,

                    "description":
                    "Known persistence IOC file detected."

                })

    def run(self):

        database = self.load_database()

        findings = []

        self.check_modules(
            database,
            findings
        )

        self.check_processes(
            database,
            findings
        )

        self.check_ports(
            database,
            findings
        )

        self.check_files(
            database,
            findings
        )

        report = {

        "summary": {

            "ioc_matches": len(findings),

            "critical": sum(
                1 for f in findings
                if f["severity"] == "CRITICAL"
            ),

            "high": sum(
                1 for f in findings
                if f["severity"] == "HIGH"
            ),

            "medium": sum(
                1 for f in findings
                if f["severity"] == "MEDIUM"
            )

        },

        "findings": findings

        }

        EvidenceManager(
            self.case
        ).add(

            "ioc_matches",

            report

        )


        print(
            "[✓] IOC Scan Completed"
        )

        print(
            f"    Matches : {len(findings)}"
        )
