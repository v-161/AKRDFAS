import json
import os

from core.evidence_manager import EvidenceManager


class IOCDetector:

    def __init__(
        self,
        logger,
        evidence,
        case_manager
    ):

        self.logger = logger

        self.evidence = evidence

        self.case = case_manager

        self.case_dir = self.case.get_case_directory()

        self.evidence_dir = os.path.join(
            self.case_dir,
            "evidence"
        )

        self.database_path = os.path.join(
            "database",
            "ioc_database.json"
        )

    def load_json(
        self,
        filename
    ):

        path = os.path.join(
            self.evidence_dir,
            filename
        )

        if not os.path.exists(path):

            return {}

        with open(
            path,
            "r"
        ) as file:

            return json.load(file)

    def load_database(self):

        if not os.path.exists(
            self.database_path
        ):

            return {}

        with open(
            self.database_path,
            "r"
        ) as file:

            return json.load(file)

    def run(self):

        database = self.load_database()

        modules = self.load_json(
            "kernel_modules.json"
        )

        network = self.load_json(
            "network_connections.json"
        )

        processes = self.load_json(
            "hidden_processes.json"
        )

        findings = []

        # -----------------------------------
        # Module IOC Matching
        # -----------------------------------

        bad_modules = database.get(
            "kernel_modules",
            []
        )

        for module in modules.get(
            "modules",
            []
        ):

            name = module.get(
                "name",
                ""
            )

            if name in bad_modules:

                findings.append({

                    "indicator": name,

                    "type": "Kernel Module",

                    "severity": "CRITICAL",

                    "description": f"Known malicious kernel module detected ({name})"

                })

        # -----------------------------------
        # Network IOC Matching
        # -----------------------------------

        bad_ports = database.get(
            "ports",
            []
        )

        for connection in network.get(
            "connections",
            []
        ):

            port = connection.get(
                "local_port",
                None
            )

            if port in bad_ports:

                findings.append({

                    "indicator": str(port),

                    "type": "Network Port",

                    "severity": "HIGH",

                    "description": f"Known malicious listening port ({port})"

                })

        # -----------------------------------
        # Process IOC Matching
        # -----------------------------------

        bad_processes = database.get(
            "processes",
            []
        )

        for process in processes.get(
            "hidden_processes",
            []
        ):

            name = process.get(
                "name",
                ""
            )

            if name in bad_processes:

                findings.append({

                    "indicator": name,

                    "type": "Process",

                    "severity": "HIGH",

                    "description": f"Known malicious process ({name})"

                })

        # -----------------------------------
        # Hash IOC Matching (Optional)
        # -----------------------------------

        bad_hashes = database.get(
            "hashes",
            []
        )

        for module in modules.get(
            "modules",
            []
        ):

            sha256 = module.get(
                "sha256",
                ""
            )

            if sha256 in bad_hashes:

                findings.append({

                    "indicator": sha256,

                    "type": "SHA256",

                    "severity": "CRITICAL",

                    "description": "Known malicious kernel module hash detected"

                })

        report = {

            "summary": {

                "ioc_matches": len(findings)

            },

            "findings": findings

        }

        evidence = EvidenceManager(
            self.case
        )

        evidence.add(
            "ioc_matches",
            report
        )

        print(
            f"[✓] IOC Detection Completed ({len(findings)} matches)"
        )