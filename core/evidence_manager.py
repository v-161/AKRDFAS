import hashlib
import json
import os
from datetime import datetime

from core.chain_of_custody import ChainOfCustody

class EvidenceManager:

    def __init__(self, case_manager):

        self.case = case_manager

        self.chain = ChainOfCustody(
            self.case
        )

    def _hash_file(self, filepath):

        sha256 = hashlib.sha256()

        with open(filepath, "rb") as f:

            while True:

                chunk = f.read(4096)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    def _update_manifest(self, filename):

        evidence_dir = os.path.join(
            self.case.get_case_directory(),
            "evidence"
        )

        manifest_path = os.path.join(
            evidence_dir,
            "integrity_manifest.json"
        )

        file_path = os.path.join(
            evidence_dir,
            filename
        )

        if not os.path.exists(file_path):
            return

        if os.path.exists(manifest_path):

            with open(manifest_path, "r") as f:

                manifest = json.load(f)

        else:

            manifest = {}

        manifest[filename] = {
            "sha256": self._hash_file(file_path),
            "size": os.path.getsize(file_path),
            "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
            ),
            "case_id": self.case.get_case_id()
        }

        with open(manifest_path, "w") as f:

            json.dump(
                manifest,
                f,
                indent=4
            )

    def add(self, category, data):

        self.case.store_evidence(
            category,
            data
        )

        filename = category

        if not filename.endswith(".json"):

            filename += ".json"

        self._update_manifest(
            filename
        )

        actions = {
            "kernel_information.json":
                "Kernel Information Collected",
            "kernel_baseline.json":
                "Kernel Baseline Collected",
            "kernel_modules.json":
                "Kernel Module Analysis Completed",
            "hidden_modules.json":
                "Hidden Module Detection Completed",
            "hidden_processes.json":
                "Hidden Process Detection Completed",
            "kernel_integrity.json":
                "Kernel Integrity Check Completed",
            "network_connections.json":
                "Network Analysis Completed",
            "kernel_logs.json":
                "Kernel Log Analysis Completed",
            "kernel_hooks.json":
                "Kernel Hook Detection Completed",
            "persistence.json":
                "Persistence Analysis Completed",
            "threat_assessment.json":
                "Threat Assessment Generated"
        }

        self.chain.log(
            action=actions.get(
                filename,
                "Evidence Collected"
            ),

            file_name=filename,
            status="SUCCESS"
        )
