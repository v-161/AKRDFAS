from pathlib import Path
from datetime import datetime
import json


class CaseManager:

    def __init__(self, config):

        self.base_directory = Path(
            config.get("evidence", "directory")
        )

        self.base_directory.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        self.case_id = f"CASE-{timestamp}"

        self.case_directory = (
            self.base_directory /
            self.case_id
        )

        self.case_directory.mkdir()

        # Create evidence folder
        self.evidence_directory = (
            self.case_directory /
            "evidence"
        )

        self.evidence_directory.mkdir()

        # Create manifest
        self.manifest = {

            "case_id": self.case_id,

            "created": datetime.now().isoformat(),

            "status": "Running",

            "detectors": [],

            "evidence_count": 0

        }

        self._save_manifest()

    def _save_manifest(self):

        with open(
            self.case_directory / "manifest.json",
            "w"
        ) as file:

            json.dump(
                self.manifest,
                file,
                indent=4
            )

    def register_detector(self, detector):

        self.manifest["detectors"].append(
            detector
        )

        self._save_manifest()

    def store_evidence(self, category, data):

        filepath = (
            self.evidence_directory /
            f"{category}.json"
        )

        with open(filepath, "w") as file:

            json.dump(
                data,
                file,
                indent=4
            )

        self.manifest["evidence_count"] += 1

        self._save_manifest()

    def close_case(self):

        self.manifest["status"] = "Completed"

        self._save_manifest()

    def get_case_directory(self):

        return self.case_directory

    def get_case_id(self):

        return self.case_id