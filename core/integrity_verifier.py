import hashlib
import json
import os
from core.evidence_manager import EvidenceManager

class IntegrityVerifier:

    def __init__(self, case_manager):

        self.case = case_manager

        self.evidence_dir = os.path.join(
            self.case.get_case_directory(),
            "evidence"
        )

    def hash_file(self, filepath):

        sha256 = hashlib.sha256()

        with open(filepath, "rb") as f:

            while True:

                chunk = f.read(4096)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    def run(self):

        manifest_path = os.path.join(
            self.evidence_dir,
            "integrity_manifest.json"
        )

        if not os.path.exists(manifest_path):

            print("[!] Integrity Manifest Missing")

            return

        with open(manifest_path, "r") as f:

            manifest = json.load(f)

        verified = []

        tampered = []

        print("\n========== Evidence Integrity ==========\n")

        for filename, data in manifest.items():

            filepath = os.path.join(
                self.evidence_dir,
                filename
            )

            if not os.path.exists(filepath):

                print(f"{filename:<30} MISSING")

                tampered.append(filename)

                continue

            current_hash = self.hash_file(filepath)

            if current_hash == data["sha256"]:

                print(f"{filename:<30} VERIFIED")

                verified.append(filename)

            else:

                print(f"{filename:<30} TAMPERED")

                tampered.append(filename)

        print()

        if len(tampered) == 0:

            status = "VERIFIED"

        else:

            status = "FAILED"

        print(f"Overall Status : {status}")

        print("\n========================================\n")

        report = {

            "status": status,

            "verified": verified,

            "tampered": tampered

        }

        evidence = EvidenceManager(
            self.case
        )

        evidence.add(
            "integrity_verification",
            report
        )
