import os
import psutil

from core.detector import BaseDetector


class HiddenProcessDetector(BaseDetector):

    def __init__(self, logger, evidence_manager, case_manager):

        super().__init__(
            logger,
            evidence_manager,
            case_manager
        )

    def run(self):

        self.logger.info(
            "Starting Hidden Process Detection"
        )

        proc_pids = set()

        for entry in os.listdir("/proc"):

            if entry.isdigit():
                proc_pids.add(int(entry))

        psutil_pids = set(psutil.pids())

        only_proc = sorted(proc_pids - psutil_pids)

        only_psutil = sorted(psutil_pids - proc_pids)

        findings = []

        for pid in only_proc:

            findings.append({
                "pid": pid,
                "issue": "Present in /proc but not psutil"
            })

        for pid in only_psutil:

            findings.append({
                "pid": pid,
                "issue": "Present in psutil but not /proc"
            })

        evidence = {

            "summary": {

                "proc_processes": len(proc_pids),
                "psutil_processes": len(psutil_pids),
                "discrepancies": len(findings)

            },

            "findings": findings

        }

        self.evidence.add(
            "hidden_processes",
            evidence
        )

        print(
            f"[✓] Hidden Process Detection ({len(findings)} discrepancies)"
        )

        self.logger.info(
            "Hidden Process Detection Finished"
        )
