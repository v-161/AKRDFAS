from pathlib import Path

from core.detector import BaseDetector

from modules.kernel.module_analyzer import ModuleAnalyzer
from modules.kernel.module_metadata import ModuleMetadata
from modules.kernel.module_hash import ModuleHasher
from modules.kernel.module_risk import ModuleRisk


class KernelModuleDetector(BaseDetector):

    def __init__(self, logger, evidence_manager, case_manager):

        super().__init__(
            logger,
            evidence_manager,
            case_manager
        )

        self.analyzer = ModuleAnalyzer()
        self.metadata = ModuleMetadata()
        self.hasher = ModuleHasher()
        self.risk = ModuleRisk()

    def run(self):

        self.logger.info(
            "Starting Kernel Module Analysis"
        )

        modules = self.analyzer.enumerate_modules()

        findings = []

        high = 0
        medium = 0
        low = 0

        for module in modules:

            info = self.metadata.get(module["name"])

            module.update(info)

            module["exists"] = False
            module["file_size"] = None
            module["modified_time"] = None

            if module["path"]:

                path = Path(module["path"])

                if path.exists():

                    module["exists"] = True
                    module["file_size"] = path.stat().st_size
                    module["modified_time"] = path.stat().st_mtime

            module["sha256"] = self.hasher.sha256(
                module["path"]
            )

            module["risk"] = self.risk.evaluate(
                module
            )

            level = module["risk"]["level"]

            if level == "HIGH":
                high += 1

            elif level == "MEDIUM":
                medium += 1

            else:
                low += 1

            findings.append(module)

        evidence = {

            "summary": {

                "modules_scanned": len(findings),

                "high_risk": high,

                "medium_risk": medium,

                "low_risk": low

            },

            "findings": findings

        }

        self.evidence.add(
            "kernel_modules",
            evidence
        )

        print(
            f"[✓] Kernel Modules Analyzed ({len(findings)})"
        )

        print(
            f"    High: {high}  Medium: {medium}  Low: {low}"
        )

        self.logger.info(
            "Kernel Module Analysis Finished"
        )