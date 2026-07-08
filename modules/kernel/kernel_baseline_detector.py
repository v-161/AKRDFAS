from pathlib import Path
import platform

from core.detector import BaseDetector


class KernelBaselineDetector(BaseDetector):

    def run(self):

        self.logger.info("Collecting kernel baseline")

        baseline = self._collect()

        self.evidence.add(
            "kernel_baseline",
            baseline
        )

        print("[✓] Kernel Baseline Collected")

    def _read_file(self, path):

        try:
            return Path(path).read_text().strip()
        except Exception:
            return None

    def _collect(self):

        return {

            "kernel_release": platform.release(),

            "kernel_version": platform.version(),

            "proc_version": self._read_file("/proc/version"),

            "cmdline": self._read_file("/proc/cmdline"),

            "hostname": platform.node(),

            "architecture": platform.machine()

        }