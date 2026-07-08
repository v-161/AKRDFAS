import platform
import psutil

from core.detector import BaseDetector


class KernelInformationDetector(BaseDetector):

    def run(self):

        self.logger.info(
            "Collecting kernel information"
        )

        information = self._collect()

        self.evidence.add(
            "kernel_information",
            information
        )

        print("[✓] Kernel Information Collected")

    def _collect(self):

        boot_time = psutil.boot_time()

        uptime = int(
            psutil.time.time() - boot_time
        )

        return {

            "hostname": platform.node(),

            "system": platform.system(),

            "kernel_release": platform.release(),

            "kernel_version": platform.version(),

            "architecture": platform.machine(),

            "processor": platform.processor(),

            "boot_time": boot_time,

            "uptime_seconds": uptime

        }