import os
import subprocess

from core.detector import BaseDetector


class KernelIntegrityDetector(BaseDetector):

    def __init__(self, logger, evidence_manager, case_manager):

        super().__init__(
            logger,
            evidence_manager,
            case_manager
        )

    def run(self):

        self.logger.info(
            "Starting Kernel Integrity Detector"
        )

        integrity = {}

        # ------------------------------------
        # Kernel Taint
        # ------------------------------------

        try:

            with open("/proc/sys/kernel/tainted") as f:

                taint = int(f.read().strip())

                integrity["kernel_tainted"] = taint

                integrity["tainted"] = taint != 0

        except:

            integrity["kernel_tainted"] = -1

            integrity["tainted"] = "Unknown"

        # ------------------------------------
        # Boot Parameters
        # ------------------------------------

        try:

            with open("/proc/cmdline") as f:

                integrity["boot_parameters"] = f.read().strip()

        except:

            integrity["boot_parameters"] = ""

        # ------------------------------------
        # Kernel Lockdown
        # ------------------------------------

        lockdown = "/sys/kernel/security/lockdown"

        if os.path.exists(lockdown):

            try:

                with open(lockdown) as f:

                    integrity["lockdown"] = f.read().strip()

            except:

                integrity["lockdown"] = "Unknown"

        else:

            integrity["lockdown"] = "Not Supported"

        # ------------------------------------
        # Kallsyms
        # ------------------------------------

        integrity["kallsyms_accessible"] = os.path.exists(
            "/proc/kallsyms"
        )

        # ------------------------------------
        # dmesg Access
        # ------------------------------------

        try:

            subprocess.run(

                ["dmesg"],

                stdout=subprocess.DEVNULL,

                stderr=subprocess.DEVNULL,

                check=True

            )

            integrity["dmesg_access"] = True

        except:

            integrity["dmesg_access"] = False

        # ------------------------------------
        # Secure Boot
        # ------------------------------------

        secure_boot = "/sys/firmware/efi/efivars"

        integrity["secure_boot"] = os.path.exists(
            secure_boot
        )

        # ------------------------------------
        # Loaded Security Modules
        # ------------------------------------

        try:

            with open("/sys/kernel/security/lsm") as f:

                integrity["lsm"] = [

                    x.strip()

                    for x in f.read().split(",")

                ]

        except:

            integrity["lsm"] = []

        # ------------------------------------
        # Important Sysctl Values
        # ------------------------------------

        sysctls = [

            "kernel.kptr_restrict",

            "kernel.dmesg_restrict",

            "kernel.modules_disabled",

            "kernel.kexec_load_disabled",

            "kernel.unprivileged_bpf_disabled"

        ]

        integrity["sysctl"] = {}

        for item in sysctls:

            try:

                value = subprocess.check_output(

                    ["sysctl", "-n", item],

                    text=True

                ).strip()

                integrity["sysctl"][item] = value

            except:

                integrity["sysctl"][item] = "Unknown"

        # ------------------------------------
        # Kernel Version
        # ------------------------------------

        integrity["kernel_version"] = os.uname().release

        # ------------------------------------
        # Hostname
        # ------------------------------------

        integrity["hostname"] = os.uname().nodename

        # ------------------------------------
        # Save Evidence
        # ------------------------------------

        self.evidence.add(

            "kernel_integrity",

            integrity

        )

        print("[✓] Kernel Integrity Checked")

        self.logger.info(

            "Kernel Integrity Detector Finished"

        )
