import os
import subprocess
from pathlib import Path

from core.detector import BaseDetector


class KernelHookDetector(BaseDetector):

    def __init__(self, logger, evidence_manager, case_manager):

        super().__init__(
            logger,
            evidence_manager,
            case_manager
        )

    def run(self):

        self.logger.info(
            "Starting Kernel Hook Detection"
        )

        findings = []

        summary = {
            "ftrace_enabled": False,
            "kprobes_enabled": False,
            "ebpf_available": False,
            "debugfs_mounted": False
        }

        # -----------------------------
        # debugfs
        # -----------------------------

        debugfs = Path("/sys/kernel/debug")
        try:
            if debugfs.exists():
                summary["debugfs_mounted"] = True
        except PermissionError:
            findings.append({
                "type": "Warning",
                "severity": "INFO",
                "message": "Unable to access debugfs. Kernel hook inspection may be incomplete."
            })

        # -----------------------------
        # ftrace
        # -----------------------------

        tracing = Path("/sys/kernel/debug/tracing")

        try:
            if tracing.exists():
                summary["ftrace_enabled"] = True
            else:
                findings.append({
                    "type": "Warning",
                    "severity": "INFO",
                    "message": "ftrace interface unavailable."
                })
        except PermissionError:
            findings.append({
                "type": "Warning",
                "severity": "INFO",
                "message": "Permission denied while accessing ftrace."
            })

        # -----------------------------
        # ftrace available tracers
        # -----------------------------

        tracers = "/sys/kernel/debug/tracing/available_tracers"

        if os.path.exists(tracers):

            try:

                with open(tracers) as f:

                    available = f.read().strip().split()

                findings.append({

                    "type": "Available Tracers",
                    "severity": "INFO",
                    "count": len(available),

                    "tracers": available

                })

            except:

                pass

        # -----------------------------
        # kprobes
        # -----------------------------

        kprobe = Path("/sys/kernel/debug/kprobes")

        try:
            if kprobe.exists():
                summary["kprobes_enabled"] = True
        except PermissionError:
            findings.append({
                "type": "Warning",
                "severity": "INFO",
                "message": "Permission denied while accessing kprobes."
            })

        # -----------------------------
        # eBPF
        # -----------------------------

        if Path("/sys/fs/bpf").exists():

            summary["ebpf_available"] = True

            try:

                mounts = subprocess.check_output(

                    ["mount"],

                    text=True

                )

                findings.append({

                    "type": "eBPF",
                    "severity": "INFO",
                    "message": "BPF filesystem is mounted."

                })

            except:

                pass

        # -----------------------------
        # Loaded BPF Programs
        # -----------------------------

        try:

            output = subprocess.check_output(

                ["bpftool", "prog", "show"],

                stderr=subprocess.DEVNULL,

                text=True

            )

            programs = output.splitlines()

            findings.append({

                "type": "BPF Programs",
                "severity": "INFO",
                "count": len(programs),

                "entries": programs

            })

        except:

            findings.append({

                "type": "BPF Programs",
                "severity": "INFO",
                "count": 0,

                "entries": []

            })

        # -----------------------------
        # Active Kprobes
        # -----------------------------

        kprobe_file = "/sys/kernel/debug/kprobes/list"

        if os.path.exists(kprobe_file):

            try:

                with open(kprobe_file) as f:

                    probes = f.read().splitlines()

                findings.append({

                    "type": "Kprobes",
                    "severity": "INFO",
                    "count": len(probes),

                    "entries": probes

                })

            except:

                pass

        # -----------------------------
        # Current ftrace tracer
        # -----------------------------

        current = "/sys/kernel/debug/tracing/current_tracer"

        if os.path.exists(current):

            try:

                with open(current) as f:

                    tracer = f.read().strip()

                findings.append({

                    "type": "Current Tracer",
                    "severity": "INFO",
                    "value": tracer

                })

            except:

                pass

        # -----------------------------
        # Calculate suspicious hooks count
        # -----------------------------

        summary["suspicious_hooks"] = sum(
            1
            for finding in findings
            if finding.get("severity") in ("SUSPICIOUS", "CRITICAL")
        )

        evidence = {

            "summary": summary,

            "findings": findings

        }

        self.evidence.add(
            "kernel_hooks",
            evidence
        )

        print("[✓] Kernel Hook Detection")

        print(
            f"    DebugFS Mounted : {summary['debugfs_mounted']}"
        )

        print(
            f"    ftrace Enabled  : {summary['ftrace_enabled']}"
        )

        print(
            f"    Kprobes Enabled : {summary['kprobes_enabled']}"
        )

        print(
            f"    eBPF Available  : {summary['ebpf_available']}"
        )

        print(
            f"    Suspicious Hooks: {summary['suspicious_hooks']}"
        )

        self.logger.info(
            "Kernel Hook Detection Finished"
        )
