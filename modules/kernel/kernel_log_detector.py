import subprocess


class KernelLogDetector:

    def __init__(self, logger, evidence, case):

        self.logger = logger
        self.evidence = evidence
        self.case = case

    def run(self):

        warnings = []

        errors = []

        panics = []

        taints = []

        security = []

        hardware = []

        filesystem = []

        network = []

        info = []

        critical_events = []

        security_events = []

        network_events = []

        filesystem_events = []

        hardware_events = []

        try:

            output = subprocess.check_output(
                ["dmesg"],
                text=True,
                stderr=subprocess.DEVNULL
            )

            for line in output.splitlines():

                line_lower = line.lower()

                if "call trace" in line_lower:

                    critical_events.append(line)

                elif "bug:" in line_lower:

                    critical_events.append(line)

                elif "rip:" in line_lower:

                    critical_events.append(line)

                elif "security" in line_lower:

                    security_events.append(line)

                elif "audit" in line_lower:

                    security_events.append(line)

                elif "net" in line_lower:

                    network_events.append(line)

                elif "eth" in line_lower:

                    network_events.append(line)

                elif "ext4" in line_lower:

                    filesystem_events.append(line)

                elif "btrfs" in line_lower:

                    filesystem_events.append(line)

                elif "xfs" in line_lower:

                    filesystem_events.append(line)

                elif "usb" in line_lower:

                    hardware_events.append(line)

                elif "pci" in line_lower:

                    hardware_events.append(line)

                elif "taint" in line_lower:

                    taints.append(line)

                elif "panic" in line_lower or "oops" in line_lower:

                    panics.append(line)

                elif "module verification failed" in line_lower:

                    warnings.append(line)

                elif "module signature" in line_lower:

                    warnings.append(line)

                elif "rootkit" in line_lower:

                    warnings.append(line)

                elif "warning" in line_lower:

                    warnings.append(line)

                elif "error" in line_lower:

                    errors.append(line)

                elif any(

                    x in line_lower

                    for x in [

                        "apparmor",

                        "selinux",

                        "audit",

                        "lockdown",

                        "integrity"

                    ]

                ):

                    security.append(line)

                elif any(

                    x in line_lower

                    for x in [

                        "eth",

                        "tcp",

                        "udp",

                        "ipv4",

                        "ipv6",

                        "net"

                    ]

                ):

                    network.append(line)

                elif any(

                    x in line_lower

                    for x in [

                        "ext4",

                        "xfs",

                        "btrfs",

                        "filesystem",

                        "mount"

                    ]

                ):

                    filesystem.append(line)

                elif any(

                    x in line_lower

                    for x in [

                        "cpu",

                        "memory",

                        "hardware",

                        "thermal",

                        "acpi"

                    ]

                ):

                    hardware.append(line)

                else:

                    info.append(line)

        except Exception as e:

            errors.append(str(e))

        report = {

            "summary": {

                "warnings": len(warnings),

                "errors": len(errors),

                "panics": len(panics),

                "taints": len(taints),

                "critical_events": len(critical_events),

                "security": len(security_events),

                "network": len(network_events),

                "filesystem": len(filesystem_events),

                "hardware": len(hardware_events),

                "informational": len(info)

            },

            "warnings": warnings,

            "errors": errors,

            "panics": panics,

            "taints": taints,

            "critical_events": critical_events,

            "security_events": security_events,

            "network_events": network_events,

            "filesystem_events": filesystem_events,

            "hardware_events": hardware_events,

            "security": security,

            "network": network,

            "filesystem": filesystem,

            "hardware": hardware

        }

        self.evidence.add(
            "kernel_logs",
            report
        )

        print("[✓] Kernel Log Analysis")

        print(f"    Warnings : {len(warnings)}")
        print(f"    Errors   : {len(errors)}")
        print(f"    Panics   : {len(panics)}")
        print(f"    Tainted  : {len(taints)}")
        print(f"    Security : {len(security)}")
        print(f"    Network  : {len(network)}")
        print(f"    Filesys  : {len(filesystem)}")
        print(f"    Hardware : {len(hardware)}")
