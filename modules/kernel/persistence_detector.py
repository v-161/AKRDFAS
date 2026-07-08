import os
import subprocess


class PersistenceDetector:

    def __init__(self, logger, evidence, case):

        self.logger = logger
        self.evidence = evidence
        self.case = case

    def check_path(self, path):

        result = {
            "path": path,
            "exists": os.path.exists(path)
        }

        result["status"] = "PRESENT"

        try:
            if os.path.isfile(path):
                with open(path) as f:
                    result["contents"] = [
                        line.strip()
                        for line in f.readlines()
                        if line.strip()
                    ]
            else:
                result["contents"] = []
        except Exception:
            result["contents"] = []

        return result

    def read_file(self, path):

        try:

            with open(path) as f:

                return f.read().splitlines()

        except:

            return []

    def run(self):

        findings = []

        suspicious = 0

        # -----------------------------------
        # Important persistence locations
        # -----------------------------------

        paths = [

            "/etc/modules",

            "/etc/modules-load.d",

            "/usr/lib/modules-load.d",

            "/etc/modprobe.d",

            "/etc/rc.local",

            "/etc/crontab",

            "/etc/cron.d",

            "/etc/cron.daily",

            "/etc/cron.weekly",

            "/etc/cron.monthly",

            "/etc/systemd/system",

            "/etc/init.d",

            "/etc/ld.so.preload"

        ]

        for path in paths:

            item = self.check_path(path)

            item["type"] = "Path"

            item["suspicious"] = False

            if path in [

                "/etc/rc.local",

                "/etc/ld.so.preload"

            ] and item["exists"]:

                item["suspicious"] = True

                suspicious += 1

            findings.append(item)

        # -----------------------------------
        # Cron Jobs
        # -----------------------------------

        cron_entries = self.read_file("/etc/crontab")

        findings.append({

            "type": "Cron",

            "entries": cron_entries,

            "count": len(cron_entries)

        })

        # -----------------------------------
        # Loaded boot modules
        # -----------------------------------

        module_entries = self.read_file("/etc/modules")

        findings.append({

            "type": "Modules",

            "entries": module_entries,

            "count": len(module_entries)

        })

        # -----------------------------------
        # Systemd Services
        # -----------------------------------

        try:

            output = subprocess.check_output(

                [

                    "systemctl",

                    "list-unit-files",

                    "--type=service",

                    "--state=enabled"

                ],

                text=True

            )

            enabled_services = [

                x.strip()

                for x in output.splitlines()

                if ".service" in x

            ]

        except:

            enabled_services = []

        findings.append({

            "type": "Systemd",

            "enabled_services": enabled_services,

            "count": len(enabled_services)

        })

        # -----------------------------------
        # ld.so.preload contents
        # -----------------------------------

        preload = self.read_file("/etc/ld.so.preload")

        findings.append({

            "type": "LD_PRELOAD",

            "entries": preload,

            "count": len(preload)

        })

        # -----------------------------------
        # Final report
        # -----------------------------------

        report = {

            "summary": {

                "paths_checked": len(paths),

                "enabled_services": len(enabled_services),

                "cron_entries": len(cron_entries),

                "module_entries": len(module_entries),

                "ld_preload_entries": len(preload),

                "suspicious_entries": suspicious

            },

            "findings": findings

        }

        self.evidence.add(

            "persistence",

            report

        )

        print("[✓] Persistence Check Completed")
