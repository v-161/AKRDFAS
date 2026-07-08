from pathlib import Path

from core.detector import BaseDetector


class HiddenModuleDetector(BaseDetector):

    def __init__(self, logger, evidence_manager, case_manager):

        super().__init__(
            logger,
            evidence_manager,
            case_manager
        )

    def _proc_modules(self):

        modules = set()

        try:

            with open("/proc/modules", "r") as f:

                for line in f:

                    modules.add(line.split()[0])

        except Exception as e:

            self.logger.error(str(e))

        return modules

    def _sys_modules(self):

        modules = set()

        path = Path("/sys/module")

        if path.exists():

            for item in path.iterdir():

                if item.is_dir():

                    modules.add(item.name)

        return modules

    def _ignore_modules(self):

        return {

            "kernel",
            "module",
            "printk",
            "rcutree",
            "srcutree",
            "rcupdate",
            "workqueue",
            "syscall",
            "random",
            "thermal",
            "suspend",
            "page_alloc",
            "memory_hotplug",
            "slab_common",
            "cpufreq",
            "cpuidle",
            "block",
            "firmware_class",
            "cryptomgr",
            "ipv6",
            "processor",
            "keyboard",
            "vt",
            "fb",
            "pstore",
            "secretmem",
            "pcie_aspm",
            "pci_hotplug",
            "dynamic_debug",
            "sched_ext",
            "nmi_backtrace",
            "spurious",
            "hibernate",
            "sysrq"

        }

    def _is_builtin(self, module):

        module_path = Path("/sys/module") / module

        initstate = module_path / "initstate"

        sections = module_path / "sections"

        if initstate.exists():

            return False

        if sections.exists():

            return False

        return True

    def run(self):

        self.logger.info(
            "Starting Hidden Module Detection"
        )

        proc_modules = self._proc_modules()

        sys_modules = self._sys_modules()

        ignore = self._ignore_modules()

        only_proc = sorted(
            proc_modules - sys_modules
        )

        only_sys = []

        for module in sorted(sys_modules - proc_modules):

            if module in ignore:

                continue

            if self._is_builtin(module):

                continue

            only_sys.append(module)

        findings = []

        for module in only_proc:

            findings.append({

                "module": module,

                "issue": "Present in /proc/modules but missing from /sys/module"

            })

        for module in only_sys:

            findings.append({

                "module": module,

                "issue": "Present in /sys/module but missing from /proc/modules"

            })

        evidence = {

            "summary": {

                "proc_modules": len(proc_modules),

                "sys_modules": len(sys_modules),

                "ignored_modules": len(ignore),

                "discrepancies": len(findings)

            },

            "findings": findings

        }

        self.evidence.add(
            "hidden_modules",
            evidence
        )

        print("[✓] Hidden Module Detection")

        print(f"    /proc/modules          : {len(proc_modules)}")
        print(f"    /sys/module            : {len(sys_modules)}")
        print(f"    Ignored Built-in Items : {len(ignore)}")
        print(f"    Potential Hidden Mods  : {len(findings)}")

        self.logger.info(
            "Hidden Module Detection Finished"
        )